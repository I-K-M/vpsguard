import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vg', Path(__file__).resolve().parents[1] / 'vpsguard.py')
vg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vg)

class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.root_patch = patch.object(vg, 'ROOT', self.root); self.root_patch.start()
        self.state_patch = patch.object(vg, 'STATE', self.root/'state'); self.state_patch.start()
        (self.root/'etc').mkdir()
        (self.root/'etc/machine-id').write_text('fixture-host')
        vg.STATE.mkdir(mode=0o700)
    def tearDown(self):
        self.root_patch.stop(); self.state_patch.stop(); self.tmp.cleanup()
    def plan(self, actions):
        return dict(schema_version=1, version=vg.VERSION, host_id=vg.host_id(), expires=int(time.time())+600, inputs=vg.watched_paths(), actions=actions, admin='fixture', ports=[2222], web=False, access_confirmed=True, ssh_connection='1 2 3 2222')
    def test_state_bound_plan(self):
        plan=self.plan([])
        vg.validate_plan(plan)
        (self.root/'etc/ssh').mkdir()
        (self.root/'etc/ssh/sshd_config').write_text('changed')
        with self.assertRaises(ValueError): vg.validate_plan(plan)
    def test_expired_and_foreign_host(self):
        for key,value in [('expires',0),('host_id','foreign')]:
            plan=self.plan([]);plan[key]=value
            with self.assertRaises(ValueError): vg.validate_plan(plan)
    def test_backup_failure_blocks_apply(self):
        plan=self.plan(['sysctl'])
        with patch.object(vg,'supported',return_value=True), patch.object(vg,'backup',side_effect=OSError('disk full')), patch.object(vg,'checked') as commands:
            with self.assertRaises(OSError): vg.apply(plan)
            commands.assert_not_called()
        self.assertFalse(vg.hostpath(vg.PATHS['sysctl']).exists())
    def test_active_validation_failure_restores_original(self):
        p=vg.hostpath(vg.PATHS['sysctl']);p.parent.mkdir(parents=True);p.write_text('original');plan=self.plan(['sysctl'])
        def checked(args): return '1'
        with patch.object(vg,'supported',return_value=True),patch.object(vg,'checked',side_effect=checked),patch.object(vg,'command',return_value=(0,'')):
            with self.assertRaises(RuntimeError):vg.apply(plan)
        self.assertEqual(p.read_text(),'original')
        manifests=list(vg.STATE.glob('*/manifest.json'))
        self.assertEqual(json.loads(manifests[0].read_text())['state'],'rolled_back')
    def test_firewall_allow_precedes_policy_and_timer_precedes_changes(self):
        calls=[]
        def checked(args):
            calls.append(args)
            if args==['ufw','status']: return 'Status: active\n2222/tcp ALLOW Anywhere'
            return ''
        plan=self.plan(['firewall'])
        with patch.object(vg,'supported',return_value=True),patch.object(vg,'verify_admin'),patch.object(vg,'ssh_ports',return_value=[2222]),patch.dict(os.environ,{'SSH_CONNECTION':plan['ssh_connection']}),patch.object(vg,'checked',side_effect=checked):
            report=vg.apply(plan)
        allow=next(i for i,a in enumerate(calls) if a[:2]==['ufw','allow'])
        policy=next(i for i,a in enumerate(calls) if a[:2]==['ufw','default'])
        timer=next(i for i,a in enumerate(calls) if a[0]=='systemd-run')
        self.assertLess(timer,allow);self.assertLess(allow,policy)
        self.assertEqual(report['state'],'awaiting_confirmation')
    def test_apply_accepts_new_client_port_but_rejects_new_origin(self):
        plan=self.plan(['ssh'])
        with patch.object(vg,'verify_admin'),patch.object(vg,'ssh_ports',return_value=[2222]):
            with patch.dict(os.environ,{'SSH_CONNECTION':'1 99 3 2222'}):vg.validate_plan(plan)
            with patch.dict(os.environ,{'SSH_CONNECTION':'9 99 3 2222'}):
                with self.assertRaises(ValueError):vg.validate_plan(plan)
    def test_confirm_requires_new_session_and_selected_admin(self):
        folder=vg.STATE/'20261002T120000-abcd1234';folder.mkdir()
        (folder/'manifest.json').write_text(json.dumps(dict(state='awaiting_confirmation',ssh_connection='1 2 3 22',admin='fixture')))
        with patch.dict(os.environ,{'SSH_CONNECTION':'1 2 3 22','SUDO_USER':'fixture'}):
            with self.assertRaises(ValueError):vg.confirm(folder.name)
    def test_rollback_validates_all_backups_before_restoring(self):
        path=vg.hostpath('/etc/example');path.write_text('before')
        folder=vg.STATE/'20261002T120000-abcd1234';folder.mkdir()
        entry=vg.backup('/etc/example',folder);path.write_text('after');(folder/entry['blob']).write_text('corrupt')
        vg.save_manifest(folder,dict(state='applying',files=[entry],actions=[]))
        with self.assertRaises(RuntimeError):vg.rollback(folder.name)
        self.assertEqual(path.read_text(),'after')
    def test_second_plan_has_no_file_changes(self):
        path=vg.hostpath(vg.PATHS['sysctl']);path.parent.mkdir(parents=True)
        path.write_text(vg.templates('',[],False)['sysctl'])
        with patch.object(vg,'supported',return_value=True),patch.object(vg,'command',side_effect=lambda a,**kw:(0,vg.SYSCTL_VALUES.get(a[-1],''))):
            plan=vg.make_plan(['sysctl'],'',False,False)
        self.assertEqual(plan['actions'],[])
    def test_managed_symlink_parent_refused(self):
        (self.root/'etc/sysctl.d').symlink_to(self.root/'other',target_is_directory=True)
        with self.assertRaises(ValueError):vg.fingerprint(vg.PATHS['sysctl'])
    def test_audit_does_not_hide_command_failures(self):
        before=vg.watched_paths()
        with patch.object(vg,'command',return_value=(127,'')),patch.object(vg,'supported',return_value=True),patch.object(vg.pwd,'getpwall',return_value=[]):report=vg.audit()
        self.assertEqual(before,vg.watched_paths())
        self.assertEqual(next(r for r in report['results'] if r['id']=='HOST-SERVICES')['status'],'unknown')
        self.assertEqual(vg.exit_code(report),3)

if __name__=='__main__':unittest.main()
