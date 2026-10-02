#!/usr/bin/env python3
"""Read-only host audit and state-bound, transactional hardening plans."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

VERSION = '0.2.0-dev'
STATE = Path('/var/lib/vpsguard/transactions')
ROOT = Path('/')
SSH_VALUES = {'PermitRootLogin': 'no', 'PubkeyAuthentication': 'yes', 'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no', 'PermitEmptyPasswords': 'no', 'X11Forwarding': 'no', 'MaxAuthTries': '3'}
SYSCTL_VALUES = {'net.ipv4.conf.all.accept_redirects': '0', 'net.ipv4.conf.default.accept_redirects': '0', 'net.ipv4.conf.all.send_redirects': '0', 'net.ipv4.conf.default.send_redirects': '0', 'net.ipv4.conf.all.accept_source_route': '0', 'net.ipv4.tcp_syncookies': '1', 'kernel.randomize_va_space': '2', 'kernel.dmesg_restrict': '1', 'kernel.kptr_restrict': '2', 'fs.protected_hardlinks': '1', 'fs.protected_symlinks': '1'}
PATHS = {'ssh': '/etc/ssh/sshd_config.d/00-vpsguard.conf', 'nginx': '/etc/nginx/conf.d/00-vpsguard-security.conf', 'sysctl': '/etc/sysctl.d/99-vpsguard.conf', 'updates': '/etc/apt/apt.conf.d/20auto-upgrades', 'fail2ban': '/etc/fail2ban/jail.d/vpsguard.conf', 'journal': '/etc/systemd/journald.conf.d/vpsguard.conf'}
SERVICES = {'ssh': 'ssh', 'nginx': 'nginx', 'fail2ban': 'fail2ban', 'journal': 'systemd-journald'}

def hostpath(path): return ROOT / path.lstrip('/')

def command(args, timeout=20, input_text=None):
    try:
        p = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout, check=False, env={**os.environ, 'LC_ALL': 'C'})
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired): return 127, ''

def checked(args):
    code, output = command(args)
    if code: raise RuntimeError('Command failed: ' + args[0] + ' (raw output omitted)')
    return output

def result(rule, status, evidence, remediation=''):
    return dict(id=rule, status=status, evidence=evidence, remediation=remediation)

def os_release():
    values = {}
    try:
        for line in hostpath('/etc/os-release').read_text().splitlines():
            if '=' in line:
                key, value = line.split('=', 1); values[key] = value.strip('"')
    except OSError: pass
    return values

def supported():
    info = os_release()
    return info.get('ID') == 'ubuntu' and info.get('VERSION_ID') in ('22.04', '24.04')

def effective_ssh(admin=None):
    args = ['/usr/sbin/sshd', '-T']
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if admin and len(connection) == 4:
        args += ['-C', f'user={admin},addr={connection[0]},host={connection[0]},laddr={connection[2]},lport={connection[3]}']
    code, text = command(args)
    values = {}
    if not code:
        for line in text.splitlines():
            key, _, value = line.partition(' ')
            values.setdefault(key, []).append(value)
    return code, values

def ssh_ports():
    code, values = effective_ssh()
    if code: raise RuntimeError('Cannot determine configured SSH ports')
    ports = values.get('port', [])
    current = os.environ.get('SSH_CONNECTION', '').split()
    if len(current) == 4: ports.append(current[3])
    numbers = sorted({int(p) for p in ports if p.isdigit() and 0 < int(p) < 65536})
    if not numbers: raise RuntimeError('No validated SSH port; no default guessed')
    return numbers

def verify_admin(user):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*', user): raise ValueError('Invalid admin account')
    entry = pwd.getpwnam(user)
    if entry.pw_uid == 0 or entry.pw_shell.endswith(('nologin', '/false')): raise ValueError('Admin must be a non-root interactive account')
    key = Path(entry.pw_dir) / '.ssh/authorized_keys'
    for path in (Path(entry.pw_dir), key.parent, key):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022 or info.st_uid not in (0, entry.pw_uid): raise ValueError('Unsafe account/key ownership or permissions')
    if not key.is_file() or key.stat().st_size == 0: raise ValueError('Admin key file missing')
    checked(['ssh-keygen', '-l', '-f', str(key)])
    code, _ = command(['sudo', '-l', '-U', user])
    if code: raise ValueError('Account has no sudo permission; prove sudo access separately')
    code, values = effective_ssh(user)
    if code or values.get('pubkeyauthentication') != ['yes']: raise ValueError('Key authentication not enabled for selected account')
    return user

def audit():
    rows = []
    rows.append(result('HOST-OS', 'pass' if supported() else 'unknown', 'Ubuntu 22.04/24.04' if supported() else 'Remediation unsupported on this OS'))
    try:
        usage = shutil.disk_usage(ROOT)
        percent = int(100 * (usage.total - usage.free) / usage.total)
        rows.append(result('HOST-DISK', 'fail' if percent >= 90 else 'warn' if percent >= 80 else 'pass', f'Root usage {percent}%'))
    except OSError: rows.append(result('HOST-DISK', 'unknown', 'Cannot read disk usage'))
    code, output = command(['systemctl', '--failed', '--no-legend', '--no-pager'])
    rows.append(result('HOST-SERVICES', 'unknown' if code else 'warn' if output else 'pass', 'Failed units detected' if output else 'No failed units observed' if not code else 'systemd query failed'))
    code, output = command(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    rows.append(result('HOST-TIME', 'unknown' if code else 'pass' if output == 'yes' else 'warn', 'NTP synchronized' if output == 'yes' else 'NTP not verified'))
    code, output = command(['apt-get', '-s', 'upgrade'], timeout=60)
    count = len(re.findall(r'^Inst ', output, re.M))
    rows.append(result('HOST-UPDATES', 'unknown' if code else 'warn' if count else 'pass', f'{count} upgrades in existing cache; cache was not refreshed'))
    rows.append(result('HOST-REBOOT', 'warn' if hostpath('/var/run/reboot-required').exists() else 'pass', 'Reboot required' if hostpath('/var/run/reboot-required').exists() else 'No reboot marker'))
    code, output = command(['ufw', 'status'])
    rows.append(result('HOST-FIREWALL', 'unknown' if code else 'pass' if 'Status: active' in output else 'warn', 'UFW active' if 'Status: active' in output else 'UFW inactive or unavailable', 'Review full rule set and provider firewall; active alone does not prove filtering'))
    code, values = effective_ssh()
    for key, expected in SSH_VALUES.items():
        actual = values.get(key.lower(), [])
        rows.append(result('SSH-' + key, 'unknown' if code else 'pass' if actual == [expected] else 'warn', f'Effective value {actual or "unavailable"}; target {expected}', 'Verify Match contexts and a second admin login before changing access'))
    for key, expected in SYSCTL_VALUES.items():
        code, value = command(['sysctl', '-n', key])
        rows.append(result('SYSCTL-' + key, 'unknown' if code else 'pass' if value == expected else 'warn', f'Active value {value or "unavailable"}; target {expected}'))
    for rule, service in (('HOST-FAIL2BAN', 'fail2ban'), ('HOST-NGINX', 'nginx')):
        code, output = command(['systemctl', 'is-active', service])
        rows.append(result(rule, 'pass' if code == 0 and output == 'active' else 'warn' if output in ('inactive', 'failed') else 'unknown', f'{service}: {output or "unavailable"}'))
    code, _ = command(['nginx', '-t'])
    rows.append(result('NGINX-CONFIG', 'pass' if code == 0 else 'unknown', 'Configuration validates' if not code else 'Nginx unavailable or configuration invalid'))
    code, output = command(['nginx', '-T'])
    rows.append(result('NGINX-TOKENS', 'unknown' if code else 'pass' if re.search(r'^\s*server_tokens\s+off;', output, re.M) else 'warn', 'Inspect effective virtual hosts; context overrides may differ'))
    code, _ = command(['aa-status', '--enabled'])
    rows.append(result('HOST-APPARMOR', 'pass' if not code else 'unknown', 'Enabled' if not code else 'AppArmor enforcement not verified'))
    rows.append(result('HOST-JOURNAL', 'pass' if hostpath('/var/log/journal').is_dir() else 'warn', 'Persistent journal directory exists' if hostpath('/var/log/journal').is_dir() else 'Persistent directory absent; review journald storage policy'))
    cfg = hostpath(PATHS['updates'])
    text = cfg.read_text() if cfg.is_file() else ''
    rows.append(result('HOST-AUTOUPDATES', 'pass' if 'Unattended-Upgrade "1"' in text else 'warn', 'Schedule configured; origin policy and execution require review'))
    uid0 = [p.pw_name for p in pwd.getpwall() if p.pw_uid == 0]
    rows.append(result('HOST-UID0', 'pass' if uid0 == ['root'] else 'fail', 'Only root has UID 0' if uid0 == ['root'] else 'Additional UID 0 accounts'))
    code, output = command(['ss', '-H', '-lntup'])
    wildcard = bool(re.search(r'(?:0\.0\.0\.0|\[::\]|\*)\:', output))
    database = any(re.search(r'(?:0\.0\.0\.0|\[::\]|\*):(3306|5432|6379|27017|9200|11211)\b', line) for line in output.splitlines())
    rows.append(result('HOST-LISTENERS', 'unknown' if code else 'warn' if wildcard else 'pass', 'Wildcard listeners detected; review authorised exposure' if wildcard else 'No wildcard binding observed' if not code else 'Listener query failed'))
    rows.append(result('HOST-DATABASE', 'unknown' if code else 'fail' if database else 'pass', 'Common database/cache wildcard binding detected' if database else 'No common database/cache wildcard binding observed'))
    code, output = command(['docker', 'ps', '--format', '{{.Ports}}'])
    rows.append(result('HOST-DOCKER', 'unknown' if code else 'warn' if re.search(r'0\.0\.0\.0:|\[::\]:', output) else 'pass', 'Review Docker-published ports independently of UFW' if output else 'No published ports observed' if not code else 'Docker absent or query unavailable'))
    for rule, binary in (('HOST-LOGROTATE', 'logrotate'), ('HOST-LYNIS', 'lynis'), ('HOST-TLS', 'certbot')):
        rows.append(result(rule, 'pass' if shutil.which(binary) else 'not_applicable', f'{binary} installed' if shutil.which(binary) else f'{binary} not installed; provisioning is operator-managed'))
    for user in pwd.getpwall():
        if user.pw_uid != 0 and user.pw_uid < 1000: continue
        key = Path(user.pw_dir) / '.ssh/authorized_keys'
        if not key.exists(): continue
        info = key.lstat()
        safe = stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_uid in (0, user.pw_uid)
        rows.append(result('ACCESS-KEY-' + user.pw_name, 'pass' if safe else 'warn', 'Key file owner/mode checked; successful login not proven'))
    return dict(schema_version=1, version=VERSION, mode='audit', results=rows)

def fingerprint(path):
    p = hostpath(path)
    if p.is_symlink(): raise ValueError('Symlink build/managed input refused: ' + path)
    for parent in p.parents:
        if parent == ROOT: break
        if parent.is_symlink(): raise ValueError('Symlink parent refused: ' + path)
    if not p.exists(): return 'absent'
    if not p.is_file(): raise ValueError('Non-file input refused: ' + path)
    info = p.stat()
    return hashlib.sha256(p.read_bytes()).hexdigest() + ':' + str(stat.S_IMODE(info.st_mode)) + ':' + str(info.st_uid) + ':' + str(info.st_gid)

def watched_paths():
    paths = set(PATHS.values()) | {'/etc/ssh/sshd_config', '/etc/default/ufw', '/etc/ufw/ufw.conf', '/etc/ufw/user.rules', '/etc/ufw/user6.rules', '/etc/nginx/nginx.conf', '/etc/fail2ban/jail.conf', '/etc/systemd/journald.conf', '/etc/passwd', '/etc/group', '/etc/shadow'}
    for directory in ('/etc/ssh/sshd_config.d', '/etc/ufw', '/etc/sysctl.d', '/etc/nginx/conf.d', '/etc/nginx/sites-enabled', '/etc/fail2ban/jail.d', '/etc/apt/apt.conf.d', '/etc/systemd/journald.conf.d'):
        folder = hostpath(directory)
        if folder.is_dir():
            for p in folder.iterdir():
                if p.is_symlink():
                    # Distribution-enabled sites are symlinks. Bind to their
                    # resolved content too, rather than writing through them.
                    resolved = p.resolve()
                    if not resolved.is_file(): raise ValueError('Broken watched symlink')
                    paths.add('/' + str(resolved.relative_to(ROOT)).lstrip('/'))
                    continue
                if p.is_file(): paths.add('/' + str(p.relative_to(ROOT)).lstrip('/'))
    return {p: fingerprint(p) for p in sorted(paths)}

def host_id():
    return hashlib.sha256(hostpath('/etc/machine-id').read_bytes()).hexdigest()

def templates(admin, ports, web):
    return {
      'ssh': '\n'.join(k + ' ' + v for k, v in SSH_VALUES.items()) + '\n',
      'nginx': 'server_tokens off;\n',
      'sysctl': '\n'.join(k + ' = ' + v for k, v in SYSCTL_VALUES.items()) + '\n',
      'updates': 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
      'fail2ban': '[sshd]\nenabled = true\nbackend = systemd\nport = ' + ','.join(map(str, ports)) + '\nbantime = 1h\nfindtime = 10m\nmaxretry = 5\n',
      'journal': '[Journal]\nStorage=persistent\n',
    }

def make_plan(actions, admin, web, access_confirmed):
    if not supported(): raise ValueError('Remediation supports Ubuntu 22.04/24.04 only')
    if any(a not in set(PATHS) | {'firewall'} for a in actions): raise ValueError('Unknown action')
    if set(actions) & {'ssh', 'firewall'}:
        if not access_confirmed: raise ValueError('Prove a second SSH login and sudo access, then pass --access-confirmed')
        verify_admin(admin)
        if len(os.environ.get('SSH_CONNECTION', '').split()) != 4: raise ValueError('Access-sensitive plans require a real SSH session and separate provider console access')
    ports = ssh_ports() if set(actions) & {'ssh', 'firewall', 'fail2ban'} else []
    for action, binary in (('firewall', 'ufw'), ('nginx', 'nginx'), ('fail2ban', 'fail2ban-client')):
        if action in actions and not shutil.which(binary): raise ValueError(binary + ' must be installed before planning')
    if 'updates' in actions and command(['dpkg-query', '-W', '-f=${Status}', 'unattended-upgrades'])[1] != 'install ok installed': raise ValueError('Install unattended-upgrades first; scheduling alone is insufficient')
    content = templates(admin, ports, web)
    needed = []
    for action in actions:
        if action == 'firewall':
            # Explicit desired UFW rule-state checks are performed after apply.
            if not firewall_matches(ports, web): needed.append(action)
            continue
        path = hostpath(PATHS[action])
        if not path.is_file() or path.read_text() != content[action]: needed.append(action)
        elif action == 'ssh' and any(effective_ssh(admin)[1].get(k.lower()) != [v] for k, v in SSH_VALUES.items()): needed.append(action)
        elif action == 'sysctl' and any(command(['sysctl', '-n', k])[1] != v for k, v in SYSCTL_VALUES.items()): needed.append(action)
    return dict(schema_version=1, version=VERSION, host_id=host_id(), expires=int(time.time()) + 3600, inputs=watched_paths(), actions=needed, admin=admin, ports=ports, web=web, access_confirmed=access_confirmed, ssh_connection=os.environ.get('SSH_CONNECTION', ''), limitations='No package installation, upgrades, provider firewall, DNS or certificate provisioning; backups restore managed configuration, not external changes')

def atomic_write(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink(): raise ValueError('Managed symlink refused')
    temporary = path.parent / ('.vpsguard-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(data); file.flush(); os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

def firewall_matches(ports, web):
    code, text = command(['ufw', 'status', 'verbose'])
    return not code and 'Status: active' in text and 'deny (incoming), allow (outgoing)' in text and all(re.search(r'\b' + str(p) + r'/tcp\s+ALLOW', text) for p in list(ports) + ([80, 443] if web else []))

def private_json(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as file: json.dump(data, file, indent=2); file.write('\n')

def transaction_path(identifier):
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}-[a-f0-9]{8}', identifier): raise ValueError('Invalid transaction ID')
    path = STATE / identifier
    if path.is_symlink() or not path.is_dir(): raise ValueError('Transaction absent or unsafe')
    return path

def validate_plan(plan):
    if plan.get('schema_version') != 1 or plan.get('version') != VERSION or plan.get('host_id') != host_id() or plan.get('expires', 0) < time.time(): raise ValueError('Plan expired or belongs to another host/version')
    if plan.get('inputs') != watched_paths(): raise ValueError('Host inputs changed; generate and review a new plan')
    actions = plan.get('actions', [])
    if set(actions) & {'nginx', 'fail2ban', 'journal'}:
        for action in set(actions) & {'nginx', 'fail2ban', 'journal'}:
            checked(['systemctl', 'is-active', SERVICES[action]])
    if not isinstance(actions, list) or len(actions) != len(set(actions)) or any(a not in set(PATHS) | {'firewall'} for a in actions): raise ValueError('Invalid actions')
    if not isinstance(plan.get('web'), bool): raise ValueError('Invalid firewall web flag')
    if set(actions) & {'ssh', 'firewall'}:
        verify_admin(plan.get('admin', ''))
        if not plan.get('access_confirmed') or plan.get('ssh_connection') != os.environ.get('SSH_CONNECTION'): raise ValueError('Access context changed; replan from current SSH session')
    if set(actions) & {'ssh', 'firewall', 'fail2ban'} and plan.get('ports') != ssh_ports(): raise ValueError('SSH port state changed')

def backup(path, folder):
    source = hostpath(path)
    if source.is_symlink(): raise ValueError('Cannot back up a managed symlink')
    if not source.exists(): return dict(path=path, existed=False)
    info = source.stat()
    if not stat.S_ISREG(info.st_mode): raise ValueError('Cannot back up a non-file')
    name = hashlib.sha256(path.encode()).hexdigest()
    data = source.read_bytes()
    atomic_write(folder / name, data)
    return dict(path=path, existed=True, blob=name, sha256=hashlib.sha256(data).hexdigest(), mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)

def save_manifest(folder, manifest): atomic_write(folder / 'manifest.json', json.dumps(manifest, indent=2).encode())

def reload_services(actions, rollback=False):
    if 'ssh' in actions:
        checked(['/usr/sbin/sshd', '-t']); checked(['systemctl', 'reload', 'ssh'])
    if 'nginx' in actions:
        checked(['nginx', '-t']); checked(['systemctl', 'reload', 'nginx'])
    if 'fail2ban' in actions:
        checked(['fail2ban-client', '-t']); checked(['systemctl', 'restart', 'fail2ban'])
    if 'journal' in actions: checked(['systemctl', 'restart', 'systemd-journald'])


def rollback(identifier, automatic=False):
    folder = transaction_path(identifier)
    manifest = json.loads((folder / 'manifest.json').read_text())
    if manifest['state'] in ('rolled_back', 'confirmed') and automatic: return manifest
    if manifest['state'] == 'rolled_back': return manifest
    # Validate all blobs before touching any host file.
    for entry in manifest['files']:
        if entry['existed'] and hashlib.sha256((folder / entry['blob']).read_bytes()).hexdigest() != entry['sha256']: raise RuntimeError('Backup integrity check failed')
    failures = []
    for entry in manifest['files']:
        try:
            target = hostpath(entry['path'])
            if entry['existed']:
                atomic_write(target, (folder / entry['blob']).read_bytes(), entry['mode']); os.chown(target, entry['uid'], entry['gid'])
            else:
                if target.is_symlink(): raise RuntimeError('Managed path changed to symlink')
                target.unlink(missing_ok=True)
        except Exception as error: failures.append(str(error))
    for key, value in manifest.get('sysctl', {}).items():
        if command(['sysctl', '-w', f'{key}={value}'])[0]: failures.append('sysctl restore failed')
    if 'firewall' in manifest['actions']:
        if command(['ufw', 'reload' if manifest['firewall_active'] else '--force', *([] if manifest['firewall_active'] else ['disable'])])[0]: failures.append('firewall restore failed')
    try: reload_services(manifest['actions'], rollback=True)
    except Exception as error: failures.append(str(error))
    manifest['state'] = 'rollback_failed' if failures else 'rolled_back'; manifest['errors'] = failures
    save_manifest(folder, manifest)
    command(['systemctl', 'stop', 'vpsguard-rollback-' + identifier + '.timer'])
    if failures: raise RuntimeError('Rollback incomplete; use provider console and retained backup')
    return manifest


def ensure_state():
    if STATE.is_symlink() or any(p.is_symlink() for p in STATE.parents): raise ValueError('Unsafe transaction directory')
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = STATE.stat()
    if info.st_uid != 0 or info.st_mode & 0o077: raise ValueError('Transaction directory must be root-owned and private')

def apply(plan):
    if not supported(): raise ValueError('Unsupported remediation OS')
    validate_plan(plan)
    actions = plan['actions']
    if not actions: return {'state': 'no_changes', 'actions': []}
    # Only one transaction may be applied at once; pending access confirmation
    # blocks later runs rather than overwriting the rollback snapshot.
    for existing in STATE.glob('*/manifest.json'):
        if json.loads(existing.read_text()).get('state') in ('applying', 'awaiting_confirmation', 'rollback_failed'): raise RuntimeError('Resolve pending/failed transaction before another apply')
    identifier = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S-') + uuid.uuid4().hex[:8]
    folder = STATE / identifier; folder.mkdir(parents=True, mode=0o700); os.chmod(STATE, 0o700)
    paths = {PATHS[a] for a in actions if a in PATHS}
    if 'firewall' in actions: paths |= {'/etc/default/ufw', '/etc/ufw/ufw.conf', '/etc/ufw/user.rules', '/etc/ufw/user6.rules'}
    manifest = dict(id=identifier, state='prepared', actions=actions, admin=plan['admin'], ssh_connection=plan['ssh_connection'], files=[backup(p, folder) for p in sorted(paths)], sysctl={}, firewall_active=False)
    if 'sysctl' in actions: manifest['sysctl'] = {k: checked(['sysctl', '-n', k]) for k in SYSCTL_VALUES}
    if 'firewall' in actions: manifest['firewall_active'] = 'Status: active' in checked(['ufw', 'status'])
    save_manifest(folder, manifest)
    # Copy the engine to root-private storage so the rollback does not depend
    # on a user-writable checkout still existing two minutes later.
    atomic_write(folder / 'engine.py', Path(__file__).read_bytes())
    needs_timer = bool(set(actions) & {'ssh', 'firewall'})
    if needs_timer:
        checked(['systemd-run', '--unit=vpsguard-rollback-' + identifier, '--on-active=120s', '--timer-property=AccuracySec=1s', '/usr/bin/python3', str(folder / 'engine.py'), '--rollback', identifier, '--automatic'])
        checked(['systemctl', 'is-active', 'vpsguard-rollback-' + identifier + '.timer'])
    manifest['state'] = 'applying'; save_manifest(folder, manifest)
    try:
        content = templates(plan['admin'], plan['ports'], plan['web'])
        for action in actions:
            if action in PATHS:
                atomic_write(hostpath(PATHS[action]), content[action].encode(), 0o600 if action == 'ssh' else 0o644)
        if 'ssh' in actions:
            checked(['/usr/sbin/sshd', '-t'])
            code, values = effective_ssh(plan['admin'])
            if code or any(values.get(k.lower()) != [v] for k, v in SSH_VALUES.items()): raise RuntimeError('Effective SSH policy does not match; Include/Match precedence must be reviewed')
        if 'sysctl' in actions:
            for key, value in SYSCTL_VALUES.items(): checked(['sysctl', '-w', f'{key}={value}'])
            if any(checked(['sysctl', '-n', k]) != v for k, v in SYSCTL_VALUES.items()): raise RuntimeError('Active sysctl validation failed')
        if 'firewall' in actions:
            # Preserve active and configured SSH ports before any policy change.
            for port in plan['ports']: checked(['ufw', 'allow', f'{port}/tcp', 'comment', 'VPSGuard SSH'])
            if plan['web']:
                for port in (80, 443): checked(['ufw', 'allow', f'{port}/tcp', 'comment', 'VPSGuard web'])
            checked(['ufw', 'default', 'deny', 'incoming']); checked(['ufw', 'default', 'allow', 'outgoing']); checked(['ufw', '--force', 'enable'])
            status = checked(['ufw', 'status'])
            if 'Status: active' not in status or any(not re.search(r'\b' + str(p) + r'/tcp\s+ALLOW', status) for p in plan['ports']): raise RuntimeError('Firewall status/SSH rule verification failed')
        reload_services(actions)
        manifest['state'] = 'awaiting_confirmation' if needs_timer else 'confirmed'; save_manifest(folder, manifest)
        return dict(id=identifier, state=manifest['state'], actions=actions, confirm='Reconnect as the selected admin, use sudo, then run --confirm ' + identifier if needs_timer else '', deadline_seconds=120 if needs_timer else None)
    except Exception:
        rollback(identifier); raise


def confirm(identifier):
    folder = transaction_path(identifier); manifest = json.loads((folder / 'manifest.json').read_text())
    if manifest['state'] != 'awaiting_confirmation': raise ValueError('Transaction is not awaiting confirmation')
    connection = os.environ.get('SSH_CONNECTION', '')
    if len(connection.split()) != 4 or connection == manifest['ssh_connection'] or os.environ.get('SUDO_USER') != manifest['admin']: raise ValueError('Confirm through sudo from a NEW SSH session as the selected non-root admin')
    verify_admin(manifest['admin'])
    checked(['systemctl', 'is-active', 'vpsguard-rollback-' + identifier + '.timer'])
    # All state changes are serialized by the CLI lock, including timer rollback.
    manifest['state'] = 'confirmed'; save_manifest(folder, manifest)
    checked(['systemctl', 'stop', 'vpsguard-rollback-' + identifier + '.timer'])
    return dict(id=identifier, state='confirmed')


def exit_code(report):
    rows = report.get('results', [])
    if any(r['status'] == 'unknown' for r in rows): return 3
    if any(r['status'] in ('warn', 'fail') for r in rows): return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--audit', action='store_true', help='Default; read-only audit')
    mode.add_argument('--plan', action='store_true', help='Create a reviewed, state-bound plan')
    mode.add_argument('--apply', type=Path, help='Apply previously reviewed plan')
    mode.add_argument('--rollback', help='Restore a transaction')
    mode.add_argument('--confirm', help='Confirm from a new SSH admin session')
    parser.add_argument('--actions', default='', help='Comma-separated ssh,firewall,nginx,sysctl,updates,fail2ban,journal')
    parser.add_argument('--admin', default='', help='Non-root SSH/sudo account for access changes')
    parser.add_argument('--access-confirmed', action='store_true', help='Operator already verified a second login and sudo, and has provider console access')
    parser.add_argument('--web', action='store_true', help='Explicitly allow HTTP/HTTPS when applying firewall')
    parser.add_argument('--output', type=Path, help='New private JSON output file')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--automatic', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Run via sudo; read-only audit also requires root visibility')
    try:
        if args.apply or args.rollback or args.confirm:
            import fcntl
            ensure_state()
            lock_fd = os.open(STATE / 'lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(lock_fd, 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if args.apply:
                    data = args.apply.read_bytes()
                    if len(data) > 1024 * 1024: raise ValueError('Plan too large')
                    report = apply(json.loads(data))
                elif args.rollback: report = rollback(args.rollback, args.automatic)
                else: report = confirm(args.confirm)
        elif args.plan:
            if not args.output: parser.error('--plan requires --output (new private file)')
            actions = [a for a in args.actions.split(',') if a]
            if not actions: parser.error('Select explicit --actions')
            report = make_plan(actions, args.admin, args.web, args.access_confirmed)
        else: report = audit()
        if args.output: private_json(args.output, report)
        if args.json or args.plan or args.apply or args.rollback or args.confirm: print(json.dumps(report, indent=2))
        else:
            print('VPSGuard ' + VERSION + ' read-only audit')
            for row in report['results']: print(f"{row['id']:<40} {row['status']:<15} {row['evidence']}")
        return exit_code(report)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print('VPSGuard: ' + str(error), file=sys.stderr); return 2

if __name__ == '__main__': sys.exit(main())
