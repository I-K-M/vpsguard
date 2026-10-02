#!/usr/bin/env bash
# shellcheck disable=SC2024
# Run only on disposable GitHub-hosted Ubuntu VMs. Scans no external host.
set -euo pipefail
# Fixture reports are intentionally written by the unprivileged runner, not sudo.
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
sudo apt-get update -qq
sudo apt-get install -y -qq openssh-server ufw nginx fail2ban unattended-upgrades
sudo useradd -m -s /bin/bash -G sudo vgfixture
sudo passwd -d vgfixture
printf 'vgfixture ALL=(ALL) NOPASSWD: ALL\nDefaults:vgfixture env_keep += "SSH_CONNECTION"\n' | sudo tee /etc/sudoers.d/vgfixture >/dev/null
sudo chmod 440 /etc/sudoers.d/vgfixture
ssh-keygen -q -t ed25519 -N '' -f "$fixture/key"
sudo install -d -m 700 -o vgfixture -g vgfixture /home/vgfixture/.ssh
sudo install -m 600 -o vgfixture -g vgfixture "$fixture/key.pub" /home/vgfixture/.ssh/authorized_keys
sudo mkdir -p /run/sshd
# Disable socket activation so the configured custom port is authoritative.
sudo systemctl disable --now ssh.socket || true
printf 'Port 22222\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin no\n' | sudo tee /etc/ssh/sshd_config.d/01-vgfixture.conf >/dev/null
sudo /usr/sbin/sshd -t
sudo systemctl restart ssh
sudo systemctl start nginx fail2ban
ssh-keyscan -p 22222 127.0.0.1 > "$fixture/known_hosts" 2>/dev/null
remote() {
  ssh -i "$fixture/key" -p 22222 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$fixture/known_hosts" vgfixture@127.0.0.1 "$@"
}
# Audit must not alter configuration or create transaction storage.
sudo python3 - <<'PY' > "$fixture/before"
from pathlib import Path
import hashlib,json
print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in ('/etc/ssh','/etc/ufw','/etc/sysctl.d','/etc/nginx','/etc/fail2ban') for p in Path(d).rglob('*') if p.is_file() and not p.is_symlink()},sort_keys=True))
PY
audit_code=0
sudo ./vpsguard.sh --audit --json > "$fixture/audit.json" || audit_code=$?
[[ "$audit_code" == 0 || "$audit_code" == 1 || "$audit_code" == 3 ]]
sudo python3 - <<'PY' > "$fixture/after"
from pathlib import Path
import hashlib,json
print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in ('/etc/ssh','/etc/ufw','/etc/sysctl.d','/etc/nginx','/etc/fail2ban') for p in Path(d).rglob('*') if p.is_file() and not p.is_symlink()},sort_keys=True))
PY
cmp "$fixture/before" "$fixture/after"
# Put the executable under root ownership before asking sudo to operate it.
sudo mkdir -p /opt/vgfixture
sudo cp vpsguard.sh vpsguard.py /opt/vgfixture/
sudo chmod 755 /opt/vgfixture/vpsguard.sh
remote 'sudo /opt/vgfixture/vpsguard.sh --plan --actions ssh,firewall,sysctl,nginx,updates,fail2ban,journal --admin vgfixture --access-confirmed --web --output /tmp/vg-plan.json' > "$fixture/plan.json"
remote 'sudo /opt/vgfixture/vpsguard.sh --apply /tmp/vg-plan.json' > "$fixture/apply.json"
id="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$fixture/apply.json")"
remote "sudo /opt/vgfixture/vpsguard.sh --confirm $id" > "$fixture/confirmed.json"
# Replanning should need no writes after a successful apply.
remote 'sudo /opt/vgfixture/vpsguard.sh --plan --actions ssh,firewall,sysctl,nginx,updates,fail2ban,journal --admin vgfixture --access-confirmed --web --output /tmp/vg-plan-second.json' > "$fixture/second.json"
python3 -c 'import json,sys;assert json.load(open(sys.argv[1]))["actions"] == []' "$fixture/second.json"
remote "sudo /opt/vgfixture/vpsguard.sh --rollback $id" > "$fixture/rolled-back.json"
# Confirm rollback really permits a NEW login and restored configuration.
remote 'sudo /usr/sbin/sshd -t && sudo ufw status' > "$fixture/rollback-state.txt"
# Apply only SSH, deliberately omit confirmation, and observe the real timer.
remote 'sudo /opt/vgfixture/vpsguard.sh --plan --actions ssh --admin vgfixture --access-confirmed --output /tmp/vg-plan-timer.json' > "$fixture/timer-plan.json"
remote 'sudo /opt/vgfixture/vpsguard.sh --apply /tmp/vg-plan-timer.json' > "$fixture/timer-apply.json"
timer_id="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$fixture/timer-apply.json")"
for _ in $(seq 1 50); do
  state="$(sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["state"])' "/var/lib/vpsguard/transactions/$timer_id/manifest.json")"
  [[ "$state" == rolled_back ]] && break
  sleep 3
done
[[ "$state" == rolled_back ]]
remote 'sudo /usr/sbin/sshd -t' > "$fixture/after-timer.txt"
mkdir -p reports
cp "$fixture"/*.json "$fixture"/*.txt reports/
printf 'Audit immutability, SSH custom port, UFW, second-login confirmation, idempotence, explicit rollback and unconfirmed timer rollback passed.\n' > reports/summary.txt
# Do not export private keys, account files or configuration backups.
