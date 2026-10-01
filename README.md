# VPSGuard

A single-file, interactive Bash assistant for auditing and hardening a fresh internet-facing Ubuntu VPS.

## Goals

- Audit first, then remediate only with explicit confirmation.
- Be safe to rerun.
- Preserve the current SSH access path.
- Back up configuration files before changes.
- Validate SSH and Nginx configuration before reload.
- Provide a read-only audit mode.

## Tested target

Initial target: Ubuntu 22.04 LTS and Ubuntu 24.04 LTS.

Other Debian-family systems can be audited, but automatic remediation should be reviewed before use.

## Run

```bash
chmod +x vpsguard.sh
sudo ./vpsguard.sh
```

Read-only audit:

```bash
sudo ./vpsguard.sh --audit
```

## Current checks

1. OS/preflight, disk pressure, failed systemd units
2. APT updates and reboot requirement
3. NTP synchronization
4. Listening ports and UFW baseline
5. UID 0/admin account sanity and SSH-key admin presence
6. Conservative OpenSSH hardening with validation/rollback
7. unattended-upgrades
8. Fail2ban SSH jail
9. Conservative sysctl hardening
10. AppArmor status
11. Nginx install/status/config validation and server token suppression
12. Common database/cache public exposure
13. Docker wildcard-published ports
14. Persistent journald and logrotate
15. Critical SSH file permissions
16. Optional Lynis audit

## Important safety decisions

### SSH

VPSGuard will not offer to disable password/root SSH access until it detects a non-root account with an `authorized_keys` file. After applying SSH changes, keep the current SSH session open and verify a second login before closing it.

### Firewall

The detected SSH port is allowed before UFW is enabled. Existing explicit UFW rules are not reset.

### Docker

Docker-published ports can bypass normal UFW expectations. VPSGuard reports wildcard bindings and recommends binding internal applications to `127.0.0.1` when Nginx is the intended public entry point.

### Kernel settings

The baseline intentionally does not disable IPv6 or global IP forwarding because doing so can break Docker, VPNs, Kubernetes and cloud networking.

### TLS

VPSGuard checks for Certbot but does not automatically request certificates in v0.1. Certificate issuance should happen only after a real domain resolves to the VPS and Nginx virtual-host configuration is known.

## Next milestones

- JSON report output and stable exit-code contract
- `--profile web|docker|node|wordpress` profiles
- Nginx virtual-host wizard + Certbot workflow
- optional auditd rules
- provider firewall checks where provider APIs are configured
- scheduled weekly `--audit` via a systemd timer
- explicit rollback command
- integration tests in disposable Ubuntu VMs/containers
- CIS Level 1 mapping/report without blindly applying every CIS recommendation