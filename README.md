<div align="center">

# VPSGuard

**Audit first. Harden safely. Preserve access.**

A single-file Bash assistant for auditing and hardening fresh internet-facing Ubuntu servers.

`Ubuntu` · `Bash` · `SSH` · `UFW` · `Fail2ban` · `AppArmor` · `Nginx`

</div>

---

## Why it exists

Fresh VPS deployments tend to fail in predictable ways: permissive SSH, missing firewall rules, exposed services, weak logging, unsafe Docker bindings or hardening changes that accidentally lock out the operator.

VPSGuard is built around one rule:

> **observe first, change second, validate before reload.**

It is designed to be safe to rerun, conservative by default and explicit about risky changes.

## Design goals

- audit before remediation
- preserve the current SSH access path
- back up configuration before changes
- validate SSH and Nginx configuration before reload
- support a read-only audit mode
- keep remediation conservative and reviewable

## Tested target

Primary target:

- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS

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

## What it checks

| Area | Checks |
|---|---|
| Platform | OS support, disk pressure, failed systemd units |
| Updates | APT updates, reboot requirement |
| Time | NTP synchronization |
| Network | listening ports, wildcard exposure, UFW |
| Access | UID 0 accounts, admin users, SSH keys |
| SSH | conservative hardening, validation, rollback safety |
| Host protection | unattended upgrades, Fail2ban, AppArmor |
| Kernel | conservative sysctl baseline |
| Web | Nginx install/status/config validation, server tokens |
| Exposure | database/cache services, Docker-published ports |
| Logging | persistent journald, logrotate |
| Permissions | critical SSH file permissions |
| Audit | optional Lynis run |

## Safety decisions

### SSH

VPSGuard will not offer to disable password/root SSH access until it detects a non-root account with an `authorized_keys` file.

After SSH changes, keep the current session open and verify a second login before closing it.

### Firewall

The detected SSH port is allowed before UFW is enabled. Existing explicit UFW rules are not reset.

### Docker

Docker-published ports can bypass normal UFW expectations. VPSGuard reports wildcard bindings and recommends binding internal applications to `127.0.0.1` when Nginx is the intended public entry point.

### Kernel

The baseline intentionally does not disable IPv6 or global IP forwarding because that can break Docker, VPNs, Kubernetes and cloud networking.

### TLS

VPSGuard checks for Certbot but does not automatically request certificates in v0.1. Certificate issuance should happen only after a real domain resolves to the VPS and the virtual-host configuration is known.

## Roadmap

- JSON report output and stable exit-code contract
- `--profile web|docker|node|wordpress`
- Nginx virtual-host wizard + Certbot workflow
- optional auditd rules
- provider firewall checks
- scheduled audit mode
- explicit rollback command
- disposable VM/container integration tests
- CIS Level 1 mapping without blindly applying every recommendation

---

**Security tooling should reduce operational risk, not create a new lockout path.**
