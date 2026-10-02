# VPSGuard

**Audit a VPS, review a plan, harden it with a tested recovery path.**

[![Security CI](https://github.com/I-K-M/vpsguard/actions/workflows/security.yml/badge.svg)](https://github.com/I-K-M/vpsguard/actions/workflows/security.yml)

A host-security CLI for Ubuntu 22.04/24.04. It observes SSH, UFW, updates, running kernel settings, services and exposure; remediation is explicit, bound to the host state and backed up before any write.

## Quick start

Requires Python 3.10+, Bash, root visibility and systemd for remediation. Run from a reviewed checkout or verified release, never pipe a mutable URL into a root shell.

```bash
chmod +x vpsguard.sh
sudo ./vpsguard.sh --audit
sudo ./vpsguard.sh --audit --json --output audit.json
```

The default is now **read-only audit**. Version 0.1's interactive mutation flow has been replaced with a reviewable plan/apply interface. No package upgrades, account creation or certificate issuance occurs automatically.

## Review and apply a plan

Install required services separately and verify their current configuration first. For SSH/firewall changes, prove a second non-root SSH login and sudo access, keep the current session open and retain provider-console access.

```bash
sudo --preserve-env=SSH_CONNECTION ./vpsguard.sh --plan \
  --actions ssh,firewall --admin YOUR_ADMIN --access-confirmed \
  --web --output plan.json
sudo cat plan.json
sudo --preserve-env=SSH_CONNECTION ./vpsguard.sh --apply plan.json
```

Plans expire after one hour and are rejected if the host identity, version, configuration snapshot or access context has changed. `--web` explicitly permits HTTP/HTTPS; it is never assumed. SSH ports are discovered from both the running configuration and current connection; none is guessed.

Access changes arm a root-owned systemd rollback timer **before** mutation. From a **new SSH session as the selected admin**, use sudo to confirm the transaction ID printed by apply:

```bash
sudo --preserve-env=SSH_CONNECTION ./vpsguard.sh --confirm TRANSACTION_ID
```

Unconfirmed access changes restore after approximately two minutes. The timer is not a substitute for provider-console access: systemd failure, reboot, host compromise or storage failure can prevent restoration. Keep unrelated administrators and deployment systems from changing the same configuration while a transaction is pending.

Explicit restoration is available, including after confirmation:

```bash
sudo ./vpsguard.sh --rollback TRANSACTION_ID
```

Backups and engine copies live under root-private `/var/lib/vpsguard/transactions`. Keep them until you have reviewed the result. Configuration rollback does not undo external provider rules, package operations or other administrators' changes.

## Controls and remediation

| Area | Audit | Explicit plan action |
|---|---|---|
| SSH | Effective global values; plan also checks selected account context | `ssh` |
| Firewall | UFW activation; listeners and database wildcard exposure | `firewall` |
| Kernel | Active sysctl values, not just configuration files | `sysctl` |
| Nginx | Service, configuration and version-token directive | `nginx` |
| Maintenance | Existing APT cache, reboot marker, automatic update schedule | `updates` |
| Brute force | Fail2ban service | `fail2ban` |
| Logging | Journal persistence; logrotate presence | `journal` |
| Host | Disk, failed units, time, AppArmor, UID 0 accounts, SSH key modes, Docker exposure | Audit only |

Nginx/Fail2ban/journald actions require existing active services. Updates scheduling requires unattended-upgrades installed. Unsupported systems can be audited but cannot receive remediation. Missing tools or failed observations remain `unknown`; an unknown result is never a pass. An active firewall does not prove a complete rule set or provider filtering.

## Automation contract

JSON schema version: `1`. Audit output has stable control IDs and `pass`, `warn`, `fail`, `unknown` or `not_applicable` states. New report files are created privately (0600) and never overwrite existing paths.

| Exit | Meaning |
|---|---|
| 0 | Evaluated controls pass, or operation completed |
| 1 | Audit has warning/failure findings |
| 2 | Invalid request or failed host operation |
| 3 | Audit coverage incomplete (takes precedence over findings) |

Treat codes 1 and 3 as report outcomes; preserve the JSON report. Plans are declarative selections of built-in actions, never arbitrary executable commands. They should still be reviewed as privileged inputs.

## DevSecOps evidence

CI runs Python unit tests, ShellCheck and secret/configuration scanning. Disposable Ubuntu 22.04/24.04 VMs exercise real systemd, SSH on a custom port, UFW, second-login confirmation, idempotence, explicit restore and expiry rollback. It does not test your provider network or production server.

Tag releases produce checksums, a keyless signature and GitHub provenance after required tests pass. See [delivery verification](docs/delivery.md), [threat model](docs/threat-model.md), [contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md).
