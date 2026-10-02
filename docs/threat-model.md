# Threat model and recovery contract

VPSGuard executes privileged host changes from operator-reviewed source. It assumes a trustworthy root account, systemd, OS utilities and filesystem. It does not defend against a compromised kernel or a malicious root administrator.

## Boundaries

- Audit executes observations only and does not refresh APT metadata or run remediation commands.
- Plans contain built-in action IDs, host identity, configuration fingerprints and expiry; a changed input invalidates the plan.
- Application rejects pending transactions, serializes apply/confirm/rollback, refuses managed symlinks and validates every backup before restoration.
- Backup errors stop application. SSH syntax and selected-account effective values are checked before reload; kernel values are checked after writes.
- SSH/firewall changes require explicit operator evidence of previous access and a second-session confirmation. The rollback engine is copied into root-private storage and scheduled before writes.

## Recovery limits

The timer restores managed files, UFW activation and captured sysctl values. Reload/start failures remain errors with retained backups. Restoration cannot guarantee connectivity through an external firewall, DNS change, host reboot or failed systemd. Backups are sensitive and must not be uploaded to issues or CI artifacts.

Tests use local keys and loopback SSH on disposable runners; reports omit keys, file contents and backups. A green VM test proves those fixture scenarios, not universal lockout prevention. Ubuntu 22.04/24.04 are the remediation scope; other distributions receive observations only.
