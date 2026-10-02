# Contributing

Run `python3 -m unittest discover -s tests -v`, `shellcheck vpsguard.sh tests/vm.sh`, `bash -n vpsguard.sh tests/vm.sh` and `git diff --check` before submitting.

Never run `tests/vm.sh` on a personal or production host: it creates a fixture account and modifies host SSH/UFW. CI uses disposable GitHub-hosted VMs. New privileged actions need failing and successful fixture cases, actual postconditions and recovery evidence. Do not turn unknown observations into pass results or suppress scan failures.

Keep operator credentials, private keys, configuration backups and real customer reports outside Git. Document semantic changes and supported OS limits. The CLI entry point is Bash; the operations engine uses Python standard library only.
