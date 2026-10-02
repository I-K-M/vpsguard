#!/usr/bin/env bash
# Stable entry point; the host operations engine requires Python 3.10+.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/vpsguard.py" "$@"
