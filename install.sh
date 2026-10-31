#!/usr/bin/env bash
# CloudPanel Companion setup. Run: sudo bash install.sh   (again to continue or update)
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
exec /usr/bin/python3 -m companion.guided_setup "$@"
