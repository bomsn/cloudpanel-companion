#!/usr/bin/env bash
# CloudPanel Companion setup. Run: sudo bash install.sh   (again to continue or update)
set -euo pipefail
# The runtime, its virtualenv and the published assets are read by the service
# accounts, so they must not inherit a stricter umask from the caller's shell.
# Private files are written with explicit modes and are unaffected.
umask 022
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
exec /usr/bin/python3 -m companion.guided_setup "$@"
