#!/usr/bin/env bash
set -euo pipefail
rm_webguard_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$rm_webguard_directory/setup.py" install
