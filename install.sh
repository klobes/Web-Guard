#!/usr/bin/env bash
set -euo pipefail
rm_webguard_bundle="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$rm_webguard_bundle/installer/install.py" "${1:-/var/www/html/MartFury}"
