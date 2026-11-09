#!/usr/bin/env bash
# RM WebGuard 1.2.0: perditeso nje instalim EKZISTUES (plugin + motor + bridge) pa prekur settings, token ose bans.
#
#   sudo bash update.sh [RRUGA_E_MARTFURY]          # default /var/www/html/MartFury
#   SKIP_TESTS=1 sudo -E bash update.sh              # vetem nese testet dështojnë per arsye mjedisi
#
# Rradha: teston -> lint PHP -> kopje rezerve -> motori -> plugin -> migrim -> assets/cache -> bridge.
# Instalim i ri (pa motor): perdor install.sh.
set -euo pipefail

BUNDLE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP="${1:-/var/www/html/MartFury}"
PLUGIN="$APP/platform/plugins/web-guard"
OPT=/opt/rm-webguard
BACKUP="/var/backups/rm-webguard-update/$(date +%Y%m%d_%H%M%S)"
ENGINE_FILES=(common.py cf_action.py telemetry.py setup.py)
die() { echo "GABIM: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "ekzekutoje me sudo"
[ -f "$APP/artisan" ] || die "$APP nuk eshte projekti Botble"
[ -f "$PLUGIN/.rm-webguard-owned" ] || die "plugin-i web-guard nuk eshte instaluar; perdor install.sh"
[ -f "$OPT/.rm-webguard-owned" ] || die "$OPT nuk eshte motori i instaluar; perdor install.sh"
command -v php >/dev/null || die "php mungon"
command -v python3 >/dev/null || die "python3 mungon"
[ -d "$BUNDLE/web-guard" ] || die "mungon $BUNDLE/web-guard (shpaketo paketen e plote)"

echo "== 1/7 Testet offline (para se te preket asgje)"
if [ "${SKIP_TESTS:-0}" = "1" ]; then
    echo "SKIP_TESTS=1: testet u anashkaluan"
else
    (cd "$BUNDLE/engine" && python3 -m unittest tests tests_paths)
    (cd "$BUNDLE" && python3 tests_bridge.py)
fi

echo "== 2/7 Lint PHP"
while IFS= read -r -d '' f; do
    case "$f" in *.blade.php) continue ;; esac
    php -l "$f" >/dev/null
done < <(find "$BUNDLE/web-guard" -name '*.php' -print0)
echo "PHP_LINT=PASS"

echo "== 3/7 Kopje rezerve te $BACKUP"
mkdir -p "$BACKUP/engine"
cp -a "$PLUGIN" "$BACKUP/plugin"
for f in "${ENGINE_FILES[@]}" panel_bridge.py; do
    if [ -f "$OPT/$f" ]; then cp -a "$OPT/$f" "$BACKUP/engine/$f"; fi
done
if [ -f /etc/systemd/system/rm-webguard-panel.service ]; then cp -a /etc/systemd/system/rm-webguard-panel.service "$BACKUP/"; fi

echo "== 4/7 Motori (para plugin-it)"
for f in "${ENGINE_FILES[@]}"; do install -m 644 -o root -g root "$BUNDLE/engine/$f" "$OPT/$f"; done
install -m 644 -o root -g root "$BUNDLE/agent/panel_bridge.py" "$OPT/panel_bridge.py"
for f in "$BUNDLE"/engine/filters/*.conf; do install -m 644 -o root -g root "$f" "$OPT/filters/$(basename "$f")"; done
python3 -m py_compile "$OPT/common.py" "$OPT/cf_action.py" "$OPT/telemetry.py" "$OPT/setup.py" "$OPT/panel_bridge.py"
echo "ENGINE_FILES=PASS"
python3 "$OPT/setup.py" lockdown-install || echo "KUJDES: mbyllja emergjente nuk u lidh me Apache; ekzekuto: sudo rm-webguard lockdown-install"

echo "== 5/7 Plugin-i"
cp -a "$BUNDLE/web-guard/." "$PLUGIN/"
chown -R www-data:www-data "$PLUGIN"
find "$PLUGIN" -type d -exec chmod 755 {} +
find "$PLUGIN" -type f -exec chmod 644 {} +
echo "PLUGIN_FILES=PASS"

echo "== 6/7 Migrimi, assets dhe cache"
cd "$APP"
runuser -u www-data -- php artisan migrate --path=platform/plugins/web-guard/database/migrations --force
runuser -u www-data -- php artisan cms:plugin:assets:publish web-guard \
    || echo "KUJDES: assets nuk u publikuan; ekzekuto: sudo -u www-data php artisan cms:publish:assets"
runuser -u www-data -- php artisan optimize:clear
runuser -u www-data -- php artisan cache:clear

echo "== 7/7 Sherbimi i bridge-it"
UNIT=/etc/systemd/system/rm-webguard-panel.service
if ! cmp -s "$BUNDLE/agent/rm-webguard-panel.service" "$UNIT"; then
    install -m 644 -o root -g root "$BUNDLE/agent/rm-webguard-panel.service" "$UNIT"
    systemctl daemon-reload
    echo "UNIT_UPDATED=PASS"
fi
systemctl restart rm-webguard-panel.service
sleep 8
systemctl is-active --quiet rm-webguard-panel.service || die "rm-webguard-panel nuk eshte aktiv; shiko: journalctl -u rm-webguard-panel -n 30"
journalctl -u rm-webguard-panel.service -n 5 --no-pager | grep -q "PANEL_SYNC=PASS" \
    && echo "PANEL_SYNC=PASS" || echo "KUJDES: PANEL_SYNC=PASS nuk u pa ende; prit disa sekonda dhe shiko journalctl"

cat <<MSG

UPDATE=PASS
Kopjet rezerve: $BACKUP
Hap Web Guard -> Instalimi per hapat dhe gjendjen e secilit.
Rikthim: kopjo $BACKUP/plugin mbi $PLUGIN dhe $BACKUP/engine/* te $OPT, pastaj
  sudo systemctl restart rm-webguard-panel.service
MSG
