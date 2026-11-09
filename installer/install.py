#!/usr/bin/env python3
"""Install only the new plugin and its owned root engine/bridge."""
import datetime
import grp
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def run(args, cwd=None, timeout=180):
    result=subprocess.run(args,cwd=cwd,text=True,capture_output=True,timeout=timeout)
    print(result.stdout, end='', flush=True)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip()[-2000:])
    return result.stdout


def php(app,*arguments):
    return run(['runuser','-u','www-data','--','php','artisan',*arguments],cwd=app)


def main():
    if os.geteuid()!=0:
        raise RuntimeError('Ekzekuto me sudo bash install.sh /var/www/html/MartFury')
    os.umask(0o077)
    app=Path(sys.argv[1]).resolve(strict=True)
    if not all((app/path).exists() for path in ['artisan','vendor/autoload.php','platform/core/base','platform/packages/plugin-management']):
        raise RuntimeError('Rruga nuk eshte projekti Botble i verifikuar')
    for command in ['php','runuser','systemctl','fail2ban-client','fail2ban-regex','apache2ctl','a2enmod','curl']:
        if not shutil.which(command):
            raise RuntimeError(command+' mungon. Instalo prerequisites sipas README.')
    run(['apache2ctl','configtest']);run(['fail2ban-client','ping'])
    version=run(['php','-r','echo PHP_VERSION;'])
    if tuple(int(v) for v in version.split('.')[:2])<(8,2):
        raise RuntimeError('Kerkohet PHP >= 8.2')
    for path in sorted((ROOT/'web-guard').rglob('*.php')):
        if not path.name.endswith('.blade.php'):
            run(['php','-l',str(path)])
    destination=app/'platform/plugins/web-guard'
    if destination.exists():
        if not (destination/'.rm-webguard-owned').exists():
            raise RuntimeError('web-guard ekziston pa shenje pronesie; nuk mbishkruhet')
    backup=Path('/var/backups/rm-webguard-botble')/datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    backup.mkdir(parents=True,mode=0o700)
    if destination.exists():
        # Update: keep a copy of the plugin, then overlay the new files (the owner marker stays).
        shutil.copytree(destination,backup/'plugin')
        for source in (ROOT/'web-guard').rglob('*'):
            target=destination/source.relative_to(ROOT/'web-guard')
            if source.is_dir():
                target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target);target.chmod(0o644)
        for path in [destination,*destination.rglob('*')]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        print('PLUGIN_UPDATED=PASS',flush=True)
    config=Path('/etc/rm-webguard')
    if config.exists():
        for name in ['settings.json','active.json','panel-bridge.json']:
            if (config/name).exists():
                shutil.copy2(config/name,backup/name)
    config.mkdir(mode=0o750,exist_ok=True)
    config.chmod(0o750);os.chown(config,0,grp.getgrnam('www-data').gr_gid)
    key=config/'panel-bridge.key'
    if not key.exists():
        key.write_text(secrets.token_hex(32)+'\n')
    if len(key.read_text().strip())!=64:
        raise RuntimeError('Bridge key ekzistues i pavlefshem')
    key.chmod(0o640);os.chown(key,0,grp.getgrnam('www-data').gr_gid)
    fresh=not destination.exists()
    if fresh:
        shutil.copytree(ROOT/'web-guard',destination)
        for path in [destination,*destination.rglob('*')]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        (destination/'.rm-webguard-owned').write_text('RM WebGuard Botble 1.2.0\n')
        (destination/'.rm-webguard-owned').chmod(0o644)
    print('BACKUP_DIR='+str(backup),flush=True)
    # Only this plugin's additive migrations; do not run unrelated pending migrations.
    php(app,'migrate','--path=platform/plugins/web-guard/database/migrations','--force')
    # Activation reports already-active as an error; avoid that on an identical rerun.
    # Always use Botble's command; a narrowly recognised already-active result is harmless.
    activated=subprocess.run(['runuser','-u','www-data','--','php','artisan','cms:plugin:activate','web-guard'],cwd=app,capture_output=True,text=True,timeout=180)
    print(activated.stdout,end='',flush=True)
    if activated.returncode:
        # Independently prove routes/command readiness rather than parse a translated message.
        try:
            php(app,'web-guard:self-test')
        except Exception:
            raise RuntimeError('Aktivizimi Botble deshtoi: '+(activated.stderr or activated.stdout)[-1500:])
    php(app,'web-guard:self-test')
    subprocess.run(['runuser','-u','www-data','--','php','artisan','cms:plugin:assets:publish','web-guard'],cwd=app,capture_output=True,text=True,timeout=180)
    php(app,'optimize:clear')
    run(['/usr/bin/python3',str(ROOT/'engine/setup.py'),'install'])
    run(['/usr/bin/python3','/opt/rm-webguard/setup.py','lockdown-install'])
    opt=Path('/opt/rm-webguard')
    shutil.copyfile(ROOT/'agent/panel_bridge.py',opt/'panel_bridge.py');(opt/'panel_bridge.py').chmod(0o644)
    previous={}
    if (config/'panel-bridge.json').exists():
        try:
            previous=json.loads((config/'panel-bridge.json').read_text())
        except ValueError:
            previous={}
    bridge={'url':'http://127.0.0.1:5555/web-guard-agent/sync','host':os.environ.get('RM_SITE_HOST') or previous.get('host') or 'klobes.al'}
    (config/'panel-bridge.json').write_text(json.dumps(bridge,indent=2)+'\n');(config/'panel-bridge.json').chmod(0o600)
    run(['/usr/bin/python3',str(opt/'panel_bridge.py'),'check'])
    service=Path('/etc/systemd/system/rm-webguard-panel.service')
    shutil.copyfile(ROOT/'agent/rm-webguard-panel.service',service);service.chmod(0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','rm-webguard-panel.service'])
    run(['systemctl','is-active','--quiet','rm-webguard-panel.service'])
    print('BOTBLE_INSTALL=PASS MENU=Web_Guard',flush=True)
    print('Hap panelin Botble > Web Guard. Settings aktive importohen nga motori. Token Cloudflare vendoset vetem ne server.',flush=True)


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print('ERROR: '+str(error),file=sys.stderr)
        print('Instalimi nuk u konfirmua. Tabelat e reja dhe backup ruhen; instaluesi nuk fshin histori.',file=sys.stderr)
        sys.exit(1)
