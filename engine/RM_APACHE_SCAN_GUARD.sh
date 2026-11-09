#!/usr/bin/env bash
# Apache scan guard for the verified klobes.al VirtualHost *:5555.
# Usage: sudo bash RM_APACHE_SCAN_GUARD.sh install|check|remove
# No argument performs a read-only check.
set -euo pipefail
command -v python3 >/dev/null || { echo 'ERROR: python3 mungon.' >&2; exit 1; }
exec python3 - "$@" <<'RM_GUARD_PYTHON'
import argparse
import datetime
import fcntl
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SITE = Path('/etc/apache2/sites-enabled/000-default.conf')
GUARD = Path('/etc/apache2/rm-guards/scan-guard-5555.conf')
BACKUPS = Path('/var/backups/rm-apache-scan-guard')
LOCK = Path('/run/lock/rm-apache-scan-guard.lock')
BEGIN = '# BEGIN RM-APACHE-SCAN-GUARD-5555 v1'
END = '# END RM-APACHE-SCAN-GUARD-5555 v1'
PATTERNS = (
    r'(^|/)(wp-login\.php|wp-config\.php|wp-admin|wp-content|wp-includes|xmlrpc\.php|_next|\.git)(/|$)',
    r'(^|/)\.env[^/]*(/|$)',
    r'^/(wp|wordpress|server-status|server-info)(/|$)',
)
GUARD_TEXT = (
    '# RM-APACHE-SCAN-GUARD-5555 v1; included only inside VirtualHost *:5555.\n'
    '# Return Apache default 403 before the application front controller.\n'
    'RewriteEngine On\n'
    'ErrorDocument 403 default\n'
    + ''.join('RewriteCond %{REQUEST_URI} "' + p + '" [NC' +
              (',OR' if i < len(PATTERNS) - 1 else '') + ']\n'
              for i, p in enumerate(PATTERNS))
    + 'RewriteRule ^ - [F,L]\n'
).encode()
VHOST_RE = re.compile(
    r'^[ \t]*<VirtualHost[ \t]+([^>\r\n]+)>[^\r\n]*\r?\n'
    r'.*?^[ \t]*</VirtualHost>[ \t]*(?:\r?\n|$)', re.M | re.S | re.I)
MARKER_RE = re.compile(
    r'^[ \t]*' + re.escape(BEGIN) + r'\r?\n'
    r'[ \t]*Include[ \t]+"' + re.escape(str(GUARD)) + r'"[ \t]*\r?\n'
    r'[ \t]*' + re.escape(END) + r'[ \t]*\r?\n', re.M)


def run(args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        details = (result.stderr or result.stdout).strip()
        raise RuntimeError(' '.join(args) + ': ' + details)
    return result.stdout


def target_block(text):
    targets = [m for m in VHOST_RE.finditer(text)
               if any(a.endswith(':5555') for a in m.group(1).split())]
    if len(targets) != 1 or targets[0].group(1).strip() != '*:5555':
        raise RuntimeError('Duhet pikerisht nje VirtualHost *:5555 ne 000-default.conf.')
    target = targets[0]
    if not re.search(r'^\s*DocumentRoot\s+"?/var/www/html/public_html"?\s*$',
                     target.group(), re.M):
        raise RuntimeError('DocumentRoot i :5555 ndryshon nga konfigurimi i verifikuar.')
    if not re.search(r'^\s*ServerName\s+klobes\.al\s*$', target.group(), re.M | re.I):
        raise RuntimeError('ServerName i :5555 nuk eshte klobes.al.')
    return target


def patch_config(original, action):
    text = original.decode('utf-8')
    target = target_block(text)
    markers = list(MARKER_RE.finditer(text))
    if text.count(BEGIN) != len(markers) or text.count(END) != len(markers):
        raise RuntimeError('Blloku i menaxhuar eshte ndryshuar; ndalohet mbishkrimi.')
    if len(markers) > 1 or (markers and not
                           target.start() <= markers[0].start() < markers[0].end() <= target.end()):
        raise RuntimeError('Blloku i menaxhuar eshte i dyfishuar ose jashte :5555.')
    if markers:
        marker = markers[0]
        if action == 'install':
            return original
        return (text[:marker.start()] + text[marker.end():]).encode()
    if str(GUARD) in text:
        raise RuntimeError('Include ekziston pa shenjat e menaxhimit; kerkohet kontroll.')
    if action == 'remove':
        return original
    newline = '\r\n' if '\r\n' in original.decode() else '\n'
    position = text.index('\n', target.start()) + 1
    block = newline.join(('    ' + BEGIN,
                          '    Include "' + str(GUARD) + '"',
                          '    ' + END, ''))
    return (text[:position] + block + text[position:]).encode()


def atomic_write(path, content):
    metadata = path.stat() if path.exists() else None
    fd, tmp = tempfile.mkstemp(prefix='.rm-scan-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode) if metadata else 0o644)
            if metadata:
                os.fchown(handle.fileno(), metadata.st_uid, metadata.st_gid)
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def probe(path, expected):
    output = run(['curl', '--noproxy', '*', '-sS', '--max-time', '15',
                  '-o', '/dev/null', '-H', 'Host: klobes.al',
                  '-w', '%{http_code} %{time_starttransfer} %{time_total}',
                  'http://127.0.0.1:5555' + path], timeout=20).strip()
    fields = output.split()
    if len(fields) != 3:
        raise RuntimeError('Pergjigje curl e papritur: ' + output)
    print('PATH=' + path + ' HTTP=' + fields[0] + ' TTFB=' + fields[1] +
          's TOTAL=' + fields[2] + 's', flush=True)
    if fields[0] != str(expected):
        raise RuntimeError(path + ': pritej HTTP ' + str(expected) + ', erdhi ' + fields[0])


def verify_installed():
    probe('/', 200)
    probe('/wp/wp-includes/js/wp-emoji.js', 403)
    probe('/frontend/_next/static/', 403)


def main(action):
    if os.geteuid() != 0:
        raise RuntimeError('Ekzekutoje me sudo.')
    for command in ('apache2ctl', 'systemctl', 'curl'):
        if not shutil.which(command):
            raise RuntimeError(command + ' mungon.')
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        site = SITE.resolve(strict=True)
        original = site.read_bytes()
        modified = patch_config(original, 'remove' if action == 'remove' else 'install')
        previous_guard = GUARD.read_bytes() if GUARD.exists() else None
        if previous_guard is not None and previous_guard != GUARD_TEXT:
            raise RuntimeError('Skedari scan-guard-5555.conf eshte i ndryshem; nuk mbishkruhet.')
        installed = BEGIN.encode() in original
        if installed and previous_guard is None:
            raise RuntimeError('Include ekziston por skedari guard mungon.')
        run(['apache2ctl', 'configtest'])
        run(['systemctl', 'is-active', '--quiet', 'apache2'])
        if 'rewrite_module' not in run(['apache2ctl', '-M']):
            raise RuntimeError('mod_rewrite nuk eshte aktiv; nuk u ndryshua konfigurimi.')
        print('VHOST=' + str(site) + ' PORT=5555 INSTALLED=' + str(installed).lower(), flush=True)
        if action == 'check':
            print('CHECK=PASS; pa ndryshim konfigurimi.', flush=True)
            if installed:
                verify_installed()
            else:
                probe('/', 200)
            return
        if modified == original:
            if installed:
                verify_installed()
            print('RESULT=ALREADY_INSTALLED' if installed else 'RESULT=ALREADY_REMOVED', flush=True)
            return
        probe('/', 200)
        backup = BACKUPS / (datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '_' + str(os.getpid()))
        backup.mkdir(parents=True, mode=0o700)
        shutil.copy2(site, backup / 'vhost.before')
        if previous_guard is not None:
            shutil.copy2(GUARD, backup / 'guard.before')
        print('BACKUP_DIR=' + str(backup), flush=True)
        if site.read_bytes() != original:
            raise RuntimeError('Konfigurimi ndryshoi gjate kontrollit; nuk u shkrua.')
        try:
            if action == 'install':
                GUARD.parent.mkdir(parents=True, exist_ok=True)
                atomic_write(GUARD, GUARD_TEXT)
            atomic_write(site, modified)
            run(['apache2ctl', 'configtest'])
            run(['systemctl', 'reload', 'apache2'])
            if action == 'install':
                verify_installed()
            else:
                probe('/', 200)
        except BaseException as exc:
            print('ERROR=' + str(exc) + '; po kthehet konfigurimi.', file=sys.stderr, flush=True)
            # Do not overwrite a concurrent edit made outside this installer.
            if site.read_bytes() == modified:
                atomic_write(site, original)
            else:
                raise RuntimeError('Konfigurimi u ndryshua nga jashte. Kontrollo BACKUP_DIR; pa mbishkrim.') from exc
            if previous_guard is not None:
                atomic_write(GUARD, previous_guard)
            elif GUARD.exists() and GUARD.read_bytes() == GUARD_TEXT:
                GUARD.unlink()
            run(['apache2ctl', 'configtest'])
            run(['systemctl', 'reload', 'apache2'])
            print('ROLLBACK=PASS', file=sys.stderr, flush=True)
            raise RuntimeError('Ndryshimi nuk u mbajt. ' + str(exc)) from exc
        print('RESULT=' + ('INSTALLED' if action == 'install' else 'REMOVED') + ' PASS', flush=True)
        if action == 'remove':
            print('Guard nuk perfshihet me; skedari i tij ruhet per kontroll.', flush=True)


parser = argparse.ArgumentParser(description='Guard per skanimin web te klobes.al :5555.')
parser.add_argument('action', nargs='?', choices=('check', 'install', 'remove'), default='check')
args = parser.parse_args()
try:
    main(args.action)
except Exception as error:
    print('ERROR: ' + str(error), file=sys.stderr)
    sys.exit(1)
RM_GUARD_PYTHON
