#!/usr/bin/env python3
"""Fail2ban action: temporary, owned, zone-scoped Cloudflare IP bans.

Desired leases are committed before API calls. Reconciliation retries failed
ban/unban operations. Multiple jails share one block until the last lease ends.
"""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from common import CONFIG, STATE, JAILS, load, canonical_ip, ignored
from telemetry import record


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Cloudflare:
    def __init__(self, settings):
        token_file = Path(settings['token_file'])
        details = token_file.stat()
        if details.st_uid != 0 or stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError('cloudflare.token duhet root dhe chmod 600')
        self.token = token_file.read_text().strip()
        if not self.token or any(char.isspace() for char in self.token):
            raise ValueError('Token mungon ose eshte i pavlefshem')
        if not re.fullmatch(r'[a-fA-F0-9]{32}', settings['zone_id']):
            raise ValueError('zone_id mungon')
        self.zone_url = 'https://api.cloudflare.com/client/v4/zones/' + settings['zone_id']
        self.base = self.zone_url + '/firewall/access_rules/rules'
        self.prefix = 'RM-WebGuard-v1:' + settings['instance_id'] + ':'
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))

    def zone_name(self):
        return self.request('GET', url=self.zone_url)['result']['name'].lower()

    def request(self, method, suffix='', body=None, query=None, url=None):
        url = url or self.base + suffix
        if query:
            url += '?' + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(url, data=data, method=method, headers={
            'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json',
            'User-Agent': 'RM-WebGuard/1.0'})
        try:
            with self.opener.open(request, timeout=8) as response:
                result = json.loads(response.read(2 * 1024 * 1024))
        except urllib.error.HTTPError as error:
            raise RuntimeError('Cloudflare HTTP ' + str(error.code)) from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            raise RuntimeError('Cloudflare: lidhja ose pergjigjja deshtoi') from None
        if result.get('success') is not True:
            codes = [str(item.get('code', 'unknown')) for item in result.get('errors', [])]
            raise RuntimeError('Cloudflare API errors=' + ','.join(codes))
        return result

    def owned_rules(self):
        rules = []
        for page in range(1, 101):
            response = self.request('GET', query={'notes': self.prefix, 'mode': 'block',
                                                 'match': 'all', 'per_page': 100, 'page': page})
            current = response['result']
            if not isinstance(current, list):
                raise RuntimeError('Cloudflare list result nuk eshte liste')
            for rule in current:
                if rule.get('mode') != 'block' or not rule.get('notes', '').startswith(self.prefix):
                    continue
                if rule.get('configuration', {}).get('target') not in ('ip', 'ip6'):
                    continue
                canonical_ip(rule['configuration']['value'])
                if not re.fullmatch(r'[a-fA-F0-9]{32}', rule.get('id', '')):
                    raise RuntimeError('Cloudflare rule ID i pavlefshem')
                rules.append(rule)
            if len(current) < 100:
                return rules
        raise RuntimeError('Lista tejkalon 10000 rregulla; nuk u perfundua kontrolli')

    def create(self, ip, expires):
        address = canonical_ip(ip)
        result = self.request('POST', body={'mode': 'block', 'configuration': {
            'target': 'ip' if address.version == 4 else 'ip6', 'value': str(address)},
            'notes': self.prefix + 'expires=' + str(int(expires))})['result']
        if not re.fullmatch(r'[a-fA-F0-9]{32}', result.get('id', '')):
            raise RuntimeError('Cloudflare create nuk ktheu rule ID')
        return result['id']

    def delete(self, rule):
        if not rule.get('notes', '').startswith(self.prefix) or rule.get('mode') != 'block':
            raise RuntimeError('Refuzohet fshirja e nje rregulli jashte modulit')
        self.request('DELETE', '/' + rule['id'])


def connect():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(STATE / 'state.sqlite3', timeout=10)
    db.execute('CREATE TABLE IF NOT EXISTS leases (zone TEXT, ip TEXT, jail TEXT, expires REAL, PRIMARY KEY(zone,ip,jail))')
    db.execute('CREATE TABLE IF NOT EXISTS edge (zone TEXT, ip TEXT, rule_id TEXT, status TEXT, checked REAL, PRIMARY KEY(zone,ip))')
    db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)')
    db.commit()
    return db


def log(event, **fields):
    record(event, fields)
    print(json.dumps({'event': event, 'at': int(time.time()), **fields}, sort_keys=True), flush=True)


def reconcile(db, settings, force=False, api=None, now=None):
    now = time.time() if now is None else now
    db.execute('DELETE FROM leases WHERE expires<=?', (now,))
    if not settings['enabled'] or settings['dry_run']:
        db.execute('DELETE FROM leases')
    db.commit()
    previous = db.execute('SELECT value FROM meta WHERE key="next_sync"').fetchone()
    if not force and previous and float(previous[0]) > now:
        return
    # Never send a lease created for another zone to the current zone endpoint.
    old_zones = db.execute('SELECT DISTINCT zone FROM leases WHERE zone<>? UNION SELECT DISTINCT zone FROM edge WHERE zone<>? AND status<>"released"',
                           (settings['zone_id'], settings['zone_id'])).fetchall()
    if old_zones:
        raise RuntimeError('zone_id ndryshoi me bllokime ekzistuese; rikthe zone_id dhe zhblloko para ndryshimit')
    has_edge = db.execute('SELECT 1 FROM edge WHERE status<>"released" LIMIT 1').fetchone()
    touched = db.execute('SELECT value FROM meta WHERE key="remote_touched"').fetchone()
    if settings['dry_run'] and not has_edge and not (touched and touched[0]=='1'):
        return
    if not settings['zone_id']:
        return
    db.execute('INSERT OR REPLACE INTO meta VALUES ("next_sync",?)',
               (str(now + settings['sync_interval_seconds']),))
    db.commit()
    api = api or Cloudflare(settings)
    rules = api.owned_rules()
    desired = dict(db.execute('SELECT ip,MAX(expires) FROM leases WHERE zone=? AND expires>? GROUP BY ip',
                              (settings['zone_id'], now)))
    # A new whitelist takes effect for both new and already active decisions.
    for ip in list(desired):
        if ignored(canonical_ip(ip), settings):
            db.execute('DELETE FROM leases WHERE zone=? AND ip=?', (settings['zone_id'], ip))
            del desired[ip]
    db.commit()
    present = set()
    changes = 0
    def before_write():
        # A POST can succeed remotely even if its response is lost locally.
        db.execute('INSERT OR REPLACE INTO meta VALUES ("remote_touched","1")')
        db.commit()
    for rule in rules:
        ip = str(canonical_ip(rule['configuration']['value']))
        if ip in desired:
            present.add(ip)
            db.execute('INSERT OR REPLACE INTO edge VALUES (?,?,?,?,?)',
                       (settings['zone_id'], ip, rule['id'], 'active', now))
        elif changes < settings['maximum_changes_per_sync']:
            before_write()
            api.delete(rule)
            changes += 1
            db.execute('INSERT OR REPLACE INTO edge VALUES (?,?,?,?,?)',
                       (settings['zone_id'], ip, rule['id'], 'released', now))
            db.commit()
            log('UNBAN_EDGE', ip=ip)
    # Clear stale local edge state only after a successful complete remote listing.
    remote_ips = {str(canonical_ip(rule['configuration']['value'])) for rule in rules}
    for (ip,) in db.execute('SELECT ip FROM edge WHERE zone=? AND status="active"', (settings['zone_id'],)).fetchall():
        if ip not in remote_ips:
            db.execute('UPDATE edge SET status="released",checked=? WHERE zone=? AND ip=?',
                       (now, settings['zone_id'], ip))
    db.commit()
    for ip, expires in desired.items():
        if ip in present or changes >= settings['maximum_changes_per_sync']:
            continue
        before_write()
        rule_id = api.create(ip, expires)
        changes += 1
        db.execute('INSERT OR REPLACE INTO edge VALUES (?,?,?,?,?)',
                   (settings['zone_id'], ip, rule_id, 'active', now))
        db.commit()
        log('BAN_EDGE', ip=ip, expires_at=int(expires))
    if not desired and not rules:
        db.execute('INSERT OR REPLACE INTO meta VALUES ("remote_touched","0")')
        db.commit()
    db.execute('INSERT OR REPLACE INTO meta VALUES ("last_api_success",?)',(str(now),))
    db.commit()


def ban(db, settings, ip, jail, started, duration, api=None, now=None):
    now = time.time() if now is None else now
    address = canonical_ip(ip)
    if jail not in JAILS:
        raise ValueError('Jail jashte modulit')
    duration = float(duration)
    started = float(started)
    if not 0 < duration <= settings['maximum_bantime_seconds'] or started > now + 60:
        raise ValueError('Koha e bllokimit eshte e pavlefshme')
    if ignored(address, settings):
        log('IGNORED', ip=str(address), jail=jail)
        return
    if not settings['enabled'] or settings['dry_run']:
        log('WOULD_BAN', ip=str(address), jail=jail, seconds=duration)
        return
    expires = started + duration
    if expires <= now:
        return
    db.execute('INSERT INTO leases VALUES (?,?,?,?) ON CONFLICT(zone,ip,jail) DO UPDATE SET expires=MAX(expires,excluded.expires)',
               (settings['zone_id'], str(address), jail, expires))
    db.commit()
    log('BAN_REQUESTED', ip=str(address), jail=jail, expires_at=int(expires))
    reconcile(db, settings, api=api, now=now)


def unban(db, settings, ip, jail=None, api=None, now=None):
    address = str(canonical_ip(ip))
    if jail is not None and jail not in JAILS:
        raise ValueError('Jail jashte modulit')
    if jail:
        db.execute('DELETE FROM leases WHERE zone=? AND ip=? AND jail=?', (settings['zone_id'], address, jail))
    else:
        db.execute('DELETE FROM leases WHERE zone=? AND ip=?', (settings['zone_id'], address))
    db.commit()
    log('UNBAN_REQUESTED', ip=address, jail=jail)
    reconcile(db, settings, api=api, now=now)


def site_domain():
    try:
        value = json.loads((CONFIG / 'panel-bridge.json').read_text()).get('host', '')
    except (OSError, ValueError):
        return ''
    return value.lower() if re.fullmatch(r'[a-z0-9.-]{3,253}', value.lower()) else ''


def verify_zone(api):
    """Catch an Account ID (or another zone's ID) typed as Zone ID. Needs Zone Read; skipped without it."""
    expected = site_domain()
    if not expected:
        return
    try:
        name = api.zone_name()
    except RuntimeError as error:
        log('ZONE_UNVERIFIED', message=str(error))
        return
    if expected != name and not expected.endswith('.' + name):
        raise RuntimeError('zone_id i takon ' + name + ', jo ' + expected + '. Kontrollo qe nuk eshte Account ID.')
    log('ZONE_VERIFIED', zone=name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('ban','unban','reconcile','status','api-check','release-all'))
    parser.add_argument('args', nargs='*')
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Ekzekutoje me sudo')
    os.umask(0o077)
    settings = load()
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE / 'action.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with contextlib.closing(connect()) as db:
            action = arguments.action
            values = arguments.args
            if action == 'ban' and len(values) == 4:
                ban(db, settings, *values)
            elif action == 'unban' and len(values) in (1,2):
                unban(db, settings, *values)
            elif action == 'reconcile' and not values:
                reconcile(db, settings)
            elif action == 'release-all' and not values:
                db.execute('DELETE FROM leases'); db.commit()
                reconcile(db, settings, force=True)
            elif action == 'api-check' and values in ([], ['write']):
                api = Cloudflare(settings)
                api.owned_rules()
                verify_zone(api)
                log('API_READ_CHECK_PASS', zone=settings['zone_id'])
                if values == ['write']:
                    # Documentation address: never a real Internet visitor.
                    test_ip = '198.51.100.23'
                    existing = [r for r in api.owned_rules()
                                if r['configuration']['value'] == test_ip]
                    for rule in existing:
                        api.delete(rule)
                    identifier = api.create(test_ip, time.time() + 30)
                    api.delete({'id': identifier, 'mode': 'block',
                                'notes': api.prefix, 'configuration': {'value': test_ip}})
                    log('API_WRITE_DELETE_CHECK_PASS', test_ip=test_ip)
            elif action == 'status' and not values:
                print(json.dumps({'dry_run': settings['dry_run'], 'enabled':settings['enabled'],
                    'leases':list(db.execute('SELECT zone,ip,jail,expires FROM leases ORDER BY expires')),
                    'edge':list(db.execute('SELECT zone,ip,status,checked FROM edge ORDER BY ip'))},indent=2))
            else:
                parser.error('Argumente te pavlefshme')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        log('ERROR', message=str(error))
        sys.exit(1)
