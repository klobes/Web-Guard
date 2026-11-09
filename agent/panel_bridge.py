#!/usr/bin/env python3
"""Signed loopback bridge. PHP queues data; only this root service runs the engine."""
import argparse
import contextlib
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.request
import uuid

sys.path.insert(0, '/opt/rm-webguard')
from common import CONFIG, STATE, BUILTIN_PROBE, canonical_ip, load, lockdown_level, probe_regex, validate
from telemetry import database, record

KEY = CONFIG/'panel-bridge.key'
BRIDGE = CONFIG/'panel-bridge.json'
LOG = Path('/var/log/rm-webguard/access.log')
LOCKFILE = Path('/etc/apache2/rm-guards/lockdown-5555.conf')
LINE = re.compile(r'^(\S+) - - \[([^\]]+)\] "([A-Z]+) ([^\s"]+) HTTP/[\d.]+" (\d{3})$')
PROBE = re.compile(BUILTIN_PROBE, re.I)


def meta(db, key, default='0'):
    value = db.execute('SELECT value FROM metadata WHERE key=?',(key,)).fetchone()
    return value[0] if value else default


def put(db, key, value):
    db.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)',(key,str(value)))
    db.commit()


def atomic(path, data):
    temporary = path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    try:
        with temporary.open('x') as handle:
            os.chmod(temporary,0o600)
            json.dump(data,handle,indent=2);handle.write('\n');handle.flush();os.fsync(handle.fileno())
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def send(payload):
    options = json.loads(BRIDGE.read_text())
    # Fixed loopback origin; settings from PHP can never redirect root requests.
    if options.get('url') != 'http://127.0.0.1:5555/web-guard-agent/sync' or options.get('host') != 'klobes.al':
        raise ValueError('Destinacioni i bridge nuk perputhet me konfigurimin e verifikuar')
    key_stat = KEY.stat()
    if key_stat.st_uid != 0 or stat.S_IMODE(key_stat.st_mode) & 0o007:
        raise ValueError('panel-bridge.key duhet root, pa leje per others')
    key = KEY.read_text().strip()
    if not re.fullmatch('[a-f0-9]{64}',key):
        raise ValueError('Bridge key i pavlefshem')
    body = json.dumps(payload,separators=(',',':')).encode()
    stamp = str(int(time.time()));nonce=uuid.uuid4().hex
    signature=hmac.new(key.encode(),stamp.encode()+b'\n'+nonce.encode()+b'\n'+body,hashlib.sha256).hexdigest()
    request=urllib.request.Request(options['url'],data=body,method='POST',headers={
        'Host':options['host'],'Content-Type':'application/json','Accept':'application/json',
        'X-WebGuard-Time':stamp,'X-WebGuard-Nonce':nonce,'X-WebGuard-Signature':signature})
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}))
    with opener.open(request,timeout=20) as response:
        result=json.loads(response.read(2*1024*1024))
    if result.get('ok') is not True:
        raise RuntimeError('Paneli nuk konfirmoi sync')
    return result


def ingest(db, budget=1000, probe=None):
    probe = probe or PROBE
    if not LOG.exists():
        return 0
    details=LOG.stat()
    identity=str(details.st_dev)+':'+str(details.st_ino)
    previous=meta(db,'log_identity','')
    offset=int(meta(db,'log_offset'))
    # Start at the tail on the first install; rotated logs start at zero.
    if previous != identity:
        offset=details.st_size if not previous else 0
    if offset > details.st_size:
        offset=0
    count=0
    with LOG.open('rb') as handle:
        handle.seek(offset)
        for _ in range(budget):
            position=handle.tell();raw=handle.readline()
            if not raw:
                break
            if not raw.endswith(b'\n'):
                handle.seek(position);break
            match=LINE.fullmatch(raw.decode(errors='replace').strip())
            if not match:
                continue
            address,stamp,method,path,status=match.groups()
            if int(status) not in (403,404) or not probe.search(path):
                continue
            try:
                ip=str(canonical_ip(address))
            except ValueError:
                continue
            try:
                occurred=int(datetime.datetime.strptime(stamp,'%d/%b/%Y:%H:%M:%S %z').timestamp())
            except ValueError:
                occurred=int(time.time())
            record('SUSPICIOUS_REQUEST',{'at':occurred,'ip':ip,'method':method[:12],'path':path[:512],'http_status':int(status)})
            count+=1
        put(db,'log_offset',handle.tell())
    put(db,'log_identity',identity)
    return count


def snapshot(settings):
    address=STATE/'state.sqlite3'
    if not address.exists():
        return [],True
    now=time.time();items={}
    with contextlib.closing(sqlite3.connect('file:'+str(address)+'?mode=ro',uri=True,timeout=2)) as db:
        for ip,jail,expires in db.execute('SELECT ip,jail,expires FROM leases WHERE zone=? AND expires>?',(settings['zone_id'],now)):
            row=items.setdefault(ip,{'ip':ip,'status':'pending','expires_at':int(expires),'edge_checked_at':None,'rules':[]})
            row['expires_at']=max(row['expires_at'],int(expires));row['rules'].append(jail)
        for ip,checked in db.execute('SELECT ip,checked FROM edge WHERE zone=? AND status="active"',(settings['zone_id'],)):
            row=items.setdefault(ip,{'ip':ip,'expires_at':None,'rules':[],'edge_checked_at':None})
            row['status']='active' if row['expires_at'] and row['expires_at'] > now else 'pending_unban'
            row['edge_checked_at']=int(checked)
    rows=list(items.values())
    return rows[:2000],len(rows)<=2000


def cpu_sample(db):
    parts=Path('/proc/stat').read_text().splitlines()[0].split()[1:]
    values=list(map(int,parts));total=sum(values[:8]);idle=values[3]+values[4]
    old=json.loads(meta(db,'cpu_sample','[0,0]'))
    put(db,'cpu_sample',json.dumps([total,idle]))
    return round(100*(1-(idle-old[1])/(total-old[0])),1) if old[0] and total>old[0] else None


def api_success():
    path=STATE/'state.sqlite3'
    if not path.exists():
        return 0
    with contextlib.closing(sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=2)) as db:
        value=db.execute('SELECT value FROM meta WHERE key="last_api_success"').fetchone()
        return float(value[0]) if value else 0


def run(arguments, timeout=180):
    result=subprocess.run(arguments,capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip()[-900:])
    return result.stdout.strip()[-900:]


def execute(command, db):
    if type(command.get('id')) is not int or not re.fullmatch('[a-f0-9]{32}',command.get('lease_token','')):
        raise ValueError('Command identity i pavlefshem')
    previous=db.execute('SELECT result FROM receipts WHERE id=?',(command['id'],)).fetchone()
    if previous:
        receipt=json.loads(previous[0]);receipt['lease_token']=command['lease_token']
        return receipt
    receipt={'id':command['id'],'lease_token':command['lease_token'],'ok':False,'message':''}
    payload=command.get('payload',{})
    try:
        if command.get('type') == 'apply_settings':
            settings=validate(payload['settings']);active=load()
            if settings['instance_id'] != active['instance_id']:
                raise ValueError('Identiteti i motorit nuk ndryshohet nga paneli')
            revision=payload['revision']
            if type(revision) is not int or revision <= 0:
                raise ValueError('Revision i pavlefshem')
            if revision < int(meta(db,'applied_revision')):
                raise ValueError('Settings te vjetra refuzohen')
            path=CONFIG/'settings.json';previous=path.read_bytes()
            atomic(path,settings)
            try:
                run(['/usr/local/sbin/rm-webguard','apply'])
            except Exception:
                # apply restores active.json/jails; restore the editable input too.
                temporary=path.with_name('.restore-'+uuid.uuid4().hex)
                temporary.write_bytes(previous);temporary.chmod(0o600);os.replace(temporary,path)
                raise
            put(db,'applied_revision',revision)
            receipt.update(ok=True,message='Settings revision '+str(revision)+' u aplikuan.')
        elif command.get('type') == 'unban':
            ip=str(canonical_ip(payload['ip']))
            run(['/usr/local/sbin/rm-webguard','unban',ip])
            receipt.update(ok=True,message='Zhbllokimi u kërkua në motor; statusi konfirmohet nga sync.')
        else:
            raise ValueError('Veprim jashte listes se lejuar')
    except Exception as error:
        receipt['message']=str(error)[:900] or 'Komanda deshtoi'
    db.execute('INSERT OR REPLACE INTO receipts VALUES (?,?)',(command['id'],json.dumps(receipt)));db.commit()
    return receipt


def cycle(check_only=False):
    settings=load()
    with contextlib.closing(database()) as db:
        ingest(db,probe=probe_regex(settings))
        events=[json.loads(row[0]) for row in db.execute('SELECT payload FROM outbox ORDER BY at,rowid LIMIT 200')]
        bans,complete=snapshot(settings)
        acks=json.loads(meta(db,'pending_acks','[]'))
        metrics={'cpu_percent':cpu_sample(db),'cpu_count':os.cpu_count(),'load1':round(os.getloadavg()[0],2),
                 'load5':round(os.getloadavg()[1],2),'queued_events':db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],
                 'dropped_events':int(meta(db,'dropped_events')),'token_ready':(CONFIG/'cloudflare.token').exists(),
                 'last_sync_error':meta(db,'last_sync_error','')[:900],'snapshot_complete':complete}
        metrics['api_last_success']=api_success()
        lock_level=lockdown_level(settings)
        metrics['lockdown']={'level':lock_level,'until':int((settings.get('lockdown') or {}).get('until',0))}
        # Keep the Apache file equal to the active state: removes an expired lockdown (at most once a minute).
        if (lock_level=='off')==LOCKFILE.exists() and time.time()-float(meta(db,'lockdown_sync_at'))>60:
            put(db,'lockdown_sync_at',time.time())
            try:
                run(['/usr/local/sbin/rm-webguard','lockdown-sync'])
            except Exception as error:
                put(db,'last_sync_error','lockdown: '+str(error)[:200])
        engine_error=json.loads(meta(db,'engine_error','{}'))
        metrics['engine_error']=engine_error.get('message','') if engine_error.get('at',0)>metrics['api_last_success'] else ''
        try:
            metrics['fail2ban_online']=subprocess.run(['fail2ban-client','ping'],capture_output=True,timeout=5).returncode==0
        except Exception:
            metrics['fail2ban_online']=False
        response=send({'instance_id':settings['instance_id'],'version':'1.1.0','mode':'DISABLED' if not settings['enabled'] else 'MONITOR' if settings['dry_run'] else 'ENFORCE',
                       'active_settings':settings,'applied_revision':int(meta(db,'applied_revision')),
                       'last_error':metrics['last_sync_error'] or metrics['engine_error'] or None,'metrics':metrics,'events':events,'check_only':check_only,
                       'bans':bans,'bans_complete':complete,'acks':acks})
        ids={item['id'] for item in events}
        for identifier in response.get('accepted_events',[]):
            if identifier in ids:
                db.execute('DELETE FROM outbox WHERE id=?',(identifier,))
        accepted=set(response.get('accepted_acks',[]))
        pending=[ack for ack in acks if str(ack['id'])+':'+ack['lease_token'] not in accepted]
        if response.get('initial_revision') == 1 and not int(meta(db,'applied_revision')):
            put(db,'applied_revision',1)
        # A connection check may report readiness but must never execute queued work.
        if not check_only:
            for command in response.get('commands',[]):
                pending.append(execute(command,db))
        put(db,'pending_acks',json.dumps(pending));put(db,'last_sync_error','')
    print('PANEL_SYNC=PASS',flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('check','run'));args=parser.parse_args()
    if os.geteuid()!=0:
        raise RuntimeError('Ekzekutoje me sudo')
    os.umask(0o077)
    while True:
        try:
            cycle(check_only=args.action=='check')
        except Exception as error:
            with contextlib.closing(database()) as db:
                put(db,'last_sync_error',str(error)[:900])
            print('PANEL_SYNC=ERROR '+str(error)[:900],flush=True)
            if args.action=='check':
                raise
        if args.action=='check':
            break
        time.sleep(5)


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print('ERROR: '+str(error)[:900],file=sys.stderr);sys.exit(1)
