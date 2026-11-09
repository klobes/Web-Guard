"""Bounded durable event queue; failures never interrupt the detector/action."""
import json
import sqlite3
import time
import uuid
from common import STATE


def database():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(STATE/'panel.sqlite3', timeout=2)
    db.execute('CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, at INTEGER, payload TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS receipts (id INTEGER PRIMARY KEY, result TEXT)')
    db.commit()
    return db


def record(event, fields=None):
    try:
        fields = fields or {}
        allowed = {k: fields[k] for k in ('expires_at','seconds','jail','message') if k in fields}
        item = {'id':uuid.uuid4().hex, 'at':int(fields.get('at',time.time())), 'event':str(event)[:40],
                'ip':fields.get('ip'), 'rule':fields.get('jail'),
                'method':fields.get('method'), 'path':fields.get('path'),
                'http_status':fields.get('http_status'), 'details':allowed}
        if item['path']:
            item['path'] = item['path'].split('?',1)[0][:512]
        if 'message' in allowed:
            allowed['message'] = str(allowed['message'])[:1000]
        with database() as db:
            db.execute('INSERT INTO outbox VALUES (?,?,?)',(item['id'],item['at'],json.dumps(item)))
            if event == 'ERROR':
                db.execute('INSERT OR REPLACE INTO metadata VALUES ("engine_error",?)',
                           (json.dumps({'at':item['at'],'message':allowed.get('message','Gabim ne motor')}),))
            # A disconnected panel cannot grow the queue without a limit.
            count = db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0]
            if count > 50000:
                extra = count - 50000
                db.execute('DELETE FROM outbox WHERE id IN (SELECT id FROM outbox ORDER BY at,rowid LIMIT ?)',(extra,))
                old = db.execute('SELECT value FROM metadata WHERE key="dropped_events"').fetchone()
                db.execute('INSERT OR REPLACE INTO metadata VALUES ("dropped_events",?)',(str((int(old[0]) if old else 0)+extra),))
    except Exception:
        # CPU protection must continue if telemetry storage is unavailable.
        pass
