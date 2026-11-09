"""Security/transport regression tests; no actual root service or remote API."""
import contextlib
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'engine'))
import common
import telemetry
spec=importlib.util.spec_from_file_location('bridge',ROOT/'agent/panel_bridge.py')
bridge=importlib.util.module_from_spec(spec);spec.loader.exec_module(bridge)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.path=Path(self.directory.name)
        self.state=self.path/'state';self.config=self.path/'config';self.config.mkdir()
        self.settings=json.loads((ROOT/'engine/settings.json').read_text())
        self.settings.update(instance_id='a'*32,zone_id='b'*32)
        (self.config/'settings.json').write_text(json.dumps(self.settings))
        (self.config/'active.json').write_text(json.dumps(self.settings))
        self.patches=[patch.object(bridge,'STATE',self.state),patch.object(bridge,'CONFIG',self.config),
                      patch.object(common,'CONFIG',self.config),patch.object(telemetry,'STATE',self.state),
                      patch.object(bridge,'LOG',self.path/'access.log')]
        for item in self.patches:item.start()
        self.db=telemetry.database()

    def tearDown(self):
        self.db.close()
        for item in reversed(self.patches):item.stop()
        self.directory.cleanup()

    def command(self,kind='unban',payload=None):
        return {'id':7,'lease_token':'c'*32,'type':kind,'payload':payload or {'ip':'8.8.8.8'}}

    def test_replayed_command_changes_receipt_not_execution(self):
        with patch.object(bridge,'run',return_value='OK') as runner:
            first=bridge.execute(self.command(),self.db)
            second=bridge.execute({**self.command(),'lease_token':'d'*32},self.db)
        self.assertTrue(first['ok']);self.assertEqual(runner.call_count,1)
        self.assertEqual(second['lease_token'],'d'*32)

    def test_ip_cannot_inject_shell(self):
        with patch.object(bridge,'run') as runner:
            result=bridge.execute(self.command(payload={'ip':'8.8.8.8; rm -rf /'}),self.db)
        self.assertFalse(result['ok']);runner.assert_not_called()

    def test_arbitrary_root_command_is_rejected(self):
        with patch.object(bridge,'run') as runner:
            result=bridge.execute(self.command('shell',{'command':'touch /root/test'}),self.db)
        self.assertFalse(result['ok']);runner.assert_not_called()

    def test_failed_settings_restore_editable_config(self):
        before=(self.config/'settings.json').read_bytes()
        desired={**self.settings,'dry_run':False}
        with patch.object(bridge,'run',side_effect=RuntimeError('API write denied')):
            result=bridge.execute(self.command('apply_settings',{'revision':2,'settings':desired}),self.db)
        self.assertFalse(result['ok']);self.assertEqual((self.config/'settings.json').read_bytes(),before)
        self.assertEqual(bridge.meta(self.db,'applied_revision'),'0')

    def test_successful_settings_record_revision(self):
        with patch.object(bridge,'run',return_value='PASS'):
            result=bridge.execute(self.command('apply_settings',{'revision':2,'settings':self.settings}),self.db)
        self.assertTrue(result['ok']);self.assertEqual(bridge.meta(self.db,'applied_revision'),'2')

    def test_older_revision_is_rejected(self):
        bridge.put(self.db,'applied_revision',4)
        with patch.object(bridge,'run') as runner:
            result=bridge.execute(self.command('apply_settings',{'revision':2,'settings':self.settings}),self.db)
        self.assertFalse(result['ok']);runner.assert_not_called()

    def test_instance_cannot_be_replaced_from_panel(self):
        desired={**self.settings,'instance_id':'f'*32}
        with patch.object(bridge,'run') as runner:
            result=bridge.execute(self.command('apply_settings',{'revision':2,'settings':desired}),self.db)
        self.assertFalse(result['ok']);runner.assert_not_called()

    def test_sensitive_request_logged_normal_missing_asset_ignored(self):
        bridge.LOG.write_text('')
        bridge.ingest(self.db)
        with bridge.LOG.open('a') as handle:
            handle.write('8.8.8.8 - - [14/Oct/2026:14:00:00 +0000] "GET /.env HTTP/1.1" 403\n')
            handle.write('8.8.8.8 - - [14/Oct/2026:14:00:00 +0000] "GET /favicon.ico HTTP/1.1" 404\n')
        self.assertEqual(bridge.ingest(self.db),1)
        self.assertEqual(bridge.ingest(self.db),0)
        events=[json.loads(row[0]) for row in self.db.execute('SELECT payload FROM outbox')]
        self.assertEqual(len(events),1);self.assertEqual(events[0]['path'],'/.env')
        self.assertEqual(events[0]['at'],1791986400)

    def test_rotation_restarts_at_start(self):
        bridge.LOG.write_text('');bridge.ingest(self.db)
        bridge.LOG.rename(bridge.LOG.with_suffix('.old'))
        bridge.LOG.write_text('8.8.8.8 - - [14/Oct/2026:14:00:00 +0000] "GET /.git/config HTTP/1.1" 403\n')
        self.assertEqual(bridge.ingest(self.db),1)

    def test_expired_edge_is_pending_unban(self):
        import cf_action
        with patch.object(cf_action,'STATE',self.state):
            db=cf_action.connect()
            db.execute('INSERT INTO edge VALUES (?,?,?,?,?)',('b'*32,'8.8.8.8','d'*32,'active',time.time()))
            db.commit();db.close()
        rows,complete=bridge.snapshot(self.settings)
        self.assertTrue(complete);self.assertEqual(rows[0]['status'],'pending_unban')

    def test_telemetry_failure_does_not_interrupt_action(self):
        with patch.object(telemetry,'database',side_effect=OSError('disk full')):
            telemetry.record('BAN_EDGE',{'ip':'8.8.8.8'})

    def test_query_strings_are_removed_from_telemetry(self):
        telemetry.record('SUSPICIOUS_REQUEST',{'ip':'8.8.8.8','path':'/.env?token=not-stored'})
        row=self.db.execute('SELECT payload FROM outbox').fetchone()
        self.assertNotIn('not-stored',row[0])

    def test_redirect_or_external_destination_is_rejected(self):
        options=self.path/'bridge.json';options.write_text(json.dumps({'url':'https://example.com','host':'klobes.al'}))
        with patch.object(bridge,'BRIDGE',options):
            with self.assertRaises(ValueError):bridge.send({})

    def test_manual_unban_skips_disabled_jail(self):
        import setup
        calls=[]
        def fake(args, **options):
            calls.append(args)
            if args[1]=='get' and args[2]=='rm-web-flood':
                raise RuntimeError('jail not active')
            return '8.8.8.8 1.1.1.1' if args[1]=='get' else '1'
        with patch.object(setup,'run',side_effect=fake):
            setup.detector_unban('8.8.8.8')
        mutations=[args for args in calls if args[1]=='set']
        self.assertEqual(len(mutations),2)
        self.assertTrue(all(args[-1]=='8.8.8.8' and args[2]!='rm-web-flood' for args in mutations))

    def test_new_allowlist_removes_only_matching_detector_tickets(self):
        import setup
        desired={**self.settings,'ignoreip':['8.8.8.8/32']}
        with patch.object(setup,'run',side_effect=lambda args,**kwargs:'8.8.8.8 1.1.1.1' if args[1]=='get' else '1') as runner:
            setup.detector_unban(ignore_settings=desired)
        mutations=[call.args[0] for call in runner.call_args_list if call.args[0][1]=='set']
        self.assertEqual(len(mutations),3)
        self.assertTrue(all(args[-1]=='8.8.8.8' for args in mutations))


if __name__=='__main__':
    unittest.main(verbosity=2)
