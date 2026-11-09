"""Offline tests. No system commands, real firewall or Cloudflare writes."""
import configparser
import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import common
import cf_action as action
import setup
import telemetry


class FakeCloudflare:
    def __init__(self):
        self.rules = []
        self.serial = 0
        self.fail_create = False
        self.fail_after_create = False
        self.fail_delete = False
        self.fail_list = False
        self.created = []
        self.deleted = []

    def owned_rules(self):
        if self.fail_list:
            raise RuntimeError('simulated API unavailable')
        return [dict(rule) for rule in self.rules]

    def create(self, ip, expires):
        if self.fail_create:
            raise RuntimeError('simulated POST failure')
        self.serial += 1
        identifier = f'{self.serial:032x}'
        self.rules.append({'id':identifier,'mode':'block','notes':'owned',
                           'configuration':{'value':ip,'target':'ip' if ':' not in ip else 'ip6'}})
        self.created.append(ip)
        if self.fail_after_create:
            raise RuntimeError('simulated lost POST response')
        return identifier

    def delete(self, rule):
        if self.fail_delete:
            raise RuntimeError('simulated DELETE failure')
        self.deleted.append(rule['configuration']['value'])
        self.rules = [old for old in self.rules if old['id'] != rule['id']]


class WebGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state_patch = patch.object(action,'STATE',Path(self.temp.name))
        self.state_patch.start()
        self.telemetry_patch = patch.object(telemetry,"STATE",Path(self.temp.name))
        self.telemetry_patch.start()
        self.settings = json.loads((Path(__file__).parent/'settings.json').read_text())
        self.settings.update(instance_id='a'*32,zone_id='b'*32,dry_run=False)
        self.settings = common.validate(self.settings)
        self.db = action.connect()
        self.api = FakeCloudflare()
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()

    def tearDown(self):
        self.output.__exit__(None,None,None)
        self.db.close(); self.state_patch.stop(); self.telemetry_patch.stop(); self.temp.cleanup()

    def ban(self, ip='8.8.8.8', jail='rm-web-probes', duration=100, now=1000):
        action.ban(self.db,self.settings,ip,jail,now,duration,api=self.api,now=now)

    def test_default_is_monitor_and_flood_is_disabled(self):
        original=json.loads((Path(__file__).parent/'settings.json').read_text())
        self.assertTrue(original['dry_run'])
        self.assertFalse(original['jails']['rm-web-flood']['enabled'])

    def test_monitor_never_creates_remote_block(self):
        self.settings['dry_run']=True
        self.ban()
        self.assertEqual(self.api.created,[])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],0)

    def test_expiry_creates_then_deletes(self):
        self.ban()
        self.assertEqual(self.api.created,['8.8.8.8'])
        action.reconcile(self.db,self.settings,True,self.api,1099)
        self.assertEqual(self.api.deleted,[])
        action.reconcile(self.db,self.settings,True,self.api,1100)
        self.assertEqual(self.api.deleted,['8.8.8.8'])

    def test_two_jails_keep_longer_lease(self):
        self.ban(duration=100)
        self.ban(jail='rm-web-sensitive',duration=300,now=1001)
        action.unban(self.db,self.settings,'8.8.8.8','rm-web-probes',api=self.api,now=1101)
        action.reconcile(self.db,self.settings,True,self.api,1101)
        self.assertEqual(len(self.api.rules),1)
        action.reconcile(self.db,self.settings,True,self.api,1301)
        self.assertEqual(self.api.rules,[])

    def test_repeat_ban_is_idempotent(self):
        self.ban(); self.ban(now=1001)
        action.reconcile(self.db,self.settings,True,self.api,1006)
        self.assertEqual(len(self.api.created),1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],1)

    def test_expired_restore_does_not_reban(self):
        action.ban(self.db,self.settings,'8.8.8.8','rm-web-probes',1,100,api=self.api,now=1000)
        self.assertEqual(self.api.created,[])

    def test_retry_failed_post_preserves_desired_lease(self):
        self.api.fail_create=True
        with self.assertRaises(RuntimeError): self.ban()
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],1)
        self.api.fail_create=False
        action.reconcile(self.db,self.settings,True,self.api,1010)
        self.assertEqual(self.api.created,['8.8.8.8'])

    def test_post_response_lost_does_not_duplicate_rule(self):
        self.api.fail_after_create=True
        with self.assertRaises(RuntimeError): self.ban()
        self.api.fail_after_create=False
        action.reconcile(self.db,self.settings,True,self.api,1010)
        self.assertEqual(len(self.api.rules),1)
        self.assertEqual(len(self.api.created),1)

    def test_lost_post_is_cleaned_when_monitor_enabled(self):
        self.api.fail_after_create=True
        with self.assertRaises(RuntimeError): self.ban()
        self.settings['dry_run']=True
        self.api.fail_after_create=False
        action.reconcile(self.db,self.settings,True,self.api,1010)
        self.assertEqual(self.api.rules,[])

    def test_failed_unban_is_retried(self):
        self.ban(); self.api.fail_delete=True
        with self.assertRaises(RuntimeError):
            action.reconcile(self.db,self.settings,True,self.api,1101)
        self.assertEqual(len(self.api.rules),1)
        self.api.fail_delete=False
        action.reconcile(self.db,self.settings,True,self.api,1110)
        self.assertEqual(self.api.rules,[])

    def test_failed_list_does_not_delete_known_blocks(self):
        self.ban(); self.api.fail_list=True
        with self.assertRaises(RuntimeError):
            action.reconcile(self.db,self.settings,True,self.api,1101)
        self.assertEqual(len(self.api.rules),1)

    def test_whitelist_removes_active_owned_block(self):
        self.ban(); self.settings['ignoreip'].append('8.8.8.8/32')
        action.reconcile(self.db,self.settings,True,self.api,1010)
        self.assertEqual(self.api.rules,[])

    def test_private_and_documentation_addresses_are_not_banned(self):
        for ip in ('127.0.0.1','::1','10.1.254.7','198.51.100.23','2001:db8::23'):
            self.ban(ip)
        self.assertEqual(self.api.created,[])

    def test_ipv6_lease(self):
        self.ban('2606:4700:4700::1111')
        self.assertEqual(self.api.rules[0]['configuration']['target'],'ip6')

    def test_v4_mapped_ipv6_is_canonicalized(self):
        self.ban('::ffff:8.8.8.8')
        self.assertEqual(self.api.created,['8.8.8.8'])

    def test_manual_unban_clears_all_jail_leases(self):
        self.ban(); self.ban(jail='rm-web-sensitive',now=1001)
        action.unban(self.db,self.settings,'8.8.8.8',api=self.api,now=1010)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],0)
        self.assertEqual(self.api.rules,[])

    def test_disabled_configuration_clears_owned_blocks(self):
        self.ban(); self.settings['enabled']=False
        action.reconcile(self.db,self.settings,True,self.api,1010)
        self.assertEqual(self.api.rules,[])

    def test_changed_zone_does_not_touch_old_bans(self):
        self.ban(); self.settings['zone_id']='c'*32
        with self.assertRaises(RuntimeError):
            action.reconcile(self.db,self.settings,True,self.api,1010)
        self.assertEqual(len(self.api.rules),1)

    def test_change_budget_leaves_pending_work(self):
        self.settings['maximum_changes_per_sync']=1
        self.ban('8.8.8.8'); self.ban('8.8.4.4',now=1001)
        self.assertEqual(len(self.api.created),1)
        action.reconcile(self.db,self.settings,True,self.api,1010)
        self.assertEqual(len(self.api.created),2)

    def test_native_firewall_only_in_enforce_and_only_port_5555(self):
        rendered=setup.render_jails(self.settings)
        self.assertIn('port=5555,protocol=tcp',rendered)
        self.assertNotIn('port=22',rendered)
        self.settings['dry_run']=True
        self.assertNotIn('iptables-multiport',setup.render_jails(self.settings))

    def test_apache_scope_and_reversible_patch(self):
        module=setup.apache_module()
        original=b'<VirtualHost *:80>\n    DocumentRoot /var/www/html/nfsen\n</VirtualHost>\n<VirtualHost *:5555>\n    ServerName klobes.al\n    DocumentRoot /var/www/html/public_html\n</VirtualHost>\n'
        changed=module['patch_config'](original,'install')
        self.assertTrue(changed.startswith(original.split(b'<VirtualHost *:5555>')[0]))
        self.assertEqual(module['patch_config'](changed,'remove'),original)
        self.assertEqual(module['patch_config'](changed,'install'),changed)
        self.assertIn(b'RemoteIPTrustedProxy 127.0.0.1',module['GUARD_TEXT'])
        self.assertIn(b'CustomLog /var/log/rm-webguard/access.log',module['GUARD_TEXT'])

    def test_filters_match_probes_not_normal_missing_assets(self):
        fixtures=[('GET','/wp/wp-includes/js/wp-emoji.js',404),('POST','/blog/wp-admin/admin-ajax.php',403),
                  ('GET','/.env',403),('GET','/.git/config',403),('GET','/old/wp-config.php',404),
                  ('GET','/',200),('GET','/favicon.ico',404),('GET','/admin/radius-manager/system/realtime',200)]
        for name,expected in zip(common.JAILS,(2,3,1)):
            parser=configparser.ConfigParser(interpolation=None)
            parser.read(Path(__file__).parent/'filters'/(name+'.conf'))
            regex=re.compile(parser['Definition']['failregex'].replace('<HOST>',r'(?P<host>[0-9a-fA-F:.]+)'))
            for timestamp in ('[14/Oct/2026:12:00:00 +0200] ','[] ',' '):
                rows=[f'198.51.100.23 - - {timestamp}"{method} {uri} HTTP/1.1" {code}' for method,uri,code in fixtures]
                self.assertEqual(sum(bool(regex.search(row)) for row in rows),expected,(name,timestamp))

    def test_cloudflare_deletion_rejects_unowned_rule(self):
        api=object.__new__(action.Cloudflare); api.prefix='RM-WebGuard-v1:'+('a'*32)+':'
        with self.assertRaises(RuntimeError):
            api.delete({'id':'b'*32,'mode':'block','notes':'manual permanent block'})

    def test_invalid_settings_and_unlimited_bans_are_rejected(self):
        for key,bad in (('maximum_bantime_seconds',-1),('enabled','true'),('zone_id','unknown'),('instance_id','x')):
            altered=dict(self.settings); altered[key]=bad
            with self.assertRaises(ValueError): common.validate(altered)
        with self.assertRaises(ValueError): self.ban(duration=-1)


if __name__=='__main__':
    unittest.main(verbosity=2)
