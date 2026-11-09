"""Offline tests for the panel-managed scan paths. No Fail2ban, Apache or Cloudflare needed.

Run from the engine folder:  python3 -m unittest tests_paths -v
"""
import json
from pathlib import Path
import re
import unittest
import common
import setup

HERE = Path(__file__).resolve().parent


def to_regex(line):
    return re.compile(line.replace('<HOST>', r'(?P<host>\S+)'))


def log_line(uri, status=404, method='GET'):
    return '198.51.100.23 - - [29/Oct/2026:19:25:56 +0100] "%s %s HTTP/1.1" %d' % (method, uri, status)


def matches(filter_text, line):
    """True when any failregex line of a rendered filter matches the log line."""
    rules = [part.strip() for part in re.split(r'\n\s*', filter_text.split('failregex =', 1)[1].split('ignoreregex =')[0])]
    return any(to_regex(rule).search(line) for rule in rules if rule)


class PathTests(unittest.TestCase):
    def settings(self, **paths):
        value = json.loads((HERE / 'settings.json').read_text())
        value.update(instance_id='a' * 32, zone_id='b' * 32)
        if paths:
            value['paths'] = paths
        return value

    def base(self, name='rm-web-probes'):
        return (HERE / 'filters' / (name + '.conf')).read_text()

    def test_settings_without_paths_are_unchanged(self):
        self.assertNotIn('paths', common.validate(self.settings()))

    def test_valid_paths_are_lowercased_and_normalised(self):
        result = common.validate(self.settings(**{
            'rm-web-probes': [{'type': 'segment', 'value': 'PhpMyAdmin'}, {'type': 'extension', 'value': 'ASPX'}]}))
        self.assertEqual(result['paths']['rm-web-probes'],
                         [{'type': 'segment', 'value': 'phpmyadmin'}, {'type': 'extension', 'value': 'aspx'}])
        self.assertEqual(result['paths']['rm-web-sensitive'], [])

    def test_rejected_entries(self):
        bad = [
            {'type': 'segment', 'value': 'admin'},                 # reserved
            {'type': 'segment', 'value': 'Admin/users'},           # reserved first part
            {'type': 'segment', 'value': 'a b'},
            {'type': 'segment', 'value': '../etc'},
            {'type': 'segment', 'value': '.'},
            {'type': 'segment', 'value': 'a/b/c/d/e'},             # too many parts
            {'type': 'segment', 'value': 'x' * 65},
            {'type': 'segment', 'value': 'a(b|c)'},                # regex syntax
            {'type': 'segment', 'value': 'a%20b'},
            {'type': 'segment', 'value': 'a<HOST>'},
            {'type': 'extension', 'value': 'php'},                 # reserved
            {'type': 'extension', 'value': 'a.b'},
            {'type': 'extension', 'value': 'x' * 11},
            {'type': 'directory', 'value': 'x'},
            {'type': 'segment', 'value': 5},
            {'type': 'segment', 'value': 'phpmyadmin', 'note': 'extra key'},
            {'value': 'phpmyadmin'},
        ]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                common.validate(self.settings(**{'rm-web-probes': [item]}))

    def test_structure_errors(self):
        for paths in ({'rm-web-flood': []}, {'rm-web-probes': 'phpmyadmin'}):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                common.validate(self.settings(**paths))
        with self.assertRaises(ValueError):
            common.validate(dict(self.settings(), paths=[]))

    def test_duplicates_and_limit(self):
        item = {'type': 'segment', 'value': 'phpmyadmin'}
        with self.assertRaises(ValueError):
            common.validate(self.settings(**{'rm-web-probes': [item], 'rm-web-sensitive': [item]}))
        many = [{'type': 'segment', 'value': 'p%d' % number} for number in range(common.PATH_LIMIT + 1)]
        with self.assertRaises(ValueError):
            common.validate(self.settings(**{'rm-web-probes': many}))
        common.validate(self.settings(**{'rm-web-probes': many[:common.PATH_LIMIT]}))

    def test_filter_unchanged_without_custom_paths(self):
        base = self.base()
        self.assertEqual(common.render_filter(base, []), base)

    def test_segment_filter_semantics(self):
        items = [{'type': 'segment', 'value': 'phpmyadmin'}, {'type': 'segment', 'value': '.svn'},
                 {'type': 'segment', 'value': 'wls-wsat/coordinatorport'}]
        text = common.render_filter(self.base(), items)
        self.assertEqual(text.count('ignoreregex ='), 1)
        for uri in ('/phpmyadmin', '/x/phpmyadmin/index.php', '/.svn/entries', '/wls-wsat/coordinatorport',
                    '/PHPMyAdmin/'):
            self.assertTrue(matches(text, log_line(uri)), uri)
            self.assertTrue(matches(text, log_line(uri, 403)), uri)
        for uri in ('/phpmyadmin2', '/myphpmyadmin', '/', '/admin', '/svn', '/wls-wsat'):
            self.assertFalse(matches(text, log_line(uri)), uri)
        self.assertFalse(matches(text, log_line('/phpmyadmin', 200)))
        self.assertTrue(matches(text, log_line('/phpmyadmin', 403, 'POST')))

    def test_extension_filter_semantics(self):
        text = common.render_filter(self.base(), [{'type': 'extension', 'value': 'aspx'},
                                                  {'type': 'extension', 'value': 'jsp'}])
        for uri in ('/a/b/test.aspx', '/login.jsp', '/TEST.ASPX'):
            self.assertTrue(matches(text, log_line(uri)), uri)
        for uri in ('/aspx', '/test.aspxx', '/test.php', '/'):
            self.assertFalse(matches(text, log_line(uri)), uri)

    def test_built_in_rules_still_match(self):
        text = common.render_filter(self.base('rm-web-sensitive'), [{'type': 'segment', 'value': 'id_rsa'}])
        self.assertTrue(matches(text, log_line('/.env', 403)))
        self.assertTrue(matches(text, log_line('/id_rsa')))

    def test_legitimate_urls_never_match_typical_lists(self):
        items = [{'type': 'segment', 'value': value} for value in
                 ('phpmyadmin', 'adminer', 'cgi-bin', 'boaform', 'hnap1', 'actuator', 'phpunit', '.svn', '.aws',
                  'id_rsa', 'wlwmanifest.xml', 'wp-json')] + [
                 {'type': 'extension', 'value': value} for value in ('asp', 'aspx', 'jsp', 'cgi', 'sql', 'bak')]
        text = common.render_filter(self.base(), items)
        for uri in setup.LEGIT_URIS:
            self.assertFalse(matches(text, log_line(uri)), uri)

    def test_probe_regex_covers_built_in_and_custom(self):
        settings = common.validate(self.settings(**{
            'rm-web-probes': [{'type': 'segment', 'value': 'phpmyadmin'}],
            'rm-web-sensitive': [{'type': 'extension', 'value': 'bak'}]}))
        probe = common.probe_regex(settings)
        for uri in ('/.env', '/wp-login.php', '/phpmyadmin/', '/x/PhpMyAdmin', '/db/dump.bak'):
            self.assertTrue(probe.search(uri), uri)
        for uri in ('/', '/admin', '/phpmyadmin2', '/dump.bakx'):
            self.assertFalse(probe.search(uri), uri)
        self.assertFalse(common.probe_regex(self.settings()).search('/phpmyadmin'))

    def test_every_rendered_filter_line_compiles(self):
        items = [{'type': 'segment', 'value': 'a.b-c_d~e/f'}, {'type': 'extension', 'value': 'x1'}]
        for line in common.filter_lines(items):
            to_regex(line)

    def test_bridge_service_can_write_every_file_apply_touches(self):
        unit = HERE.parent / 'agent' / 'rm-webguard-panel.service'
        if not unit.exists():
            self.skipTest('service unit not next to the engine')
        writable = re.search(r'^ReadWritePaths=(.*)$', unit.read_text(), re.M).group(1).split()
        writable = [path.lstrip('-') for path in writable]
        for directory in (setup.FILTER_DIR, setup.JAILFILE.parent, setup.CONFIG, setup.LOG.parent, setup.LOCKFILE.parent):
            target = directory.as_posix()
            self.assertTrue(any(target == path or target.startswith(path.rstrip('/') + '/') for path in writable),
                            target + ' is read-only for the bridge service')

    def test_php_and_engine_reserved_lists_match(self):
        source = HERE.parent / 'web-guard' / 'src' / 'Services' / 'SettingsService.php'
        if not source.exists():
            self.skipTest('plugin source not next to the engine')
        text = source.read_text(encoding='utf-8')
        for constant, expected in (('PROTECTED_SEGMENTS', common.PROTECTED_SEGMENTS),
                                   ('PROTECTED_EXTENSIONS', common.PROTECTED_EXTENSIONS)):
            block = re.search(constant + r' = \[(.*?)\];', text, re.S).group(1)
            self.assertEqual(set(re.findall(r"'([^']+)'", block)), set(expected), constant)
        self.assertIn('PATH_LIMIT = %d' % common.PATH_LIMIT, text)


class CustomGuardTests(unittest.TestCase):
    def settings(self, **paths):
        value = json.loads((HERE / 'settings.json').read_text())
        value.update(instance_id='a' * 32, zone_id='b' * 32)
        if paths:
            value['paths'] = paths
        return common.validate(value)

    def conditions(self, text):
        return [re.compile(m.group(1), re.I) for m in re.finditer(r'RewriteCond %\{REQUEST_URI\} "(.*)" \[NC', text)]

    def test_nothing_without_paths(self):
        self.assertIsNone(common.render_custom_guard(self.settings()))
        self.assertIsNone(common.render_custom_guard(self.settings(**{'rm-web-probes': []})))

    def test_structure(self):
        text = common.render_custom_guard(self.settings(**{
            'rm-web-probes': [{'type': 'segment', 'value': 'phpmyadmin'}],
            'rm-web-sensitive': [{'type': 'extension', 'value': 'bak'}]}))
        self.assertTrue(text.startswith(common.CUSTOM_MARK))
        self.assertEqual(text.count('RewriteCond'), 2)
        self.assertIn('[NC,OR]', text)
        self.assertTrue(text.rstrip().endswith('RewriteRule ^ - [F,L]'))
        self.assertEqual(text.count('[F,L]'), 1)

    def test_semantics_match_the_filter(self):
        text = common.render_custom_guard(self.settings(**{
            'rm-web-probes': [{'type': 'segment', 'value': 'phpmyadmin'}, {'type': 'segment', 'value': '.svn'},
                              {'type': 'segment', 'value': 'wls-wsat/coordinatorport'}, {'type': 'extension', 'value': 'aspx'}]}))
        patterns = self.conditions(text)
        hit = lambda uri: any(p.search(uri) for p in patterns)
        for uri in ('/phpmyadmin', '/x/PhpMyAdmin/index.php', '/.svn/entries', '/wls-wsat/coordinatorport', '/a/b/test.aspx', '/TEST.ASPX'):
            self.assertTrue(hit(uri), uri)
        for uri in ('/', '/phpmyadmin2', '/myphpmyadmin', '/svn', '/aspx', '/test.aspxx'):
            self.assertFalse(hit(uri), uri)

    def test_legitimate_urls_are_never_refused(self):
        items = [{'type': 'segment', 'value': v} for v in ('phpmyadmin', 'adminer', 'cgi-bin', 'boaform', 'hnap1', 'actuator', '.svn', 'id_rsa', 'wp-json')] + [
            {'type': 'extension', 'value': v} for v in ('asp', 'aspx', 'jsp', 'cgi', 'sql', 'bak')]
        text = common.render_custom_guard(self.settings(**{'rm-web-probes': items}))
        patterns = self.conditions(text)
        for uri in setup.LEGIT_URIS:
            self.assertFalse(any(p.search(uri) for p in patterns), uri)

    def test_special_characters_are_escaped(self):
        text = common.render_custom_guard(self.settings(**{'rm-web-probes': [{'type': 'segment', 'value': 'a.b-c_d~e/f'}]}))
        self.assertIn(r'a\.b\-c_d', text)
        self.assertIn('e/f)', text)

    def test_vhost_block_has_both_includes(self):
        block = setup.vhost_block()
        self.assertIn(str(setup.CUSTOMFILE), block)
        self.assertIn(str(setup.LOCKFILE), block)
        self.assertTrue(block.startswith('    ' + setup.LOCK_BEGIN))
        self.assertTrue(block.rstrip().endswith(setup.LOCK_END))


class LockdownTests(unittest.TestCase):
    NOW = 1_000_000

    def settings(self, level='full', until=None, ignoreip=('203.0.113.0/24',)):
        value = json.loads((HERE / 'settings.json').read_text())
        value.update(instance_id='a' * 32, zone_id='b' * 32, ignoreip=list(ignoreip),
                     lockdown={'level': level, 'until': self.NOW + 600 if until is None else until})
        return common.validate(value)

    def test_absent_or_off_renders_nothing(self):
        value = json.loads((HERE / 'settings.json').read_text())
        value.update(instance_id='a' * 32, zone_id='b' * 32)
        self.assertIsNone(common.render_lockdown(common.validate(value), self.NOW))
        self.assertIsNone(common.render_lockdown(self.settings('off', 0), self.NOW))

    def test_expired_lockdown_renders_nothing(self):
        self.assertIsNone(common.render_lockdown(self.settings('full', self.NOW - 1), self.NOW))
        self.assertEqual(common.lockdown_level(self.settings('admin', self.NOW + 5), self.NOW), 'admin')

    def test_lockdown_page_is_safe_single_line_html(self):
        page = common.LOCKDOWN_PAGE
        self.assertTrue(page.isascii())
        self.assertFalse(set('"\\%$\n') & set(page))
        self.assertIn('<h1>', page)
        self.assertIn('Temporarily unavailable', page)
        text = common.render_lockdown(self.settings('full'), self.NOW)
        line = [row for row in text.splitlines() if 'ErrorDocument 403' in row][0]
        self.assertEqual(line.strip(), 'ErrorDocument 403 "' + page + '"')
        self.assertLess(len(line), 8000)

    def test_blocked_page_has_home_button_and_is_in_custom_guard(self):
        page = common.BLOCKED_PAGE
        self.assertIn("href='/'", page)
        self.assertFalse(set('"\\%$\n') & set(page))
        settings = common.validate(dict(self.settings('off', 0), paths={
            'rm-web-sensitive': [{'type': 'segment', 'value': 'web.config'}]}))
        text = common.render_custom_guard(settings)
        self.assertIn('ErrorDocument 403 "' + page + '"', text)
        self.assertIn('RewriteRule ^ - [F,L]', text)

    def test_full_and_admin_scope(self):
        full = common.render_lockdown(self.settings('full'), self.NOW)
        admin = common.render_lockdown(self.settings('admin'), self.NOW)
        self.assertIn('<Location "/">', full)
        self.assertIn('<LocationMatch "^/admin(/|$)">', admin)
        for text in (full, admin):
            self.assertTrue(text.startswith(common.LOCKDOWN_MARK))
            self.assertIn('Require ip 127.0.0.1', text)
            self.assertIn('Require ip ::1', text)
            self.assertIn('Require ip 203.0.113.0/24', text)
            self.assertNotIn('<If', text)

    def test_never_without_allowlist(self):
        with self.assertRaises(ValueError):
            self.settings('full', ignoreip=())

    def test_rejects_bad_values(self):
        for lock in ({'level': 'total', 'until': self.NOW}, {'level': 'full'}, {'level': 'full', 'until': 'x'},
                     {'level': 'full', 'until': 0}, {'level': 'full', 'until': True}, {'level': 'full', 'until': 1, 'x': 1}, []):
            value = json.loads((HERE / 'settings.json').read_text())
            value.update(instance_id='a' * 32, zone_id='b' * 32, ignoreip=['203.0.113.0/24'], lockdown=lock)
            with self.subTest(lock=lock), self.assertRaises(ValueError):
                common.validate(value)

    def test_allowlist_is_canonical_cidr_only(self):
        text = common.render_lockdown(self.settings('full', ignoreip=('203.0.113.7',)), self.NOW)
        self.assertIn('Require ip 203.0.113.7/32', text)


class I18nTests(unittest.TestCase):
    """English and Albanian panel texts: same keys, same placeholders, every key used by the plugin exists."""
    PLUGIN = HERE.parent / 'web-guard'

    def setUp(self):
        if not self.PLUGIN.exists():
            self.skipTest('plugin source not next to the engine')

    def load(self, locale):
        text = (self.PLUGIN / 'resources' / 'lang' / locale / 'web-guard.php').read_text(encoding='utf-8')
        return dict(re.findall(r"^    '([a-z0-9_]+)' => '((?:[^'\\]|\\.)*)',$", text, re.M))

    def test_same_keys_in_both_languages(self):
        sq, en = self.load('sq'), self.load('en')
        self.assertGreater(len(sq), 200)
        self.assertEqual(set(sq), set(en))

    def test_same_placeholders_and_not_empty(self):
        sq, en = self.load('sq'), self.load('en')
        for key in sq:
            self.assertTrue(sq[key].strip() and en[key].strip(), key)
            self.assertEqual(set(re.findall(r':([a-z]+)\b', sq[key])), set(re.findall(r':([a-z]+)\b', en[key])), key)

    def test_every_used_key_is_defined(self):
        defined = set(self.load('en'))
        used = set()
        for path in self.PLUGIN.rglob('*.php'):
            if '/lang/' in path.as_posix():
                continue
            text = path.read_text(encoding='utf-8')
            used |= set(re.findall(r"(?:\$t\(|SettingsService::t\(|self::t\()'([a-z0-9_]+)'", text))
            used |= set(re.findall(r"web-guard::web-guard\.([a-z0-9_]+)'", text))
        used -= {'key', 'nav_'}
        used |= {'nav_' + name for name in ('dashboard', 'incidents', 'bans', 'allowlist', 'paths', 'settings', 'audit', 'setup')}
        self.assertEqual(sorted(used - defined), [])

    def test_views_have_no_hardcoded_albanian(self):
        for path in (self.PLUGIN / 'resources' / 'views').glob('*.php'):
            self.assertIsNone(re.search('[ëçËÇ]', path.read_text(encoding='utf-8')), path.name)


if __name__ == '__main__':
    unittest.main()
