import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock
from companion import client_address, probe_guard
# The disposable Nginx harness, run from this folder as `python3 -m unittest discover -s tests` does.
from test_client_address import NGINX, free_port, start_nginx

ROOT = Path(__file__).resolve().parents[1]
FAIL2BAN_REGEX = shutil.which('fail2ban-regex')

PROBES = ['/.env', '/.ENV', '/.env.production', '/.git/config', '/.aws/config', '/.kube/config', '/.docker/config.json',
          '/.terraform/terraform.tfstate', '/.well-knownold/', '/wp-config.php', '/wp-config.php.bak', '/wp-config.php~',
          '/wp-config.txt', '/wp-config-sample.php', '/wp-configs.php', '/blog/wp-config.php.bak', '/wp-content-x/.env', '/backup.sql', '/Backup.SQL', '/db.sqlite', '/data.sqlite3',
          '/site.bak', '/index.php.old', '/index.php.orig', '/x.backup', '/x.save', '/x.sav', '/.x.swp', '/x.swo',
          '/db.dump', '/config.yaml', '/config.yml', '/docker-compose.yml', '/docker-compose.yaml', '/deployment.yml',
          '/deployment.yaml', '/terraform.tfvars', '/terraform.tfstate', '/settings.py', '/deploy.sh', '/server.key',
          '/server.pem', '/id_rsa.ppk', '/php.ini', '/nginx.conf', '/app.cfg', '/netlify.toml', '/debug.log',
          '/app/.env', '/kubeconfig', '/railway.json', '/composer.json', '/composer.lock',
          '/package.json', '/package-lock.json']
ARCHIVES = ['/backup.zip', '/shop.example.com.rar', '/site.tar.gz', '/x.7z', '/x.tar', '/x.tgz', '/x.gz', '/x.bz2',
            '/x.xz', '/x.zst', '/BACKUP.ZIP']
# The owner's never list, generic pages, WooCommerce, media and names outside the known list.
NEVER = ['/', '/wp-json/wp/v2/posts', '/wp-json/shop/v1/config.yml', '/wp-json', '/wp-admin/', '/wp-admin/admin-ajax.php',
         '/wp-login.php', '/wp-cron.php', '/xmlrpc.php', '/robots.txt', '/llms.txt', '/sitemap.xml',
         '/sitemap_index.xml', '/wp-sitemap-posts-post-1.xml', '/sitemap.xml.gz', '/product-sitemap.xml.gz',
         '/.well-known/acme-challenge/token', '/.well-known/security.txt', '/.well-known/apple-app-site-association',
         '/wp-content/uploads/2026/01/photo.jpg', '/wp-content/uploads/report.zip', '/wp-content/uploads/talk.key',
         '/wp-content/uploads/config.yml', '/wp-content/uploads/woocommerce_uploads/file.zip', '/cart/', '/checkout/',
         '/my-account/', '/wc-api/v3/orders', '/wc-auth/v1/authorize', '/product/blue-chair/', '/shop/', '/feed/',
         '/some-missing-page/', '/graphql', '/config/aws.json', '/password/reset', '/favicon.ico', '/brochure.pdf',
         '/model.glb', '/scene.usdz', '/wp-content/plugins/shop/readme.txt', '/wp-content/themes/shop/style.css',
         '/wp-content/plugins/shop/build/app.js.map', '/sub/backup.zip', '/wp-content/backup.zip', '/alfa.php',
         '/sub/railway.json', '/sub/composer.json', '/ads.txt', '/manifest.json', '/sw.js', '/apple-touch-icon.png',
         '/.well-known/apple-developer-merchantid-domain-association', '/.well-known/assetlinks.json',
         '/wc-api/WC_Gateway_Paypal/', '/search/backup.sql/', '/feed/atom/', '/WP-ADMIN/admin-ajax.php',
         # A blog post about wp-config: WordPress slugs never contain a dot.
         '/wp-config-explained/', '/wp-config-explained', '/blog/wp-config-guide',
         # Files plugins and themes ship, at any depth; a page may load any of them.
         '/wp-content/plugins/shop/bin/install.sh', '/wp-content/plugins/shop/config.yml', '/wp-content/plugins/shop/app.conf',
         '/wp-content/plugins/shop/tool.py', '/wp-content/plugins/shop/settings.cfg', '/wp-content/plugins/shop/public.key',
         '/wp-content/plugins/shop/vendor/cacert.pem', '/wp-content/themes/shop/theme.toml', '/wp-content/themes/shop/x.dump',
         '/wp-content/plugins/wp-config-editor/js/wp-config.js', '/wp-includes/certificates/ca-bundle.crt',
         '/blog/wp-content/themes/shop/style.css', '/blog/wp-content/plugins/shop/config.yml', '/wp-content/cache/x.html.gz']
# Files the safeguards always hid where WordPress works: still a 404, never counted as probes.
HIDDEN = ['/wp-content/uploads/.htaccess', '/wp-content/uploads/2026/01/.env', '/wp-content/uploads/backup.sql',
          '/wp-content/uploads/wc-logs/fatal.log', '/wp-admin/.htaccess', '/wp-admin/install.log', '/wp-json/.env', '/wp-content/uploads/x.sqlite3',
          '/wp-content/debug.log', '/wp-content/mysql.sql', '/wp-content/themes/shop/.git/HEAD', '/wp-includes/.htaccess',
          # Broken asset paths a page asked for, from a real site's log: hidden, never counted.
          '/wp-content/plugins/gravityforms/assets/js/dist/.min.js', '/wp-content/plugins/elementor-pro/assets/js/.json',
          '/blog/wp-content/uploads/.env', '/shop2/wp-includes/install.log']


class ClassificationTests(unittest.TestCase):
    def test_probe_archive_hidden_and_never_classes(self):
        for kind, paths in (('probe', PROBES), ('archive', ARCHIVES), ('', NEVER), ('hidden', HIDDEN)):
            for path in paths:
                with self.subTest(path=path):
                    self.assertEqual(probe_guard.classify(path), kind)

    def test_request_targets_are_normalized_like_nginx(self):
        for target, path in (('/?rest_route=/wp/v2/posts', '/'), ('//wp-config.php?x=1', '/wp-config.php'),
                             ('/%2Eenv', '/.env'), ('/a/../.env', '/.env'), ('/shop/', '/shop/'), ('/x/./y', '/x/y')):
            with self.subTest(target=target):
                self.assertEqual(probe_guard.normalized(target), path)
        self.assertIsNone(probe_guard.normalized('*'))

    def test_one_map_carries_every_rule_in_order(self):
        text = probe_guard.http_configuration()
        entries = [line.strip() for line in text.split('map $uri $companion_probe {', 1)[1].split('}', 1)[0].strip().splitlines()]
        self.assertEqual(entries[0], 'default "";')
        self.assertEqual(entries[1:], [f'"~*{pattern}" {kind or chr(34) * 2};' for kind, pattern in probe_guard.RULES])
        self.assertIn(f'include {probe_guard.BAN_MAP};', text)
        # Never 444: behind Cloudflare a closed connection becomes a 520.
        self.assertNotIn('444', text + probe_guard.site_include())

    def test_site_include_keeps_the_unrelated_safeguards_and_hides_private_downloads(self):
        include = probe_guard.site_include()
        for kept in ('disable_symlinks if_not_owner from=$document_root;', 'ai1wm-backups', '(php[0-9]?|phtml|phar)',
                     'location ^~ /wp-content/uploads/woocommerce_uploads/ { internal; }', 'return 403;', 'return 404;'):
            self.assertIn(kept, include)
        # The ban comes first, then the probe answer; the folded-in deny rules are gone.
        self.assertLess(include.index('return 403;'), include.index('return 404;'))
        self.assertNotIn('location = /wp-config.php', include)
        for media in ('pdf', 'glb', 'usdz'):
            self.assertNotIn(media, include)

    def test_never_banned_addresses(self):
        cloudflare = client_address.cloudflare_ranges()
        local = {ipaddress.ip_address('203.0.113.10')}
        allowed = probe_guard.allowlist(['198.51.100.0/24', '2001:db8::5'])
        for address in ('127.0.0.1', '127.8.8.8', '::1', '::ffff:127.0.0.1', '203.0.113.10', '173.245.48.7',
                        '2400:cb00::1', '198.51.100.77', '2001:db8::5'):
            with self.subTest(address=address):
                self.assertTrue(probe_guard.never_banned(address, allowed, local, cloudflare))
        for address in ('192.0.2.44', '2001:db8::6', '203.0.113.11'):
            self.assertFalse(probe_guard.never_banned(address, allowed, local, cloudflare))
        self.assertEqual(probe_guard.enforced(['192.0.2.44', '173.245.48.7', '127.0.0.1'], allowed, local, cloudflare),
                         ['192.0.2.44'])
        for wide in ('0.0.0.0/0', '10.0.0.0/7', '::/0', 'not-an-address'):
            with self.subTest(wide=wide), self.assertRaises(ValueError):
                probe_guard.allowlist([wide])

    def test_jail_counts_three_probes_an_hour_and_never_bans_cloudflare(self):
        jail = probe_guard.jail_configuration(['198.51.100.0/24'])
        for line in ('[companion-probes]', 'backend = auto', 'maxretry = 3', 'findtime = 1h', 'bantime = 24h',
                     'bantime.increment = true', 'bantime.maxtime = 1w', f'logpath = {probe_guard.PROBE_LOG}',
                     f'action = {probe_guard.ACTION.stem}', f'filter = {probe_guard.FILTER.stem}'):
            self.assertIn(line + '\n', jail)
        ignored = next(line for line in jail.splitlines() if line.startswith('ignoreip = ')).split()[2:]
        self.assertEqual(ignored, ['127.0.0.0/8', '::1', *map(str, client_address.cloudflare_ranges()), '198.51.100.0/24'])
        # The ban history outlives the longest ban, so a repeat offender's ban can grow.
        self.assertIn('dbpurgeage = 30d', probe_guard.server_settings())
        action = probe_guard.action_configuration()
        for line in ('actionstart_on_demand = false', 'actionban = %(companion)s ban <ip>',
                     'actionunban = %(companion)s unban <ip>', 'actionflush = %(companion)s clear'):
            self.assertIn(line + '\n', action)
        self.assertIn(f'test -e {probe_guard.PROBE_LOG} ||', probe_guard.fail2ban_dropin())

    def test_access_log_404s_that_the_guard_did_not_answer(self):
        line = '203.0.113.5 - - [08/Nov/2026:10:00:00 +0000] "GET {} HTTP/2.0" {} 162 "-" "curl/8.5.0" "203.0.113.5"'
        entry = probe_guard.not_found_entry(line.format('/alfa.php?cmd=1', 404))
        self.assertEqual(entry, {'at': 1794132000, 'ip': '203.0.113.5', 'path': '/alfa.php'})
        for target, status in (('/.env', 404), ('/backup.zip', 404), ('/wp-content/uploads/.htaccess', 404),
                               ('/alfa.php', 200), ('/alfa.php', 403)):
            with self.subTest(target=target, status=status):
                self.assertIsNone(probe_guard.not_found_entry(line.format(target, status)))
        self.assertIsNone(probe_guard.not_found_entry('not a log line'))

    def test_probe_log_lines_are_validated(self):
        line = {'at': 1794132000.5, 'ip': '2001:db8::7', 'edge': '2400:cb00::1', 'country': 'DE', 'host': 'shop.example.com',
                'method': 'GET', 'path': '/.env', 'status': 404, 'agent': 'curl/8.5.0'}
        self.assertEqual(probe_guard.probe_entry(json.dumps(line))['ip'], '2001:db8::7')
        self.assertEqual(len(probe_guard.probe_entry(json.dumps({**line, 'path': '/.' + 'a' * 500}))['path']),
                         probe_guard.PATH_LIMIT)
        for change in ({'ip': 'unknown'}, {'country': 'de'}, {'path': 'relative'}, {'at': 'NaN'}, {'status': 'x'}):
            with self.subTest(change=change):
                self.assertIsNone(probe_guard.probe_entry(json.dumps({**line, **change})))

    def test_edge_patterns_group_probes_and_list_not_found_pages_exactly(self):
        patterns = probe_guard.edge_patterns(
            [('/.env', 30), ('/.env.production', 5), ('/.git/config', 12), ('/backup.sql', 7), ('/dump.sql', 3),
             ('/wp-config.php.bak', 2), ('/wp-configs.php', 1), ('/composer.json', 1), ('/..x', 1)],
            [('/config/aws.json', 6), ('/', 9), ('/wp-json/x', 4), ('/sitemap.xml', 3), ('/robots.txt', 2),
             ('/.well-known/x', 2), ('/blog/wp-content/x', 2), ('/a"b', 1)])
        # A widened condition never reaches into WordPress's folders, where plugins keep files of every kind.
        outside = ('not http.request.uri.path contains "/wp-content/" and not http.request.uri.path contains "/wp-includes/" '
                   'and not http.request.uri.path contains "/wp-admin/" and not http.request.uri.path contains "/wp-json/"')
        self.assertEqual([(item['condition'], item['requests'], item['source']) for item in patterns['conditions']], [
            ('http.request.uri.path contains "/.env" and ' + outside, 35, 'probe'),
            ('http.request.uri.path contains "/.git" and ' + outside, 12, 'probe'),
            ('http.request.uri.path.extension eq "sql" and ' + outside, 10, 'probe'),
            ('http.request.uri.path eq "/config/aws.json"', 6, 'not-found'),
            ('http.request.uri.path contains "/wp-config." and ' + outside, 2, 'probe'),
            # Not widened: a broader wp-config condition could match a post, an empty dot name every dot folder.
            ('http.request.uri.path eq "/wp-configs.php"', 1, 'probe'),
            ('http.request.uri.path eq "/composer.json"', 1, 'probe'),
            ('http.request.uri.path eq "/..x"', 1, 'probe'),
            ('http.request.uri.path eq "/a\\"b"', 1, 'not-found')])
        # The joined expression names WordPress's folders once.
        self.assertTrue(patterns['expression'].startswith('((http.request.uri.path contains "/.env") or ('))
        self.assertTrue(patterns['expression'].endswith(') and ' + outside))
        self.assertEqual(patterns['expression'].count('/wp-content/'), 1)
        self.assertEqual(probe_guard.edge_patterns([], [('/alfa.php', 2)])['expression'], '(http.request.uri.path eq "/alfa.php")')
        self.assertLessEqual(len(probe_guard.edge_patterns([(f'/{n}.sql', 1) for n in range(50)],
                                                           [(f'/p{n}', 1) for n in range(50)])['conditions']), 10)


class BanStateTests(unittest.TestCase):
    def setUp(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name, value in (('BANNED', folder / 'banned.json'), ('BAN_MAP', folder / 'banned.conf'),
                            ('LOCK', folder / 'bans.lock'), ('CONFIG', folder / 'probe-guard.json')):
            self.enterContext(mock.patch.object(probe_guard, name, value))
        self.enterContext(mock.patch.object(probe_guard, 'own_addresses', return_value={ipaddress.ip_address('203.0.113.10')}))
        self.enterContext(mock.patch.object(probe_guard, 'settings', return_value={'allowlist': ['198.51.100.0/24']}))
        self.calls = []

    def run_command(self, arguments, **kwargs):
        self.calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, b'', b'')

    def test_bans_are_recorded_protected_addresses_refused_and_one_reload_requested(self):
        with mock.patch.object(probe_guard.subprocess, 'run', side_effect=self.run_command), \
                mock.patch('builtins.print'):
            probe_guard.change('ban', '192.0.2.44')
            probe_guard.change('ban', '192.0.2.45')
            for protected in ('173.245.48.7', '127.0.0.1', '203.0.113.10', '198.51.100.9'):
                probe_guard.change('ban', protected)
            self.assertEqual(probe_guard.load_bans(), ['192.0.2.44', '192.0.2.45'])
            probe_guard.change('unban', '192.0.2.44')
            self.assertEqual(probe_guard.load_bans(), ['192.0.2.45'])
            probe_guard.change('clear')
            self.assertEqual(probe_guard.load_bans(), [])
        start = ['/usr/bin/systemctl', 'start', '--no-block', probe_guard.RELOAD_UNIT]
        # Every recorded change asks for the reload; a refused ban changes nothing and asks for nothing.
        self.assertEqual(self.calls, [start] * 4)

    def test_nginx_refusal_keeps_the_previous_list_and_a_late_ban_is_applied(self):
        probe_guard.BAN_MAP.write_text(probe_guard.ban_map([]))
        probe_guard.BANNED.write_text(json.dumps(['192.0.2.44', '173.245.48.7']))
        refused = lambda arguments, **kwargs: subprocess.CompletedProcess(arguments, 1 if arguments[-1] == '-t' else 0, b'', b'emerg')
        with mock.patch.object(probe_guard.subprocess, 'run', side_effect=refused), self.assertRaises(RuntimeError):
            probe_guard.apply_bans(settle=0)
        self.assertEqual(probe_guard.BAN_MAP.read_text(), probe_guard.ban_map([]))

        def reload(arguments, **kwargs):
            self.calls.append(arguments)
            # A ban recorded while the first list is being applied.
            if arguments[-1] == 'nginx' and len(self.calls) == 2:
                probe_guard.BANNED.write_text(json.dumps(['192.0.2.44', '192.0.2.46', '173.245.48.7']))
            return subprocess.CompletedProcess(arguments, 0, b'', b'')
        with mock.patch.object(probe_guard.subprocess, 'run', side_effect=reload):
            result = probe_guard.apply_bans(settle=0)
        self.assertEqual(result, {'banned': 2, 'reloads': 2})
        self.assertEqual(probe_guard.BAN_MAP.read_text(), probe_guard.ban_map(['192.0.2.44', '192.0.2.46']))
        self.assertEqual(self.calls, [[probe_guard.NGINX, '-t'], ['/usr/bin/systemctl', 'reload', 'nginx']] * 2)
        # Nothing changed: no test, no reload.
        self.calls.clear()
        with mock.patch.object(probe_guard.subprocess, 'run', side_effect=self.run_command):
            self.assertEqual(probe_guard.apply_bans(settle=0), {'banned': 2, 'reloads': 0})
        self.assertEqual(self.calls, [])

    def test_current_bans_and_their_end_come_from_fail2ban(self):
        start = int(time.mktime(time.strptime('2026-11-09 16:04:53', '%Y-%m-%d %H:%M:%S')))
        listed = b'192.0.2.44 \t2026-11-09 16:04:53 + 86400 = 2026-11-10 16:04:53\n2001:db8::9 \t2026-11-09 16:04:53 + 172800 = x\n'
        with mock.patch.object(probe_guard.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, listed, b'')):
            self.assertEqual(probe_guard.active_bans(), [('192.0.2.44', start, start + 86400), ('2001:db8::9', start, start + 172800)])
        with mock.patch.object(probe_guard.subprocess, 'run', return_value=subprocess.CompletedProcess([], 255, b'', b'')), \
                self.assertRaises(ValueError):
            probe_guard.active_bans()


class InstallerTests(unittest.TestCase):
    def test_a_security_include_the_companion_did_not_write_is_never_replaced(self):
        spec = importlib.util.spec_from_file_location('install_probe_guard', ROOT / 'install-probe-guard.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with mock.patch.object(probe_guard, 'SITE_INCLUDES', folder):
            earlier = folder / 'shop-security.conf'
            # Written by the application safeguards of earlier releases: the Companion's own.
            earlier.write_text('# Managed by CloudPanel Companion application hardening.\nlocation = /wp-config.php { deny all; }\n')
            previous = installer.replace({earlier: (probe_guard.site_include(), 0o644)})
            self.assertEqual(earlier.read_text(), probe_guard.site_include())
            installer.restore(previous)
            self.assertIn('application hardening', earlier.read_text())
            earlier.write_text('location / { }\n')
            with self.assertRaisesRegex(ValueError, 'not written by the Companion'):
                installer.replace({earlier: (probe_guard.site_include(), 0o644)})
            self.assertEqual(earlier.read_text(), 'location / { }\n')

    def test_installed_needs_every_file_current_and_the_jail_running(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        paths = {name: folder / name.lower() for name in ('HTTP_CONFIG', 'LOGROTATE', 'CONFIG', 'FILTER', 'ACTION',
                                                           'JAIL_FILE', 'SERVER_SETTINGS', 'FAIL2BAN_DROPIN', 'PROBE_LOG',
                                                           'BAN_MAP')}
        with mock.patch.multiple(probe_guard, SITE_INCLUDES=folder, SYSTEMD=folder, **paths):
            wanted = probe_guard.files(['shop', 'shopstg'], [], probe_guard.site_access_log('shop'))
            for group in wanted.values():
                for path, (content, _) in group.items():
                    path.write_text(content)
            for name in ('PROBE_LOG', 'BAN_MAP'):
                paths[name].write_text('')
            (folder / probe_guard.RELOAD_UNIT).write_text('')
            with mock.patch.object(probe_guard, 'jail_running', return_value=True):
                self.assertTrue(probe_guard.installed(['shop', 'shopstg'], [], '/home/shop/logs/nginx/access.log'))
                # A new allowlist entry changes the jail and the settings.
                self.assertFalse(probe_guard.installed(['shop', 'shopstg'], ['198.51.100.7/32'], '/home/shop/logs/nginx/access.log'))
                self.assertFalse(probe_guard.installed(['shop', 'other'], [], '/home/shop/logs/nginx/access.log'))
            with mock.patch.object(probe_guard, 'jail_running', return_value=False):
                self.assertFalse(probe_guard.installed(['shop', 'shopstg'], [], '/home/shop/logs/nginx/access.log'))


# CloudPanel's own access-log format and static-file location, as its nginx.conf and vhosts ship them.
CLOUDPANEL_LOG = '''    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
'''
STATIC = '''        location ~* ^.+\\.(css|js|jpg|jpeg|gif|png|ico|gz|svg|svgz|ttf|otf|woff|woff2|eot|mp4|ogg|ogv|webm|webp|zip|swf|map)$ {
            access_log off;
            add_header X-Served static;
        }
'''


@unittest.skipUnless(os.access(NGINX, os.X_OK), 'Nginx is not installed')
class NginxProbeGuardTests(unittest.TestCase):
    """The generated probe guard in the website's two-hop chain, in a disposable, unprivileged Nginx.

    Loopback 127.0.0.1 stands in for a Cloudflare edge, so CF-Connecting-IP names the visitor as on
    a real site. The backend block answers every request it receives with "backend", so a probe that
    reached it would show.
    """

    def setUp(self):
        self.folder = folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.probes, self.access, self.backend_log = folder / 'probes.log', folder / 'access.log', folder / 'backend.log'
        self.ban_map = folder / 'banned.conf'
        self.enterContext(mock.patch.multiple(probe_guard, PROBE_LOG=self.probes, BAN_MAP=self.ban_map))
        edge = [ipaddress.ip_network('127.0.0.1/32')]
        # The jail asked for a visitor and for the edge itself; only the visitor is enforced.
        self.ban_map.write_text(probe_guard.ban_map(probe_guard.enforced(['198.51.100.66', '127.0.0.1'], [], set(), edge)))
        (folder / 'public.conf').write_text(client_address.public_trust(edge))
        (folder / 'backend.conf').write_text(client_address.backend_trust())
        (folder / 'security.conf').write_text(probe_guard.site_include())
        www = folder / 'www'
        (www / 'wp-content/uploads/woocommerce_uploads').mkdir(parents=True)
        (www / 'existing.zip').write_text('archive')
        (www / 'sitemap.xml.gz').write_text('sitemap')
        (www / 'wp-config.php').write_text('<?php secret')
        (www / 'wp-content/uploads/woocommerce_uploads/order.zip').write_text('paid download')
        self.public, backend, self.stale = free_port(), free_port(), free_port()
        # In sites-enabled order: 000-companion-probes.conf before 000-companion-security.conf, whose variables it uses.
        start_nginx(self, folder, f'''{CLOUDPANEL_LOG}{probe_guard.http_configuration()}{client_address.http_configuration(edge)}
    default_type text/plain;
    server {{
        listen 127.0.0.1:{self.public};
        server_name shop.example.com;
        root {www};
        include {folder}/public.conf;
        include {folder}/security.conf;
        access_log {self.access} main;
        location / {{
            proxy_set_header X-Real-IP $remote_addr;
            proxy_pass http://127.0.0.1:{backend};
        }}
{STATIC}    }}
    server {{
        listen 127.0.0.1:{backend};
        server_name shop.example.com;
        root {www};
        include {folder}/backend.conf;
        include {folder}/security.conf;
        location / {{ access_log {self.backend_log} main; return 200 "backend"; }}
    }}
    # A vhost saved before the client-address includes: CloudPanel's http-level realip
    # believes any X-Real-IP there.
    server {{
        listen 127.0.0.1:{self.stale};
        server_name stale.example.com;
        root {www};
        include {folder}/security.conf;
        location / {{ return 200 "stale"; }}
    }}
''', [self.public, backend, self.stale])

    def fetch(self, path, client='192.0.2.10', country='DE', port=None, source='127.0.0.1', headers=None):
        """A request from `source`: 127.0.0.1 is the Cloudflare edge, any other loopback address a direct visitor."""
        connection = http.client.HTTPConnection('127.0.0.1', port or self.public, timeout=5, source_address=(source, 0))
        headers = {'CF-IPCountry': country, 'User-Agent': 'probe-test/1.0', **(headers or {})}
        if client:
            headers['CF-Connecting-IP'] = client
        try:
            connection.request('GET', path, headers=headers)
            response = connection.getresponse()
            return response.status, response.read().decode(errors='replace'), response.getheader('X-Served')
        finally:
            connection.close()

    def lines(self, path, count):
        for _ in range(100):
            found = path.read_text().splitlines() if path.exists() else []
            if len(found) >= count:
                return found
            time.sleep(0.05)
        return path.read_text().splitlines() if path.exists() else []

    def test_probes_end_with_a_404_before_the_backend_and_are_logged(self):
        targets = ['/.env', '/wp-config.php', '/backup.sql?x=1', '/missing.zip', '/terraform.tfstate', '/.git/config',
                   '/composer.json']
        for target in targets:
            with self.subTest(target=target):
                status, body, _ = self.fetch(target)
                self.assertEqual(status, 404)
                self.assertNotIn('backend', body)
        entries = [probe_guard.probe_entry(line) for line in self.lines(self.probes, len(targets))]
        self.assertEqual([entry['path'] for entry in entries], [target.split('?')[0] for target in targets])
        self.assertEqual({(entry['ip'], entry['country'], entry['status'], entry['host']) for entry in entries},
                         {('192.0.2.10', 'DE', 404, 'shop.example.com')})
        self.assertIn('"edge":"127.0.0.1"', self.probes.read_text())
        self.assertNotIn('x=1', self.probes.read_text())
        self.assertEqual(self.backend_log.read_text(), '')
        # The website's own log has them too, and the not-found report leaves them out.
        access = self.lines(self.access, len(targets))
        self.assertEqual(len(access), len(targets))
        self.assertEqual([probe_guard.not_found_entry(line) for line in access], [None] * len(targets))

    def test_ordinary_requests_reach_the_backend_untouched(self):
        for target in ('/', '/wp-json/wp/v2/posts', '/?rest_route=/wp/v2/posts', '/wp-login.php', '/wp-admin/',
                       '/wp-cron.php', '/xmlrpc.php', '/robots.txt', '/llms.txt', '/sitemap.xml', '/sitemap.xml.gz',
                       '/.well-known/acme-challenge/token', '/wp-content/uploads/2026/01/report.pdf', '/cart/',
                       '/checkout/', '/my-account/', '/some-missing-page/', '/graphql', '/config/aws.json',
                       '/wp-content/plugins/shop/config.yml', '/wp-content/plugins/shop/bin/install.sh',
                       '/wp-content/themes/shop/theme.toml', '/blog/wp-content/plugins/shop/app.conf',
                       '/wp-config-explained', '/.well-known/apple-developer-merchantid-domain-association'):
            with self.subTest(target=target):
                status, body, served = self.fetch(target)
                # CloudPanel's static-file location serves a compressed sitemap from disk.
                self.assertEqual((status, served or body), (200, 'static' if target == '/sitemap.xml.gz' else 'backend'))
        self.assertEqual(self.probes.read_text(), '')

    def test_an_existing_archive_is_a_download_and_private_files_stay_hidden(self):
        self.assertEqual(self.fetch('/existing.zip')[:3:2], (200, 'static'))
        self.assertEqual(self.fetch('/wp-content/uploads/woocommerce_uploads/order.zip')[0], 404)
        for hidden in ('/wp-content/uploads/.htaccess', '/wp-content/debug.log', '/wp-content/plugins/shop/dist/.min.js',
                       '/wp-content/themes/shop/.git/HEAD'):
            with self.subTest(hidden=hidden):
                self.assertEqual(self.fetch(hidden)[0], 404)
        status, body, _ = self.fetch('/missing.zip')
        self.assertEqual(status, 404)
        # Only the missing archive counted; the hidden files and the private download did not.
        self.assertEqual([probe_guard.probe_entry(line)['path'] for line in self.lines(self.probes, 1)], ['/missing.zip'])

    def test_a_banned_visitor_gets_a_403_and_the_edge_itself_is_never_banned(self):
        self.assertEqual(self.fetch('/', client='198.51.100.66')[0], 403)
        self.assertEqual(self.fetch('/.env', client='198.51.100.66')[0], 403)
        # Another visitor through the same edge, and the edge's own request without a visitor header.
        self.assertEqual(self.fetch('/', client='198.51.100.67')[:2], (200, 'backend'))
        self.assertEqual(self.fetch('/', client=None)[:2], (200, 'backend'))
        # A ban is not a probe: nothing was logged for the banned visitor.
        self.assertEqual(self.probes.read_text(), '')

    def test_only_a_certain_address_is_counted_and_no_header_aims_a_ban(self):
        # CF-Connecting-IP from a peer outside Cloudflare's ranges: forged, or an edge not listed yet.
        self.assertEqual(self.fetch('/.env', client='192.0.2.30', source='127.0.0.2')[0], 404)
        # X-Real-IP naming a banned address changes nothing, even where CloudPanel's realip believes it.
        forged = {'X-Real-IP': '198.51.100.66'}
        self.assertEqual(self.fetch('/', client=None, port=self.stale, source='127.0.0.2', headers=forged)[:2], (200, 'stale'))
        self.assertEqual(self.fetch('/', client=None, source='127.0.0.2', headers=forged)[:2], (200, 'backend'))
        self.assertEqual(self.fetch('/.env', client=None, port=self.stale, source='127.0.0.2', headers=forged)[0], 404)
        self.assertEqual(self.fetch('/.git/config', client='192.0.2.31')[0], 404)
        entries = [probe_guard.probe_entry(line) for line in self.lines(self.probes, 2)]
        self.assertEqual([(entry['ip'], entry['path']) for entry in entries], [('127.0.0.2', '/.env'), ('192.0.2.31', '/.git/config')])
        # The banned visitor named by the edge is still refused on the stale vhost.
        self.assertEqual(self.fetch('/', client='198.51.100.66', port=self.stale)[0], 403)

    def test_ipv6_visitors_are_banned_and_logged(self):
        self.ban_map.write_text(probe_guard.ban_map(['2001:db8::66']))
        subprocess.run([NGINX, '-p', str(self.folder), '-c', str(self.folder / 'nginx.conf'), '-s', 'reload'], check=True,
                       capture_output=True, timeout=30)
        for _ in range(100):
            if self.fetch('/', client='2001:db8::66')[0] == 403:
                break
            time.sleep(0.05)
        self.assertEqual(self.fetch('/', client='2001:db8::66')[0], 403)
        self.assertEqual(self.fetch('/', client='2001:db8::67')[:2], (200, 'backend'))
        self.assertEqual(self.fetch('/.env', client='2001:db8::67')[0], 404)
        self.assertEqual(probe_guard.probe_entry(self.lines(self.probes, 1)[0])['ip'], '2001:db8::67')

    @unittest.skipUnless(FAIL2BAN_REGEX, 'fail2ban-regex is not installed')
    def test_fail2ban_counts_the_logged_probes_and_skips_declared_crawlers(self):
        self.fetch('/.env')
        self.fetch('/backup.sql', client='2001:db8::7')
        connection = http.client.HTTPConnection('127.0.0.1', self.public, timeout=5)
        connection.request('GET', '/.git/config', headers={'CF-Connecting-IP': '192.0.2.20', 'User-Agent':
                           'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'})
        connection.getresponse().read()
        connection.close()
        self.fetch('/missing-backup.zip', client='192.0.2.30')
        self.lines(self.probes, 4)
        filter_file = self.folder / 'filter.conf'
        filter_file.write_text(probe_guard.filter_configuration())
        result = subprocess.run([FAIL2BAN_REGEX, '--print-all-matched', str(self.probes), str(filter_file)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Lines: 4 lines, 2 ignored, 2 matched, 0 missed', result.stdout)
        matched, ignored = result.stdout.split('|- Matched line(s):', 1)[1].split('|- Ignored line(s):', 1)
        self.assertIn('"ip":"192.0.2.10"', matched)
        self.assertIn('"ip":"2001:db8::7"', matched)
        self.assertNotIn('Googlebot', matched)
        self.assertIn('"ip":"192.0.2.20"', ignored)
        # A missing archive is logged for the Security page but never counts towards a ban.
        self.assertIn('"ip":"192.0.2.30"', ignored)
        self.assertNotIn('192.0.2.30', matched)


if __name__ == '__main__':
    unittest.main()
