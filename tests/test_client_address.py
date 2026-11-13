import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import urllib.error
import urllib.request
from companion import client_address

ROOT = Path(__file__).resolve().parents[1]
NGINX = shutil.which('nginx') or '/usr/sbin/nginx'
# What every forged-address test sends: the headers a client could use to pick its own address.
FORGED = {'X-Real-IP': '198.51.100.7', 'X-Forwarded-For': '198.51.100.8', 'CF-Connecting-IP': '198.51.100.9',
          'CF-IPCountry': 'DE'}


class ClientAddressRulesTests(unittest.TestCase):
    def test_published_ranges_are_parsed_and_implausible_lists_refused(self):
        networks = client_address.cloudflare_ranges()
        self.assertEqual(sum(network.version == 4 for network in networks), 15)
        self.assertEqual(sum(network.version == 6 for network in networks), 7)
        for text in ('', '# only a comment\n', '10.0.0.0/8\n', '0.0.0.0/0\n', 'not-a-network\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                client_address.cloudflare_ranges(text)

    def test_rules_trust_cloudflare_headers_only_from_the_connecting_peer(self):
        networks = client_address.cloudflare_ranges()
        text = client_address.http_configuration(networks)
        # The realip-rewritten address is chosen by any client sending X-Real-IP on CloudPanel servers.
        self.assertNotIn('$remote_addr', text)
        self.assertIn('geo $realip_remote_addr $companion_via_cloudflare {\n    default 0;\n', text)
        for network in networks:
            self.assertIn(f'    {network} 1;\n', text)
        self.assertIn('default $realip_remote_addr;', text)
        self.assertIn('"~^1:(?<companion_cloudflare_ip>', text)
        self.assertIn('"~^1:(?<companion_cloudflare_country>[A-Z0-9]{2})$"', text)
        # Only what the Security page needs: no URL, query string, cookie or user agent.
        log_format = next(line for line in text.splitlines() if line.startswith('log_format'))
        for field in ('$request_uri', '$args', '$query_string', '$http_cookie', '$http_user_agent', '$request '):
            self.assertNotIn(field, log_format)

    def test_website_includes_trust_only_cloudflare_publicly_and_loopback_behind(self):
        networks = client_address.cloudflare_ranges()
        public = client_address.public_trust(networks)
        lines = [line for line in public.splitlines() if not line.startswith('#')]
        self.assertEqual(lines, [f'set_real_ip_from {network};' for network in networks]
                         + ['real_ip_header CF-Connecting-IP;', 'real_ip_recursive off;'])
        backend = [line for line in client_address.backend_trust().splitlines() if not line.startswith('#')]
        self.assertEqual(backend, ['set_real_ip_from 127.0.0.1;', 'set_real_ip_from ::1;',
                                   'real_ip_header X-Real-IP;', 'real_ip_recursive off;'])
        # A failed update restores (or removes) them with the other managed Nginx files.
        from companion import package_install
        for path in client_address.TRUST_INCLUDES:
            self.assertEqual(path.parent, Path('/etc/cloudpanel-companion'))
            self.assertIn(path, package_install.MANAGED)

    def test_install_writes_the_website_includes_from_the_range_list(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            paths = {name: folder / name for name in ('HTTP_CONFIG', 'LOGROTATE', 'PUBLIC_TRUST', 'BACKEND_TRUST')}
            with mock.patch.multiple(client_address, LOG_DIRECTORY=folder / 'logs', **paths), \
                    mock.patch.object(client_address.os, 'chown'):
                client_address.install()
            networks = client_address.cloudflare_ranges()
            self.assertEqual(paths['PUBLIC_TRUST'].read_text(), client_address.public_trust(networks))
            self.assertEqual(paths['BACKEND_TRUST'].read_text(), client_address.backend_trust())
            self.assertEqual(paths['HTTP_CONFIG'].read_text(), client_address.http_configuration(networks))
            for name in ('PUBLIC_TRUST', 'BACKEND_TRUST'):
                self.assertEqual(paths[name].stat().st_mode & 0o777, 0o644)

    def test_interface_routing_forwards_only_the_decided_address(self):
        proxy = (ROOT / 'assets/companion-web-proxy.conf').read_text()
        self.assertNotIn('$remote_addr', proxy)
        self.assertIn('proxy_set_header X-Forwarded-For $companion_client_ip;', proxy)
        self.assertIn('proxy_set_header X-Real-IP $companion_client_ip;', proxy)
        self.assertIn('proxy_set_header X-Companion-Country $companion_client_country;', proxy)
        self.assertIn('proxy_set_header CF-Connecting-IP "";', proxy)
        self.assertIn('proxy_set_header CF-IPCountry "";', proxy)
        self.assertIn(client_address.access_directive('companion'), proxy)

    def test_log_lines_are_validated_field_by_field(self):
        line = {'at': 1793500000.123, 'ip': '2001:db8::1', 'country': 'DE', 'method': 'POST', 'path': 'login',
                'status': 302, 'next': 'login'}
        self.assertEqual(client_address.access_entry(json.dumps(line))['ip'], '2001:db8::1')
        for change in ({'ip': '198.51.100.7, 203.0.113.9'}, {'ip': 'unknown'}, {'country': 'de'}, {'country': 'DEU'},
                       {'path': '/login'}, {'next': '/sites'}, {'status': 99}, {'method': 'post'}, {'at': 'NaN'}):
            with self.subTest(change=change):
                self.assertIsNone(client_address.access_entry(json.dumps({**line, **change})))
        self.assertIsNone(client_address.access_entry('{"at": NaN}'))
        self.assertIsNone(client_address.access_entry('not json'))

    def test_panel_include_is_added_once_and_its_loss_is_detected(self):
        vhost = ('server {\n  listen 443 ssl http2;\n  server_name panel.example.com;\n'
                 '  #access_log /home/clp/logs/nginx/access.log;\n}\n')
        connected = client_address.panel_vhost(vhost, 'panel.example.com')
        self.assertEqual(connected.count(client_address.PANEL_INCLUDE_LINE), 1)
        self.assertEqual(client_address.panel_vhost(connected, 'panel.example.com'), connected)
        with self.assertRaises(ValueError):
            client_address.panel_vhost(vhost, 'other.example.com')
        with self.assertRaises(ValueError):
            client_address.panel_vhost(vhost + vhost, 'panel.example.com')
        with tempfile.TemporaryDirectory() as folder:
            path, include = Path(folder) / 'custom-domain.conf', Path(folder) / 'cloudpanel-access.conf'
            path.write_text(connected)
            self.assertEqual(client_address.panel_log_state(path, include), 'not-installed')
            include.write_text(client_address.access_directive('cloudpanel'))
            self.assertEqual(client_address.panel_log_state(path, include), 'connected')
            # CloudPanel regenerated its vhost (a custom-domain or certificate change).
            path.write_text(vhost)
            self.assertEqual(client_address.panel_log_state(path, include), 'disconnected')
        # An include re-indented by hand is refused rather than added a second time.
        with self.assertRaises(ValueError):
            client_address.panel_vhost(connected.replace(client_address.PANEL_INCLUDE_LINE,
                                                         client_address.PANEL_INCLUDE_LINE.strip()), 'panel.example.com')

    def test_installer_connects_the_panel_log_once_and_restores_the_vhost_when_nginx_refuses(self):
        spec = importlib.util.spec_from_file_location('install_security', ROOT / 'install-security.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        vhost = 'server {\n  listen 443 ssl http2;\n  server_name panel.example.com;\n}\n'
        with tempfile.TemporaryDirectory() as folder:
            path, include = Path(folder) / 'custom-domain.conf', Path(folder) / 'cloudpanel-access.conf'
            path.write_text(vhost)
            path.chmod(0o640)
            with mock.patch.object(client_address, 'PANEL_VHOST', path), mock.patch.object(client_address, 'PANEL_INCLUDE', include):
                with mock.patch.object(installer, 'run', side_effect=[subprocess.CalledProcessError(1, 'nginx')]):
                    with self.assertRaises(subprocess.CalledProcessError):
                        installer.connect_panel_log('panel.example.com')
                self.assertEqual(path.read_text(), vhost)
                self.assertFalse(include.exists())
                with mock.patch.object(installer, 'run') as executed:
                    installer.connect_panel_log('panel.example.com')
                    installer.connect_panel_log('panel.example.com')
                self.assertEqual([call.args for call in executed.call_args_list], [('nginx', '-t'), ('systemctl', 'reload', 'nginx')])
                self.assertEqual(path.read_text().count(client_address.PANEL_INCLUDE_LINE), 1)
                self.assertEqual(include.read_text(), client_address.access_directive('cloudpanel') + '\n')
                # CloudPanel's own file keeps the mode CloudPanel gave it.
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)
                # An unexpected layout is left alone and does not stop the collector's installation.
                unexpected = vhost + 'server {\n  listen 80;\n}\n'
                path.write_text(unexpected)
                include.unlink()
                with mock.patch.object(installer, 'run') as executed, mock.patch('builtins.print') as said:
                    installer.connect_panel_log('panel.example.com')
                executed.assert_not_called()
                self.assertIn('unexpected layout', said.call_args.args[0])
                self.assertEqual(path.read_text(), unexpected)
                self.assertEqual(client_address.panel_log_state(path, include), 'not-installed')


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


# CloudPanel's http-level realip settings, as its nginx.conf ships them.
CLOUDPANEL_REALIP = '''    real_ip_recursive on;
    set_real_ip_from 127.0.0.1;
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    set_real_ip_from 0.0.0.0/0;
    #real_ip_header X-Forwarded-For;
'''


def start_nginx(test, folder, http, ports):
    """Run a disposable, unprivileged Nginx with `http` inside its http block until the test ends."""
    temporary = ''.join(f'    {name}_temp_path {folder}/{name};\n' for name in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'))
    (folder / 'nginx.conf').write_text(f'''daemon off;
pid {folder}/nginx.pid;
error_log {folder}/error.log;
events {{ worker_connections 16; }}
http {{
{temporary}{CLOUDPANEL_REALIP}{http}}}
''')
    process = subprocess.Popen([NGINX, '-p', str(folder), '-c', str(folder / 'nginx.conf'), '-e', str(folder / 'error.log')],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    test.addCleanup(process.wait, 10)
    test.addCleanup(process.terminate)
    for port in ports:
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', port), timeout=0.2).close()
                break
            except OSError:
                if process.poll() is not None:
                    test.fail('Disposable Nginx did not start: ' + (folder / 'error.log').read_text())
                time.sleep(0.05)
        else:
            test.fail('Disposable Nginx did not accept connections')


@unittest.skipUnless(os.access(NGINX, os.X_OK), 'Nginx is not installed')
class NginxClientAddressTests(unittest.TestCase):
    """The generated rules in a disposable, unprivileged Nginx on a loopback port.

    CloudPanel's own realip settings are reproduced, so a forged X-Real-IP would win
    if the rules ever read $remote_addr.
    """

    def serve(self, networks):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        port = free_port()
        log = folder / 'access.log'
        start_nginx(self, folder, f'''{client_address.http_configuration(networks)}
    server {{
        listen 127.0.0.1:{port};
        access_log {log} {client_address.LOG_FORMAT} if=$companion_access_observe;
        default_type text/plain;
        location = /login {{ return 302 /login; }}
        location = /accepted {{ return 302 /sites; }}
        location / {{ return 200 "$companion_client_ip|$companion_client_country"; }}
    }}
''', [port])
        return f'http://127.0.0.1:{port}', log

    def fetch(self, url, headers, method='GET'):
        class Keep(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        request = urllib.request.Request(url, headers=headers, method=method)
        try:
            with urllib.request.build_opener(Keep).open(request, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, ''

    def logged(self, log):
        for _ in range(50):
            lines = log.read_text().splitlines() if log.exists() else []
            if lines:
                return [client_address.access_entry(line) for line in lines]
            time.sleep(0.05)
        return []

    def test_forged_headers_from_a_peer_outside_cloudflare_are_ignored(self):
        base, log = self.serve(client_address.cloudflare_ranges())
        self.assertEqual(self.fetch(base + '/', FORGED), (200, '127.0.0.1|'))
        entry = self.logged(log)[0]
        self.assertEqual((entry['ip'], entry['country'], entry['path']), ('127.0.0.1', '', 'other'))

    def test_cloudflare_peer_supplies_client_and_country(self):
        # Loopback stands in for a Cloudflare edge server here.
        base, log = self.serve([ipaddress.ip_network('127.0.0.0/8')])
        self.assertEqual(self.fetch(base + '/', FORGED), (200, '198.51.100.9|DE'))
        # A malformed client header from the edge falls back to the edge address, never to X-Real-IP.
        self.assertEqual(self.fetch(base + '/', {**FORGED, 'CF-Connecting-IP': '198.51.100.9, 203.0.113.1'}), (200, '127.0.0.1|DE'))

    def test_log_classifies_sign_in_redirects_without_storing_the_url(self):
        base, log = self.serve(client_address.cloudflare_ranges())
        self.assertEqual(self.fetch(base + '/login?user=secret', {}, 'POST')[0], 302)
        self.fetch(base + '/accepted', {}, 'POST')
        self.fetch(base + '/static/workspace.css', {})
        entries = self.logged(log)
        for _ in range(50):
            if len(entries) >= 2:
                break
            time.sleep(0.05)
            entries = self.logged(log)
        self.assertEqual([(entry['path'], entry['status'], entry['next']) for entry in entries],
                         [('login', 302, 'login'), ('other', 302, 'other')])
        self.assertNotIn('secret', log.read_text())


@unittest.skipUnless(os.access(NGINX, os.X_OK), 'Nginx is not installed')
class NginxWebsiteAddressTests(unittest.TestCase):
    """The website's two-hop chain with the generated includes, in a disposable Nginx.

    A public block (as the website's, proxying with `X-Real-IP $remote_addr`) in front of
    a backend block (as the 8080 PHP block), both under CloudPanel's http-level trust in
    every peer. Each answer carries the address each hop decided.
    """

    def serve(self, networks):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (folder / 'public.conf').write_text(client_address.public_trust(networks))
        (folder / 'backend.conf').write_text(client_address.backend_trust())
        public, backend, native = free_port(), free_port(), free_port()
        start_nginx(self, folder, f'''    default_type text/plain;
    access_log off;
    server {{
        listen 127.0.0.1:{public};
        include {folder}/public.conf;
        location / {{
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_pass http://127.0.0.1:{backend};
            add_header X-Public-Address $remote_addr always;
        }}
    }}
    server {{
        listen 127.0.0.1:{backend};
        include {folder}/backend.conf;
        location / {{ return 200 "$remote_addr"; }}
    }}
    server {{
        listen 127.0.0.1:{native};
        location / {{ return 200 "$remote_addr"; }}
    }}
''', [public, backend, native])
        return public, backend, native

    def fetch(self, port, headers, source='127.0.0.1'):
        """(address the public hop decided, address the answering block decided) for one request."""
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5, source_address=(source, 0))
        try:
            connection.request('GET', '/', headers=headers)
        except OSError as error:
            connection.close()
            # Linux answers on all of 127.0.0.0/8; other systems may not have a second loopback address.
            if source == '127.0.0.1':
                raise
            self.skipTest(f'Cannot connect from {source}: {error}')
        response = connection.getresponse()
        answer = (response.getheader('X-Public-Address'), response.read().decode())
        connection.close()
        self.assertEqual(response.status, 200)
        return answer

    def test_cloudpanel_alone_lets_any_client_choose_its_address(self):
        # Without the includes, CloudPanel's nginx.conf believes X-Real-IP from every peer.
        _, _, native = self.serve(client_address.cloudflare_ranges())
        self.assertEqual(self.fetch(native, FORGED), (None, '198.51.100.7'))

    def test_peer_outside_cloudflare_keeps_its_own_address_at_both_hops(self):
        public, _, _ = self.serve(client_address.cloudflare_ranges())
        self.assertEqual(self.fetch(public, FORGED), ('127.0.0.1', '127.0.0.1'))

    def test_cloudflare_peer_names_the_visitor_at_both_hops(self):
        # Loopback stands in for a Cloudflare edge server here.
        public, _, _ = self.serve([ipaddress.ip_network('127.0.0.1/32')])
        self.assertEqual(self.fetch(public, FORGED), ('198.51.100.9', '198.51.100.9'))
        self.assertEqual(self.fetch(public, {**FORGED, 'CF-Connecting-IP': '2001:db8::7'}), ('2001:db8::7', '2001:db8::7'))
        # A missing or unreadable CF-Connecting-IP leaves the edge's own address, never X-Real-IP or X-Forwarded-For.
        without = {name: value for name, value in FORGED.items() if name != 'CF-Connecting-IP'}
        self.assertEqual(self.fetch(public, without), ('127.0.0.1', '127.0.0.1'))
        self.assertEqual(self.fetch(public, {**FORGED, 'CF-Connecting-IP': 'unknown'}), ('127.0.0.1', '127.0.0.1'))
        # Nginx reads any realip header as a list and, with recursion off, takes its last address.
        # Cloudflare replaces this header with the one address it saw, so it never sends a list.
        self.assertEqual(self.fetch(public, {**FORGED, 'CF-Connecting-IP': '198.51.100.9, 203.0.113.1'}),
                         ('203.0.113.1', '203.0.113.1'))
        # A peer outside the trusted range is believed in neither hop.
        self.assertEqual(self.fetch(public, FORGED, source='127.0.0.2'), ('127.0.0.2', '127.0.0.2'))

    def test_backend_believes_x_real_ip_only_from_loopback(self):
        _, backend, _ = self.serve(client_address.cloudflare_ranges())
        # 127.0.0.2 is not one of the backend's trusted peers (127.0.0.1 and ::1).
        self.assertEqual(self.fetch(backend, FORGED, source='127.0.0.2'), (None, '127.0.0.2'))
        # The public block and Varnish connect from 127.0.0.1, so their X-Real-IP is believed.
        self.assertEqual(self.fetch(backend, FORGED), (None, '198.51.100.7'))


if __name__ == '__main__':
    unittest.main()
