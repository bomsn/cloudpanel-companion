"""Exercise the real stock Varnish/controller contract on loopback only.

Run as root on a disposable Linux test host. This starts its own Varnish and
backend, never reloads the system cache, and contains no customer data.
"""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import grp
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

from companion.cache_config import render
from companion.cache_control import RevisionController, ControlServer, Handler


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Backend(BaseHTTPRequestHandler):
    generation = 0
    requests = 0
    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            Backend.requests += 1
            generation = Backend.generation
        path = self.path.split('?')[0]
        if path == '/race' and generation == 0:
            self.entered.set()
            self.release.wait(10)
        body = json.dumps({'generation': generation, 'host': self.headers['Host'],
                           'cookie': self.headers.get('Cookie', ''), 'path': path}).encode()
        self.send_response(200)
        content_type = 'application/pdf' if path == '/catalogue.pdf' else (
            'application/json' if path in ('/wp-json/public-data', '/wc-api/payment-callback') else 'text/html')
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        if path != '/unapproved':
            self.send_header('X-Cache-Manager-For-CloudPanel-Public', '1')
        self.send_header('Cache-Control', {
            '/private': 'private, max-age=60', '/no-store': 'no-store',
            '/no-cache': 'no-cache', '/zero': 'public, max-age=0',
            '/long': 'public, max-age=86400', '/short': 'public, max-age=2',
            '/origin-shortened': 'public, max-age=2',
        }.get(path, 'public, max-age=0, s-maxage=300, must-revalidate' if path.startswith('/origin')
              else 'public, max-age=60'))
        # The plugin's origin-retention header (CACHE_MANAGER_FOR_CLOUDPANEL_ORIGIN_TTL).
        origin = {'/origin-retention': '3600', '/origin-shortened': '3600', '/origin-clamped': '99999'}.get(path)
        if origin:
            self.send_header('X-Cache-Manager-For-CloudPanel-Origin-TTL', origin)
        extra = {
            '/set-cookie': ('Set-Cookie', 'private=one'),
            '/vary-cookie': ('Vary', 'Cookie'), '/vary-star': ('Vary', '*'),
            '/pragma': ('Pragma', 'no-cache'),
        }.get(path)
        if extra:
            self.send_header(*extra)
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def exercise(policy_path):
    results = []
    with tempfile.TemporaryDirectory(prefix='cmcp-acceptance-', dir='/var/tmp') as folder:
        root = Path(folder)
        gid = grp.getgrnam('varnish').gr_gid
        root.chmod(0o750)
        os.chown(root, 0, gid)
        backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
        backend_thread.start()
        listen, admin = port(), port()
        config = {'backend_port': backend.server_port, 'sites': [
            {'host': 'one.example', 'purge_key': 'a' * 64},
            {'host': 'two.example', 'purge_key': 'b' * 64},
        ]}
        policy = policy_path.read_text()
        vcl = root / 'initial.vcl'
        vcl.write_text(render(config, policy))
        vcl.chmod(0o640)
        os.chown(vcl, 0, gid)
        instance = root / 'instance'
        state = root / 'state'
        state.mkdir(mode=0o700)
        ready = root / 'ready'
        ready.mkdir(mode=0o755)
        controller = control = process = None
        log = (root / 'varnish.log').open('wb')

        def request(path='/', host='one.example', headers=None, method='GET', destination=None):
            req = urllib.request.Request(f'http://127.0.0.1:{destination or listen}{path}',
                                         headers={'Host': host, **(headers or {})}, method=method)
            try:
                response = urllib.request.urlopen(req, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, dict(response.headers), response.read()

        def purge(host='one.example', key='a' * 64, **kwargs):
            status, headers, _ = request(host=host, method='PURGE', destination=control.server_port,
                headers={'X-Cache-Manager-For-CloudPanel-Key': key, **kwargs})
            assert status == 200, status
            assert headers.get('X-Cache-Manager-For-CloudPanel-Policy') == 'site-revision-v1'

        try:
            process = subprocess.Popen(['varnishd', '-F', '-a', f'127.0.0.1:{listen}',
                '-T', f'127.0.0.1:{admin}', '-n', str(instance), '-f', str(vcl), '-s', 'malloc,32m'],
                stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Isolated Varnish failed: ' + (root / 'varnish.log').read_text())
                try:
                    with socket.create_connection(('127.0.0.1', listen), timeout=.1):
                        break
                except OSError:
                    time.sleep(.1)
            controller = RevisionController(config, policy, state, instance, ready)
            controller.activate()
            assert all(controller.marker(site['host']).is_file() for site in config['sites'])
            control = ControlServer(('127.0.0.1', 0), Handler)
            control.controller = controller
            control_thread = threading.Thread(target=control.serve_forever, daemon=True)
            control_thread.start()
            request()
            status, headers, body = request()
            assert status == 200 and headers['X-Cache-Manager-For-CloudPanel'] == 'HIT'
            assert headers['X-Frame-Options'] == 'SAMEORIGIN'
            results.append('anonymous HIT preserves security headers')

            for name, headers in [('cart', {'Cookie': 'woocommerce_items_in_cart=1'}),
                ('session', {'Cookie': 'wp_woocommerce_session_a=one'}),
                ('login', {'Cookie': 'wordpress_logged_in_a=one'}),
                ('unknown-cookie', {'Cookie': 'wholesale_role=approved'}),
                ('authorization', {'Authorization': 'Bearer example'})]:
                for _ in range(2):
                    status, got, _ = request(headers=headers)
                    assert status == 200 and got['X-Cache-Manager-For-CloudPanel'] == 'BYPASS', name
                    assert got['Cache-Control'] == 'private, no-store', name
                assert request()[1]['X-Cache-Manager-For-CloudPanel'] == 'HIT'
                results.append(name + ' bypass cannot contaminate anonymous cache')

            for cookie in ('_ga=GA1.1.1; _ga_ABC123=GS1; _gid=1', '_fbp=fb.1; cf_clearance=x; __cf_bm=y',
                           '_hjSessionUser_123=a; _cs_id=b; _cs_mk_ga=c; _clck=d'):
                status, got, body = request(headers={'Cookie': cookie})
                assert got['X-Cache-Manager-For-CloudPanel'] == 'HIT', cookie
                assert got['Cache-Control'].startswith('public'), cookie
            request('/analytics-only', headers={'Cookie': '_ga=GA1.1.1'})
            assert json.loads(request('/analytics-only', headers={'Cookie': '_gid=2'})[2])['cookie'] == ''
            results.append('analytics-only cookies share the anonymous cache and never reach WordPress')
            for cookie in ('_ga=1; wordpress_logged_in_a=one', '_gallery_view=grid', 'x_ga=1', '_ga=1; wholesale_role=approved'):
                status, got, body = request('/analytics-mixed', headers={'Cookie': cookie})
                assert got['X-Cache-Manager-For-CloudPanel'] == 'BYPASS', cookie
                assert got['Cache-Control'] == 'private, no-store', cookie
            # Server-side integrations on private pages may read analytics cookies,
            # so a bypassed request reaches WordPress with its cookies unchanged.
            received = json.loads(request('/analytics-mixed', headers={'Cookie': '_ga=1; sbjs_current=x; wordpress_logged_in_a=one'})[2])['cookie']
            assert received == '_ga=1; sbjs_current=x; wordpress_logged_in_a=one', received
            status, got, _ = request(headers={'Cookie': 'sbjs_first=a; sbjs_session=b; sbjs_udata=c'})
            assert got['X-Cache-Manager-For-CloudPanel'] == 'HIT'
            results.append('session and look-alike cookies still bypass with all cookies intact; analytics-only visits share the cache')
            request('/campaign')
            for path in ('/campaign?utm_source=news&utm_medium=email', '/campaign?gclid=abc', '/campaign?fbclid=1&utm_campaign=x'):
                status, got, body = request(path)
                assert got['X-Cache-Manager-For-CloudPanel'] == 'HIT', path
                assert json.loads(body)['path'] == '/campaign', path
            for path in ('/campaign?utm_source=x&page=2', '/campaign?xutm_source=x', '/campaign?s=chair'):
                assert request(path)[1]['X-Cache-Manager-For-CloudPanel'] == 'BYPASS', path
            before = Backend.requests
            request('/campaign?page=2&utm_source=x')
            assert Backend.requests == before + 1
            status, got, body = request('/campaign?utm_source=x', headers={'Cookie': 'wordpress_logged_in_a=one'})
            assert got['X-Cache-Manager-For-CloudPanel'] == 'BYPASS'
            results.append('campaign parameters share the clean cached page; other query strings still bypass')

            status, headers, body = request(headers={'Range': 'bytes=0-10'})
            assert status == 206 and len(body) == 11, (status, headers, body)
            assert headers['X-Cache-Manager-For-CloudPanel'] == 'BYPASS'
            assert request()[1]['X-Cache-Manager-For-CloudPanel'] == 'HIT'
            results.append('range returns the requested bytes without reusing or replacing full page cache')
            status, headers, body = request('/catalogue.pdf')
            assert status == 200 and headers['X-Cache-Manager-For-CloudPanel'] == 'BYPASS'
            assert headers['Cache-Control'] == 'public, max-age=60'
            results.append('public PDF pass retains origin cache directives for downstream CDNs')
            status, headers, body = request('/catalogue.pdf', headers={'Cookie': 'private=one'})
            assert status == 200 and headers['Cache-Control'] == 'private, no-store'
            results.append('cookie-bearing PDF response remains private downstream')
            status, headers, _ = request('/long')
            assert status == 200 and headers['Cache-Control'] == 'public, max-age=0, s-maxage=300, must-revalidate'
            results.append('HTML downstream lifetime cannot exceed the 300-second local limit')
            status, headers, _ = request('/short')
            assert status == 200 and headers['Cache-Control'] == 'public, max-age=0, s-maxage=2, must-revalidate'
            assert request('/short')[1]['X-Cache-Manager-For-CloudPanel'] == 'HIT'
            time.sleep(2.2)
            assert request('/short')[1]['X-Cache-Manager-For-CloudPanel'] == 'MISS'
            results.append('Aged HTML actually expires at its shorter origin lifetime and requires a fresh render')

            def stored_ttl(path):
                # The TTL Varnish actually stored for the object, from its own log.
                log = subprocess.run(['varnishlog', '-n', str(instance), '-d', '-b', '-i', 'TTL',
                                      '-q', 'BereqURL eq "' + path + '"'], capture_output=True, text=True, timeout=20).stdout
                values = [line.split()[3] for line in log.splitlines() if line.split()[2:3] == ['VCL']]
                return float(values[-1]) if values else None
            status, headers, _ = request('/origin-retention')
            assert status == 200 and headers['Cache-Control'] == 'public, max-age=0, s-maxage=300, must-revalidate'
            assert 'X-Cache-Manager-For-CloudPanel-Origin-TTL' not in headers
            assert stored_ttl('/origin-retention') == 3600, stored_ttl('/origin-retention')
            time.sleep(1.2)
            status, headers, _ = request('/origin-retention')
            assert headers['X-Cache-Manager-For-CloudPanel'] == 'HIT' and 'Age' not in headers, headers
            assert headers['Cache-Control'] == 'public, max-age=0, s-maxage=300, must-revalidate'
            results.append('Varnish keeps approved HTML for its origin setting (3600 s) while Cloudflare and browsers '
                           'still get s-maxage=300 with a fresh downstream window')
            request('/origin-clamped')
            assert stored_ttl('/origin-clamped') == 86400, stored_ttl('/origin-clamped')
            request('/origin-shortened')
            assert request('/origin-shortened')[1]['X-Cache-Manager-For-CloudPanel'] == 'HIT'
            time.sleep(2.2)
            assert request('/origin-shortened')[1]['X-Cache-Manager-For-CloudPanel'] == 'MISS'
            results.append('origin retention is bounded to one day and never lengthens a lifetime another handler shortened')
            for path in ('/wp-json/public-data', '/wc-api/payment-callback'):
                status, headers, _ = request(path)
                assert status == 200 and headers['Cache-Control'] == 'private, no-store'
                assert request(path)[1]['X-Cache-Manager-For-CloudPanel'] == 'BYPASS'
                results.append(path + ' JSON stays uncached and private downstream')

            for path in ['/private', '/no-store', '/no-cache', '/zero', '/set-cookie',
                         '/vary-cookie', '/vary-star', '/pragma', '/unapproved',
                         '/?add-to-cart=1', '/wp-admin/', '/wp-json/']:
                before = Backend.requests
                request(path)
                request(path)
                assert Backend.requests == before + 2, path
                results.append(path + ' never reused')

            assert request(host='unknown.example')[0] == 421
            assert request(method='PURGE')[0] == 405
            assert request(method='PURGE', destination=control.server_port)[0] == 403
            assert request(host='two.example', method='PURGE', destination=control.server_port,
                headers={'X-Cache-Manager-For-CloudPanel-Key': 'a' * 64})[0] == 403
            assert request(method='PURGE', destination=control.server_port, headers={
                'X-Cache-Manager-For-CloudPanel-Key': 'a' * 64,
                'X-Cache-Manager-For-CloudPanel-Tag': 'post:1'})[0] == 400
            results.append('unregistered host, direct purge, cross-site key and selective purge rejected')

            request('/separate', host='two.example')
            request('/separate')
            Backend.generation = 1
            purge()
            assert json.loads(request('/separate')[2])['generation'] == 1
            status, headers, body = request('/separate', host='two.example')
            assert headers['X-Cache-Manager-For-CloudPanel'] == 'HIT' and json.loads(body)['generation'] == 0
            results.append('purging one site preserves the other site cache')

            Backend.generation = 0
            with ThreadPoolExecutor(max_workers=2) as pool:
                old = pool.submit(request, '/race')
                assert Backend.entered.wait(5)
                Backend.generation = 2
                purge()
                Backend.release.set()
                assert json.loads(old.result()[2])['generation'] == 0
            assert json.loads(request('/race')[2])['generation'] == 2
            assert request('/race')[1]['X-Cache-Manager-For-CloudPanel'] == 'HIT'
            results.append('old in-flight render cannot populate the new revision')

            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda _: purge(), range(4)))
            assert request('/race')[1]['X-Cache-Manager-For-CloudPanel'] == 'MISS'
            assert request('/race')[1]['X-Cache-Manager-For-CloudPanel'] == 'HIT'
            results.append('concurrent real control requests complete and cache remains usable')
            controller.policy = policy + '\nthis is not valid VCL;\n'
            failure = request(method='PURGE', destination=control.server_port,
                headers={'X-Cache-Manager-For-CloudPanel-Key': 'a' * 64})
            assert failure[0] == 503
            assert not controller.marker('one.example').exists()
            assert controller.marker('two.example').is_file()
            results.append('actual failed VCL compile disables only affected host availability before returning failure')
            controller.policy = policy
            purge()
            assert controller.marker('one.example').is_file()
            results.append('successful retry restores availability only after fresh VCL activation')
            controller.close()
            assert not any(ready.glob('*.ready'))
            controller = None
            results.append('controller shutdown clears its cache availability markers')
            return {'passed': True, 'results': results}
        finally:
            Backend.release.set()
            if control:
                control.shutdown()
                control.server_close()
                control_thread.join()
            if controller:
                controller.close()
            if process:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            backend.shutdown()
            backend.server_close()
            backend_thread.join()
            log.close()


if __name__ == '__main__':
    import sys
    print(json.dumps(exercise(Path(sys.argv[1])), indent=2))
