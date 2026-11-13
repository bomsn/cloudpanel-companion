import http.server
import threading
import unittest
from companion.health import Target, probe


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/application/'):
            self.send_response(200)
            self.end_headers()
            body = {'/application/ready': b'{"ready":true}', '/application/failed': b'{"ready":false}',
                    '/application/wrong-type': b'{"ready":1}', '/application/broken': b'<html>Error page</html>'}
            self.wfile.write(body[self.path])
            return
        self.send_response(int(self.path.strip('/') or '200'))
        self.end_headers()

    def log_message(self, *_args):
        pass


class HealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_http_success(self):
        self.assertTrue(probe(Target('public', self.url)).healthy)

    def test_real_application_body_is_checked_beyond_status_200(self):
        self.assertTrue(probe(Target('PHP/database', self.url + '/application/ready', expected_json={'ready': True})).healthy)
        for path in ('failed', 'wrong-type', 'broken'):
            with self.subTest(path=path):
                result = probe(Target('PHP/database', self.url + '/application/' + path, expected_json={'ready': True}))
                self.assertFalse(result.healthy)
                self.assertEqual(result.category, 'application-check-failed')

    def test_error_is_not_healthy(self):
        for status in (401, 403, 404, 500, 503):
            with self.subTest(status=status):
                result = probe(Target('public', self.url + '/' + str(status)))
                self.assertFalse(result.healthy)
                self.assertEqual(result.status, status)

    def test_expected_protected_staging(self):
        self.assertTrue(probe(Target('staging', self.url + '/401', (401,))).healthy)

    def test_redirect_is_explicit(self):
        self.assertFalse(probe(Target('public', self.url + '/301')).healthy)
        self.assertTrue(probe(Target('redirect', self.url + '/301', (301,))).healthy)

    def test_invalid_configuration(self):
        for url in ('file:///etc/passwd', 'http://user:pass@localhost', 'https://example.com/\r\nx:y'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                probe(Target('bad', url))


if __name__ == '__main__':
    unittest.main()
