"""Real local TLS connections with disposable certificates, not mocked SSL."""
import http.server
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from companion.health import Target, probe


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for TLS fixture')
class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.temp.name) / 'cert.pem'
        key = Path(cls.temp.name) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True)
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'https://localhost:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def test_untrusted_is_not_healthy(self):
        result = probe(Target('untrusted', self.url, connect_host='127.0.0.1'))
        self.assertFalse(result.healthy)
        self.assertEqual(result.category, 'certificate-invalid')

    def test_explicit_origin_trust_and_expiry_warning(self):
        result = probe(Target('origin', self.url, connect_host='127.0.0.1', ca_file=str(self.cert)))
        self.assertTrue(result.healthy)
        self.assertEqual(result.category, 'certificate-expiring')
        self.assertLessEqual(result.certificate_days, 1)

    def test_wrong_hostname_is_not_healthy(self):
        result = probe(Target('wrong-host', self.url.replace('localhost', '127.0.0.1'), ca_file=str(self.cert)))
        self.assertFalse(result.healthy)
        self.assertEqual(result.category, 'certificate-invalid')


if __name__ == '__main__':
    unittest.main()
