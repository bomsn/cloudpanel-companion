import http.server
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from companion.delivery import post_json, payload, validate_webhook


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.received = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.send_response(200 if self.path == '/accepted' else 429 if self.path == '/limited' else 302)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *_args):
        pass


class DeliveryValidationTests(unittest.TestCase):
    def test_reject_unrelated_or_malformed_destinations(self):
        for url in ['http://hooks.slack.com/services/A/B/C', 'https://example.com/services/A/B/C',
                    'https://hooks.slack.com@127.0.0.1/services/A/B/C', 'https://hooks.slack.com/services/A/B/C?x=1']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_webhook(url)

    def test_payload_uses_plain_text_and_stable_identity(self):
        value = payload(('event-1', 'Site <name>', 'down', 1, 0))
        self.assertFalse(value['mrkdwn'])
        self.assertEqual(value['blocks'][0]['text']['type'], 'plain_text')
        self.assertIn('event-1', value['text'])


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for local TLS delivery fixture')
class DeliveryTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.temp.name) / 'cert.pem'
        key = Path(cls.temp.name) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       capture_output=True, check=True)
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

    def test_real_tls_json_delivery(self):
        data = {'text': 'Quotes " and newlines\nremain JSON'}
        self.assertTrue(post_json(self.url + '/accepted', data, str(self.cert)))
        self.assertEqual(self.server.received, data)

    def test_rate_limit_is_not_acknowledgement(self):
        self.assertFalse(post_json(self.url + '/limited', {'text': 'test'}, str(self.cert)))

    def test_redirect_is_not_followed(self):
        self.assertFalse(post_json(self.url + '/redirect', {'text': 'test'}, str(self.cert)))
