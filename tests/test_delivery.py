import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from companion.delivery import context, context_values, post_json, payload, validate_webhook, write_context

WHERE = {'server': 'web-1', 'address': '203.0.113.10', 'site': 'shop.example.com'}


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
        value = payload(('event-1', 'Site <name>', 'down', 1, 0, '[]'), WHERE)
        self.assertFalse(value['mrkdwn'])
        self.assertEqual(value['blocks'][0]['text']['type'], 'plain_text')
        self.assertIn('event-1', value['text'])

    def test_every_message_names_the_server_and_website_first(self):
        details = json.dumps([['Account', 'deploy'], ['Source IP', '198.51.100.7'], ['Method', 'SSH key']])
        security = payload(('event-2', 'SSH sign-in from a new IP address: deploy from 198.51.100.7', 'security',
                            1794240000, 0, details), WHERE)
        self.assertEqual(security['text'], 'Security alert · web-1 (203.0.113.10) · shop.example.com: '
                                           'SSH sign-in from a new IP address: deploy from 198.51.100.7\nEvent: event-2')
        header, origin, event, listed, context = security['blocks']
        self.assertEqual(header['text']['text'], 'Security alert · shop.example.com')
        self.assertEqual([field['text'] for field in origin['fields']], ['Server: web-1 (203.0.113.10)', 'Website: shop.example.com'])
        self.assertEqual(event['text']['text'], 'SSH sign-in from a new IP address: deploy from 198.51.100.7')
        self.assertEqual([field['text'] for field in listed['fields']],
                         ['Account: deploy', 'Source IP: 198.51.100.7', 'Method: SSH key'])
        self.assertEqual(context['elements'][0]['text'], '09 Nov 2026, 16:00 UTC · Event event-2')
        # Service and website-check alerts carry the same origin, without a details block.
        down = payload(('event-3', 'shop.example.com: page HTML', 'down', 1794240000, 0, '[]'), WHERE)
        self.assertTrue(down['text'].startswith('Needs attention · web-1 (203.0.113.10) · shop.example.com: '))
        self.assertEqual([block['type'] for block in down['blocks']], ['header', 'section', 'section', 'context'])
        bare = payload(('event-4', 'Outgoing mail', 'down', 1794240000, 0, '[]'), {'server': 'web-1', 'address': '', 'site': ''})
        self.assertEqual([field['text'] for field in bare['blocks'][1]['fields']], ['Server: web-1'])

    def test_context_is_validated_and_falls_back_to_the_host_name(self):
        self.assertEqual(context_values('web-1', '2001:db8::10', 'shop.example.com')['address'], '2001:db8::10')
        for values in (('web 1', '', 'shop.example.com'), ('web-1', '203.0.113.300', 'shop.example.com'),
                       ('web-1', '', 'https://shop.example.com'), ('web-1', '2001:DB8::10', 'shop.example.com')):
            with self.subTest(values=values), self.assertRaises(ValueError):
                context_values(*values)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'alert-context.json'
            self.assertEqual(context(path), {'server': socket.gethostname()[:63], 'address': '', 'site': ''})
            if os.geteuid() == 0:
                write_context('web-1', '203.0.113.10', 'shop.example.com', path)
                self.assertEqual(context(path), WHERE)
                path.chmod(0o666)
            else:
                path.write_text(json.dumps(WHERE))
            # Only root's own, unwritable-by-others file is believed.
            self.assertEqual(context(path)['site'], '')


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
