import base64
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from companion.relay import default_policy, destination, normalize_policy, permitted, public_addresses, capture_mail


class RelayTests(unittest.TestCase):
    def policy(self):
        result = default_policy()
        result.update(http_enabled=True, http_rules=[{'host': 'example.com', 'path': '/test', 'methods': ['GET']}])
        return normalize_policy(result, {'live.example.com'})

    def test_defaults_and_independent_http_webhook_switches(self):
        policy = default_policy()
        self.assertFalse(permitted(policy, 'https://example.com/test', 'GET'))
        policy = self.policy()
        self.assertTrue(permitted(policy, 'https://example.com/test/item?value=1', 'GET'))
        self.assertFalse(permitted(policy, 'https://example.com/test-other', 'GET'))
        self.assertFalse(permitted(policy, 'https://example.com/test', 'POST'))
        policy.update(http_enabled=False, webhooks_enabled=True, webhook_rules=[{'host': 'example.com', 'path': '/hook', 'methods': ['POST']}])
        self.assertTrue(permitted(policy, 'https://example.com/hook', 'POST'))
        self.assertFalse(permitted(policy, 'https://example.com/test', 'GET'))

    def test_ambiguous_or_non_https_destinations_fail_closed(self):
        for url in ['http://example.com/test', 'https://user:secret@example.com/test', 'https://example.com:444/test',
                    'https://example.com/test/../live', 'https://example.com/test/%2e%2e/live',
                    'https://example.com//test', 'https://example.com/test#fragment', 'https://127.0.0.1/test']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                destination(url)

    def test_live_hostnames_and_empty_enabled_rules_are_refused(self):
        policy = self.policy()
        policy['http_rules'][0]['host'] = 'live.example.com'
        with self.assertRaises(ValueError):
            normalize_policy(policy, {'live.example.com'})
        policy['http_rules'] = []
        with self.assertRaises(ValueError):
            normalize_policy(policy, set())

    def test_all_dns_answers_must_be_public(self):
        for addresses in [('127.0.0.1',), ('10.1.2.3',), ('169.254.169.254',), ('100.64.0.1',), ('::1',), ('::ffff:127.0.0.1',), ('224.0.0.1',), ('8.8.8.8', '192.168.0.1')]:
            answers = [(socket.AF_INET6 if ':' in value else socket.AF_INET, socket.SOCK_STREAM, 6, '', (value, 443)) for value in addresses]
            with self.subTest(addresses=addresses), patch('socket.getaddrinfo', return_value=answers), self.assertRaises(ValueError):
                public_addresses('example.com')
        with patch('socket.getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]):
            self.assertEqual(public_addresses('example.com'), ['8.8.8.8'])

    def test_email_capture_requires_every_approved_recipient(self):
        policy = default_policy()
        message = {'recipients': ['test@example.com'], 'subject': 'Test', 'body': '<script>escaped by UI</script>'}
        with tempfile.TemporaryDirectory() as directory:
            inbox = Path(directory) / 'mail'
            with self.assertRaises(ValueError):
                capture_mail(policy, message, inbox)
            policy.update(mail_enabled=True, mail_recipients=['test@example.com'])
            result = capture_mail(policy, message, inbox)
            self.assertEqual(json.loads((inbox / (result['id'] + '.json')).read_text())['body'], message['body'])
            message['recipients'].append('customer@example.com')
            with self.assertRaises(ValueError):
                capture_mail(policy, message, inbox)

    def test_capture_storage_is_bounded_before_writing(self):
        policy = default_policy()
        policy.update(mail_enabled=True, mail_recipients=['test@example.com'])
        message = {'recipients': ['test@example.com'], 'subject': 'Test', 'body': 'x' * 200000}
        with tempfile.TemporaryDirectory() as directory:
            inbox = Path(directory) / 'mail'
            for _ in range(55):
                capture_mail(policy, message, inbox)
            files = list(inbox.glob('*.json'))
            self.assertLessEqual(len(files), 50)
            self.assertLessEqual(sum(path.stat().st_size for path in files), 8 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
