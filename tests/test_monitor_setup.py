import hashlib
import unittest
from companion.monitor_setup import endpoint_configuration, service_configuration


class MonitorSetupTests(unittest.TestCase):
    def test_initial_origin_and_registered_database_checks_are_replayable(self):
        health = 'companion-origin-' + 'a' * 32 + '.php'
        result = endpoint_configuration(None, 'shop.example.com', health, 'shopdb')
        self.assertEqual(len(result['targets']), 2)
        self.assertTrue(all(row['connect_host'] == '127.0.0.1' for row in result['targets']))
        self.assertEqual(result['targets'][1]['expected_json'], {
            'ready': True, 'database_identity': hashlib.sha256(b'shopdb').hexdigest()})
        self.assertEqual(endpoint_configuration(result, 'shop.example.com', health, 'shopdb'), result)

    def test_existing_names_timeouts_and_extra_expectations_are_preserved(self):
        health = 'companion-origin-' + 'b' * 32 + '.php'
        original = {'failure_threshold': 3, 'targets': [
            {'name': 'Public edge', 'url': 'https://shop.example.com/', 'timeout': 12},
            {'name': 'Application', 'url': 'https://shop.example.com/' + health,
             'connect_host': '127.0.0.1', 'expected_json': {'ready': True, 'timestamp_validation': True}}]}
        result = endpoint_configuration(original, 'shop.example.com', health, 'shopdb')
        self.assertEqual(result['failure_threshold'], 3)
        self.assertEqual(result['targets'][0], original['targets'][0])
        self.assertEqual(result['targets'][1]['name'], 'Application')
        self.assertTrue(result['targets'][1]['expected_json']['timestamp_validation'])
        self.assertNotIn('database_identity', original['targets'][1]['expected_json'])
        self.assertEqual(len(result['targets']), 3)

    def test_conflicting_application_checks_are_not_silently_replaced(self):
        health = 'companion-origin-' + 'c' * 32 + '.php'
        for fields in ({'expected_statuses': [200, 503]}, {'expected_json': {'ready': False}},
                       {'expected_json': {'database_identity': 'another-database'}},
                       {'expected_json': {'ready': 1}}):
            existing = {'targets': [{'name': 'Existing', 'url': 'https://shop.example.com/' + health,
                                     'connect_host': '127.0.0.1', **fields}]}
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                endpoint_configuration(existing, 'shop.example.com', health, 'shopdb')

    def test_invalid_health_and_foreign_names_refuse(self):
        for health in ('../wp-config.php', 'companion-origin-not-registered.php'):
            with self.subTest(health=health), self.assertRaises(ValueError):
                endpoint_configuration(None, 'shop.example.com', health, 'shopdb')
        with self.assertRaises(ValueError):
            endpoint_configuration({'targets': [{'name': 'shop.example.com: origin HTML',
                                                 'url': 'https://another.example.com/'}]}, 'shop.example.com')

    def test_website_certificate_authority_is_added_and_removed_on_origin_checks_only(self):
        import copy
        from companion.monitor_setup import origin_trust_pending
        health = 'companion-origin-' + 'd' * 32 + '.php'
        managed = '/etc/cloudpanel-companion/site-ca-shop.example.com.crt'
        original = endpoint_configuration(None, 'shop.example.com', health, 'shopdb')
        original['targets'] += [{'name': 'Public edge', 'url': 'https://shop.example.com/'},
                                {'name': 'Other site', 'url': 'https://other.example.com/', 'connect_host': '127.0.0.1'}]
        trusted = endpoint_configuration(original, 'shop.example.com', health, 'shopdb', site_ca=True)
        expected = copy.deepcopy(original)
        for target in expected['targets'][:2]:
            target['ca_file'] = managed
        self.assertEqual(trusted, expected)
        self.assertTrue(origin_trust_pending(original, 'shop.example.com', True))
        self.assertFalse(origin_trust_pending(trusted, 'shop.example.com', True))
        self.assertEqual(endpoint_configuration(trusted, 'shop.example.com', health, 'shopdb', site_ca=True), trusted)
        # Removed: back to the system store, nothing else changes.
        self.assertTrue(origin_trust_pending(trusted, 'shop.example.com', False))
        self.assertEqual(endpoint_configuration(trusted, 'shop.example.com', health, 'shopdb'), original)

    def test_operator_certificate_authority_on_an_origin_check_is_kept_or_conflicts(self):
        from companion.monitor_setup import origin_trust_pending
        existing = {'targets': [{'name': 'Own trust', 'url': 'https://shop.example.com/', 'connect_host': '127.0.0.1',
                                 'ca_file': '/etc/ssl/own-origin.pem'}]}
        self.assertEqual(endpoint_configuration(existing, 'shop.example.com'), existing)
        self.assertFalse(origin_trust_pending(existing, 'shop.example.com', False))
        self.assertTrue(origin_trust_pending(existing, 'shop.example.com', True))
        with self.assertRaises(ValueError):
            endpoint_configuration(existing, 'shop.example.com', site_ca=True)

    def test_service_replay_preserves_deliberately_disabled_recovery(self):
        current = {'units': [{'name': 'nginx.service', 'label': 'My web service', 'recover': False}]}
        candidates = [('nginx.service', 'Nginx'), ('php8.3-fpm.service', 'PHP')]
        result = service_configuration(current, candidates, True)
        self.assertEqual(result['units'][0], current['units'][0])
        self.assertTrue(result['units'][1]['recover'])
        self.assertEqual(service_configuration(result, candidates, True), result)
        self.assertFalse(service_configuration(None, [('nginx.service', 'Web')])['units'][0]['recover'])

    def test_cloudpanel_php_is_its_own_service_not_a_stock_pool(self):
        # Earlier versions watched php8.1-fpm as "CloudPanel PHP"; CloudPanel runs on
        # clp-php-fpm, and an unused stock PHP version may be disabled on purpose.
        from pathlib import Path
        source = (Path(__file__).resolve().parents[1] / 'install-monitor.py').read_text()
        self.assertIn("('clp-php-fpm.service', 'CloudPanel PHP')", source)
        self.assertNotIn('php8.1-fpm', source)
        current = {'units': [{'name': 'php8.1-fpm.service', 'label': 'shop.example.com: CloudPanel PHP', 'recover': False},
                             {'name': 'nginx.service', 'label': 'shop.example.com: Nginx', 'recover': True}]}
        candidates = [('nginx.service', 'shop.example.com: Nginx'), ('clp-php-fpm.service', 'shop.example.com: CloudPanel PHP')]
        result = service_configuration(current, candidates, True)
        self.assertEqual(result['units'], [
            {'name': 'clp-php-fpm.service', 'label': 'shop.example.com: CloudPanel PHP', 'recover': False},
            {'name': 'nginx.service', 'label': 'shop.example.com: Nginx', 'recover': True}])
        self.assertEqual(service_configuration(result, candidates, True), result)
        # A php8.1-fpm entry the operator labelled themselves is theirs and stays.
        own = {'units': [{'name': 'php8.1-fpm.service', 'label': 'Legacy shop PHP', 'recover': True}]}
        self.assertEqual(service_configuration(own, candidates)['units'][0], own['units'][0])

    def test_service_conflicts_and_limits_fail_before_publication(self):
        with self.assertRaises(ValueError):
            service_configuration({'units': [{'name': 'nginx.service', 'label': 'PHP', 'recover': False}]},
                                  [('php8.3-fpm.service', 'PHP')])
        with self.assertRaises(ValueError):
            service_configuration(None, [(f'unit-{number}.service', str(number)) for number in range(21)])
        with self.assertRaises(ValueError):
            service_configuration(None, [('not a service; reboot', 'Bad')])

    def test_long_valid_hostname_does_not_overflow_monitor_names(self):
        host = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'com'])
        result = endpoint_configuration(None, host)
        self.assertLessEqual(len(result['targets'][0]['name']), 128)
        self.assertEqual(result['targets'][0]['url'], 'https://' + host + '/')
