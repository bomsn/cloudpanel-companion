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
            endpoint_configuration({'targets': [{'name': 'shop.example.com: page HTML',
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
        from companion.monitor_setup import service_profile
        source = (Path(__file__).resolve().parents[1] / 'install-monitor.py').read_text()
        self.assertIn("'clp-php-fpm.service'", source)
        self.assertNotIn('php8.1-fpm', source)
        # New registrations are labelled from the catalog; the corrected unit keeps its legacy label and choice.
        self.assertEqual(service_profile('clp-php-fpm.service')[1], 'CloudPanel (PHP-FPM)')
        current = {'units': [{'name': 'php8.1-fpm.service', 'label': 'shop.example.com: CloudPanel PHP', 'recover': False},
                             {'name': 'nginx.service', 'label': 'shop.example.com: Nginx', 'recover': True}]}
        candidates = [('nginx.service', 'shop.example.com: NGINX'),
                      ('clp-php-fpm.service', 'shop.example.com: CloudPanel (PHP-FPM)')]
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

    def test_interface_and_panel_certificates_are_watched_without_page_requests(self):
        from companion.monitor_setup import certificate_hosts, certificates_pending
        hosts = certificate_hosts({'host': 'ops.example.com', 'panel_url': 'https://panel.example.com'})
        self.assertEqual(hosts, ['ops.example.com', 'panel.example.com'])
        # A panel reached by address or on its own port has no domain certificate to watch.
        self.assertEqual(certificate_hosts({'host': 'ops.example.com', 'panel_url': 'https://203.0.113.4:8443'}),
                         ['ops.example.com'])
        result = endpoint_configuration(None, 'shop.example.com', certificates=hosts)
        watched = [target for target in result['targets'] if target.get('certificate_only')]
        self.assertEqual([(target['name'], target['url'], target['connect_host']) for target in watched], [
            ('ops.example.com: certificate', 'https://ops.example.com/', '127.0.0.1'),
            ('panel.example.com: certificate', 'https://panel.example.com/', '127.0.0.1')])
        self.assertEqual(endpoint_configuration(result, 'shop.example.com', certificates=hosts), result)
        self.assertFalse(certificates_pending(result, hosts))
        self.assertTrue(certificates_pending(endpoint_configuration(None, 'shop.example.com'), hosts))
        # An operator's own page check on the same address is a different check and stays.
        own = {'targets': [{'name': 'Panel sign-in', 'url': 'https://panel.example.com/', 'connect_host': '127.0.0.1',
                            'expected_statuses': [302]}]}
        merged = endpoint_configuration(own, 'shop.example.com', certificates=hosts)
        self.assertIn(own['targets'][0], merged['targets'])
        self.assertTrue(any(target['name'] == 'panel.example.com: certificate' for target in merged['targets']))

    def test_earlier_page_check_name_is_renamed_in_place(self):
        earlier = {'failure_threshold': 2, 'targets': [{'name': 'shop.example.com: origin HTML', 'url': 'https://shop.example.com/',
                                                        'connect_host': '127.0.0.1', 'expected_statuses': [200]}]}
        result = endpoint_configuration(earlier, 'shop.example.com')
        self.assertEqual([target['name'] for target in result['targets']], ['shop.example.com: page HTML'])
        # An operator's own name for the same check is theirs and stays.
        earlier['targets'][0]['name'] = 'Homepage'
        self.assertEqual(endpoint_configuration(earlier, 'shop.example.com')['targets'][0]['name'], 'Homepage')

    def test_every_registered_and_scheduled_unit_is_described(self):
        from pathlib import Path
        from companion.monitor_setup import SERVICE_GROUPS, TIMERS, service_profile
        # The service watch and package updates use this catalog; it must name every timer the package ships.
        assets = Path(__file__).resolve().parents[1] / 'assets'
        self.assertEqual(set(TIMERS), {path.name for path in assets.glob('*.timer')})
        sprite = (Path(__file__).resolve().parents[1] / 'companion_web/static/icons.svg').read_text()
        groups = {group for group, _, _ in SERVICE_GROUPS}
        for unit in ('nginx.service', 'clp-php-fpm.service', 'php8.3-fpm.service', 'mariadb.service', 'mysql.service',
                     'varnish.service', 'cache-manager-control.service', 'companion-redis-shop.service',
                     'companion-web.service', 'companion-security-cache.service', 'companion-operations.service',
                     'companion-relay@shopstg.service', 'fail2ban.service', *TIMERS):
            with self.subTest(unit=unit):
                group, title, icon, description = service_profile(unit)
                self.assertIn(group, groups - {'other'})
                self.assertTrue(title and description.endswith('.'))
                self.assertIn(f'<symbol id="{icon}" ', sprite)
        self.assertEqual(service_profile('ssh.service'), ('other', None, 'server', None))
        for group, _, icon in SERVICE_GROUPS:
            self.assertIn(f'<symbol id="{icon}" ', sprite)

    def test_catalog_uses_each_products_own_name_scope_and_mark(self):
        from pathlib import Path
        from companion.monitor_setup import service_profile
        expected = {'nginx.service': ('web', 'NGINX', 'nginx'), 'php8.3-fpm.service': ('web', 'PHP-FPM 8.3', 'php'),
                    'php8.4-fpm.service': ('web', 'PHP-FPM 8.4', 'php'),
                    'clp-php-fpm.service': ('web', 'CloudPanel (PHP-FPM)', 'php'),
                    'mariadb.service': ('database', 'MariaDB', 'mariadb'), 'mysql.service': ('database', 'MySQL', 'mysql'),
                    'varnish.service': ('cache', 'Varnish Cache', 'zap'), 'fail2ban.service': ('protection', 'Fail2ban', 'shield'),
                    # Installed per website: its private Redis and its staging copy's relay.
                    'companion-redis-shop.service': ('site', 'Redis', 'redis'),
                    'companion-relay@shopstg.service': ('site', 'Staging email and test requests', 'send'),
                    'companion-web.service': ('companion', 'Web interface', 'layout-dashboard')}
        for unit, profile in expected.items():
            with self.subTest(unit=unit):
                self.assertEqual(service_profile(unit)[:3], profile)
        # A brand mark is one filled shape in the text colour, sized like the outline icons beside it.
        sprite = (Path(__file__).resolve().parents[1] / 'companion_web/static/icons.svg').read_text()
        for mark in ('nginx', 'php', 'mysql', 'mariadb', 'redis'):
            with self.subTest(mark=mark):
                symbol = sprite.split(f'<symbol id="{mark}" viewBox="0 0 24 24">', 1)[1].split('</symbol>', 1)[0]
                self.assertEqual(symbol.count('<path '), 1)
                self.assertIn('fill="currentColor" stroke="none"', symbol)
