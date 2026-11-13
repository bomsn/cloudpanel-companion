import json
from pathlib import Path
import tempfile
import unittest
from companion_web.monitoring import (attention, bars, chart, disk, endpoints, mail, presentation, resources,
                                      services, sparkline, usage, wordpress)


def unit(name, label, state, **values):
    return {'unit': name, 'name': label, 'state': state, 'healthy': state in ('active', 'reloading'), 'since': 1000,
            'recovery_enabled': True, 'attempted_recovery': False, **values}


def job(name, **values):
    return {'unit': name, 'service': name.replace('.timer', '.service'), 'name': 'Scheduled job', 'enabled': True,
            'scheduled': True, 'running': False, 'last_run': 1000, 'result': 'success', 'next_run': 1060, 'healthy': True, **values}


class MonitoringPresentationTests(unittest.TestCase):
    def test_missing_intervals_break_the_line(self):
        value = chart([{'at': 60, 'cpu': 10}, {'at': 120, 'cpu': None}, {'at': 180, 'cpu': 30}],
                      'cpu', 'CPU use', '%', 'Measured CPU', 60, 100)
        self.assertEqual(len(value['segments']), 2)
        self.assertEqual(value['points'], 2)
        self.assertEqual(value['latest'], '30.0')

    def test_sparkline_keeps_gaps_and_reports_its_range(self):
        trend = sparkline([{'at': 0, 'cpu': 10}, {'at': 300, 'cpu': 50}, {'at': 600, 'cpu': None}, {'at': 900, 'cpu': 30}],
                          'cpu', 300, 100)
        self.assertEqual(len(trend['segments']), 2)
        self.assertEqual((trend['low'], trend['high']), (10, 50))
        self.assertIsNone(sparkline([{'at': 0, 'cpu': 10}], 'cpu', 300, 100))

    def test_usage_bars_warn_at_80_and_alarm_at_90_percent(self):
        self.assertEqual([usage(used, 100)['tone'] for used in (79, 80, 90)], ['', 'warning', 'danger'])
        self.assertEqual(usage(31, 200)['percent'], 16)
        self.assertIsNone(usage(5, None))
        self.assertIsNone(usage(5, 0))

    def test_overview_tiles_use_the_24_hour_window_only_when_history_exists(self):
        current = {'cpus': 2, 'load': [0.5, 0.4, 0.3], 'memory_total': 1000, 'memory_available': 150,
                   'swap_used': 10, 'disk_total': 100, 'disk_free': 40}
        points = [{'at': at, 'load': 0.5, 'memory': 50, 'disk': 60, 'swap_bytes': 10} for at in (0, 300, 600)]
        tiles = resources(current, {'windows': {'24h': {'points': points}}})
        self.assertEqual((tiles['memory']['bar']['percent'], tiles['memory']['bar']['tone']), (85, 'warning'))
        self.assertEqual(tiles['disk']['bar']['percent'], 60)
        self.assertIsNotNone(tiles['memory']['trend'])
        # Without a known swap size there is no swap bar or trend, only the amount in use.
        self.assertIsNone(tiles['swap']['bar'])
        self.assertIsNone(tiles['swap']['trend'])
        self.assertIsNone(resources(current, {})['load']['trend'])
        self.assertIsNone(resources(None, {}))

    def test_bars_share_one_scale_and_keep_small_values_visible(self):
        chart = bars([0, 1, 100], ['Mon', 'Tue', 'Wed'])
        self.assertEqual([bar['height'] for bar in chart['bars']], ['0.0', '1.5', '60.0'])
        self.assertEqual([bar['label'] for bar in chart['bars']], ['Mon', 'Tue', 'Wed'])
        self.assertEqual(bars([0, 0], ['a', 'b'])['peak'], 0)

    def test_chart_summary_is_the_same_intervals_as_the_line(self):
        value = chart([{'at': 60, 'origin_ms': 100}, {'at': 120, 'origin_ms': 400}, {'at': 180, 'origin_ms': 100}],
                      'origin_ms', 'Uncached response time', 'ms', 'Measured', 60)
        self.assertEqual((value['average'], value['peak'], value['suffix']), ('200.0', '400.0', ' ms'))
        self.assertEqual(value['peak_at'].timestamp(), 120)

    def test_missing_export_has_no_health_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(presentation(Path(directory) / 'absent.json')['history'])

    def test_private_bypasses_do_not_reduce_public_hit_rate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.json'
            routes = [{'route': 'home', 'count': 100, 'hits': 3, 'misses': 1, 'errors': 0, 'timed': 97,
                       'typical_ms': 120.0, 'slowest_ms': 900.0}]
            path.write_text(json.dumps({'observed_at': 100, 'started_at': 100, 'latest': {}, 'windows': {
                '1h': {'points': [], 'routes': routes, 'errors': [], 'gaps': 0, 'sample_count': 1}}}))
            value = presentation(path, now=100)
            self.assertEqual(value['cache_percent'], 75)
            self.assertEqual(value['request_count'], 100)
            # Each page type's own share counts every request it received.
            self.assertEqual(value['routes'][0]['cache_share'], 3)

    def test_stale_history_and_unavailable_counters_remain_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.json'
            path.write_text(json.dumps({'observed_at': 100, 'started_at': 100, 'latest': {}, 'windows': {
                '1h': {'points': [], 'routes': [], 'errors': [], 'gaps': 0, 'sample_count': 1}}}))
            value = presentation(path, now=400)
            self.assertTrue(value['stale'])
            self.assertIsNone(value['latest']['opcache_free'])
            self.assertIsNone(value['cache_percent'])
            self.assertEqual(value['findings'], [])

    def test_services_are_grouped_by_scope_with_product_names_and_truthful_states(self):
        watched = services({'services': [
            unit('nginx.service', 'shop.example.com: Nginx', 'active'),
            unit('companion-web.service', 'shop.example.com: Companion interface', 'active'),
            unit('mariadb.service', 'shop.example.com: Database service', 'failed'),
            unit('php8.3-fpm.service', 'shop.example.com: Website PHP', 'active'),
            unit('companion-redis-shop.service', 'shop.example.com: Website object cache', 'active'),
            unit('varnish.service', 'shop.example.com: Page cache', 'not-installed'),
            unit('clp-php-fpm.service', 'shop.example.com: CloudPanel PHP', 'active'),
            unit('companion-relay@shopstg.service', 'shop.example.com: Staging test transport', 'active'),
            unit('ssh.service', 'My SSH', 'inactive')], 'scheduled': [
            job('companion-monitor.timer'),
            job('companion-telemetry.timer', result='exit-code', healthy=False),
            job('companion-delivery.timer', result='skipped'),
            job('companion-retention.timer', enabled=False, scheduled=False, next_run=None),
            job('companion-system-watch.timer', running=True, result=None, next_run=None)]}, 'shop.example.com')
        # The website's own units come first under its domain, then the server's shared
        # services by kind, then the Companion's components; jobs are their own group.
        self.assertEqual([(group['title'], group['role'], group['icon'], group['anchor']) for group in watched['groups']], [
            ('shop.example.com', 'Website', 'globe', 'services-site'), ('Web server and PHP', None, 'server', 'services-web'),
            ('Database', None, 'database', 'services-database'), ('Caches', None, 'zap', 'services-cache'),
            ('Other services', None, 'server', 'services-other'),
            ('Companion services', None, 'layers', 'services-companion')])
        # Rows carry the product's own name and icon, never the registered label's domain prefix.
        self.assertEqual([[(row['title'], row['icon']) for row in group['rows']] for group in watched['groups']], [
            [('Redis', 'redis'), ('Staging email and test requests', 'send')],
            [('NGINX', 'nginx'), ('PHP-FPM 8.3', 'php'), ('CloudPanel (PHP-FPM)', 'php')],
            [('MariaDB', 'mariadb')], [('Varnish Cache', 'zap')], [('My SSH', 'server')], [('Web interface', 'layout-dashboard')]])
        rows = {row['unit']: row for group in watched['groups'] for row in group['rows']}
        self.assertEqual(rows['nginx.service']['label'], 'Running')
        self.assertEqual(rows['mariadb.service']['label'], 'Failed')
        self.assertEqual(rows['varnish.service']['label'], 'Not installed')
        # An operator's own unit keeps its label.
        self.assertEqual(rows['ssh.service']['label'], 'Stopped')
        self.assertEqual((watched['jobs']['title'], watched['jobs']['icon'], watched['jobs']['anchor']),
                         ('Scheduled jobs', 'timer', 'scheduled-jobs'))
        self.assertEqual([(item['title'], item['icon'], item['label']) for item in watched['jobs']['rows']], [
            ('Website and certificate checks', 'timer', 'Succeeded'), ('Performance history', 'timer', 'Failed'),
            ('Website alerts to Slack', 'timer', 'Skipped'), ('Staging cleanup', 'timer', 'Off'),
            ('Service checks', 'timer', 'Running now')])
        # Attention items name the product, carry its icon and link to its group.
        found = attention([], watched, None, None, None, 0)['problems']
        self.assertEqual([(item['icon'], item['text'], item['link']) for item in found], [
            ('mariadb', 'MariaDB: failed.', '/monitoring/#services-database'),
            ('zap', 'Varnish Cache: not installed.', '/monitoring/#services-cache'),
            ('server', 'My SSH: stopped.', '/monitoring/#services-other'),
            ('timer', 'Scheduled job "Performance history": failed.', '/monitoring/#scheduled-jobs')])

    def test_endpoints_are_grouped_by_domain_with_plain_names(self):
        checks = [{'name': 'shop.example.com: page HTML', 'host': 'shop.example.com', 'healthy': True, 'category': 'healthy',
                   'status': 200, 'elapsed_ms': 90, 'certificate_days': 80},
                  {'name': 'panel.example.com: certificate', 'host': 'panel.example.com', 'healthy': True,
                   'category': 'certificate-expiring', 'status': None, 'elapsed_ms': 8, 'certificate_days': 9},
                  {'name': 'shop.example.com: application and database', 'host': 'shop.example.com', 'healthy': False,
                   'category': 'application-check-failed', 'status': 200, 'elapsed_ms': 300, 'certificate_days': 80}]
        groups = endpoints(checks, {'shop.example.com': 'Website', 'ops.example.com': 'Companion',
                                    'panel.example.com': 'CloudPanel'})
        self.assertEqual([(group['host'], group['role']) for group in groups],
                         [('shop.example.com', 'Website'), ('panel.example.com', 'CloudPanel')])
        self.assertEqual([row['title'] for row in groups[0]['rows']], ['Page HTML', 'Application and database'])
        self.assertEqual(groups[0]['rows'][1]['result'], 'WordPress or database check failed, HTTP 200')
        self.assertEqual(groups[1]['rows'][0]['title'], 'Certificate')
        self.assertTrue(groups[1]['rows'][0]['attention'])

    def test_overview_attention_lists_what_needs_the_operator_worst_first(self):
        checks = endpoints([{'name': 'ops.example.com: certificate', 'host': 'ops.example.com', 'healthy': True,
                             'category': 'certificate-expiring', 'status': None, 'elapsed_ms': 5, 'certificate_days': 6},
                            {'name': 'panel.example.com: certificate', 'host': 'panel.example.com', 'healthy': True,
                             'category': 'certificate-expiring', 'status': None, 'elapsed_ms': 5, 'certificate_days': 18}], {})
        watched = services({'services': [], 'scheduled': [job('companion-telemetry.timer', result='timeout', healthy=False)]},
                           'shop.example.com')
        queue = mail({'available': True, 'count': 18, 'complete': True, 'oldest_at': 1000, 'stuck': True, 'stuck_after': 3600})
        trend = disk({'since': 0, 'growth': 7 * 1024 ** 3, 'free': 10 * 1024 ** 3, 'full_at': 10 * 86400}, 0)
        site = wordpress({'checked_at': 0, 'available': True, 'core': {'version': '6.8.1', 'update': None},
                          'plugins': [{'name': 'Forms', 'version': '2', 'update': '3', 'package': False},
                                      {'name': 'Shop', 'version': '1', 'update': '2', 'package': True}],
                          'themes': [], 'updates_checked': 0, 'cron': {'overdue': 2, 'oldest': 0, 'hooks': [['a', 2]]}}, 0)
        found = attention(checks, watched, queue, trend, site, 1)
        self.assertEqual([item['tone'] for item in found['problems']], ['danger'] * 3 + ['warning'] * 4)
        text = ' '.join(item['text'] for item in found['problems'])
        for expected in ('Performance history', 'Mail is stuck: 18 messages waiting', '1 scheduled backup did not succeed',
                         'ops.example.com certificate expires in 6 days', 'The disk may be full by 11 January',
                         '1 update cannot install', '2 WordPress scheduled tasks are overdue'):
            self.assertIn(expected, text)
        # Available updates and a certificate still weeks from expiry are worth knowing, not problems.
        self.assertEqual([item['text'] for item in found['notes']],
                         ['The panel.example.com certificate expires in 18 days.', '1 WordPress update available.'])
        self.assertEqual(attention([], services({}, 'shop.example.com'), None, None, None, 0), {'problems': [], 'notes': []})
        self.assertEqual([item['tone'] for item in attention([], None, None, None, None, 0)['problems']], ['warning'])

    def test_disk_trend_states(self):
        day = 86400
        self.assertEqual(disk({'since': 0, 'growth': 0, 'free': 1, 'full_at': None}, 0)['state'], 'flat')
        self.assertEqual(disk({'since': 0, 'growth': 1, 'free': 1, 'full_at': 400 * day}, 0)['state'], 'slow')
        growing = disk({'since': 0, 'growth': 1, 'free': 1, 'full_at': 60 * day}, 0)
        self.assertEqual((growing['state'], growing['soon']), ('growing', False))
        self.assertIsNone(disk(None, 0))

    def test_wordpress_counts_updates_that_cannot_install(self):
        site = wordpress({'checked_at': 0, 'available': True, 'core': {'version': '6.8.1', 'update': '6.8.3'},
                          'plugins': [{'name': 'Forms', 'version': '2', 'update': '3', 'package': False}],
                          'themes': [{'name': 'Shop theme', 'version': '1', 'update': '2', 'package': True}],
                          'updates_checked': None, 'cron': {'overdue': 0, 'oldest': None, 'hooks': []}}, 10000)
        self.assertEqual([(item['kind'], item['name']) for item in site['updates']],
                         [('Core', 'WordPress'), ('Plugin', 'Forms'), ('Theme', 'Shop theme')])
        self.assertEqual(site['blocked'], 1)
        self.assertTrue(site['stale'])
        unreadable = wordpress({'checked_at': 0, 'available': False}, 0)
        self.assertFalse(unreadable['available'])
        self.assertIn('WordPress health could not be read.', [item['text'] for item in attention([], services({}, 'shop.example.com'), None, None, unreadable, 0)['problems']])


if __name__ == '__main__':
    unittest.main()
