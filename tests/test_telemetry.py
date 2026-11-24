import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
from companion import telemetry
from companion.telemetry import cpu_delta, error_groups, export, request_groups, tail


class TelemetryTests(unittest.TestCase):
    def test_cpu_counter_delta_and_reset(self):
        self.assertEqual(cpu_delta([0]*8, [20, 0, 10, 50, 20, 0, 0, 0]), (30, 20))
        self.assertEqual(cpu_delta([1]*8, [0]*8), (None, None))
        self.assertEqual(cpu_delta(None, [1]*8), (None, None))

    def test_log_starts_now_then_follows_rotation_without_identity_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            path.write_text('historical\n')
            rows, cursor, gap = tail(path, None)
            self.assertEqual((rows, gap), ([], 0))
            with path.open('a') as stream:
                stream.write('before rotation\n')
            path.rename(Path(str(path) + '.1'))
            path.write_text('after rotation\npartial')
            rows, cursor, gap = tail(path, cursor)
            self.assertEqual(rows, ['before rotation', 'after rotation'])
            self.assertEqual(gap, 0)
            with path.open('a') as stream:
                stream.write(' line\n')
            self.assertEqual(tail(path, cursor)[0], ['partial line'])

    def test_one_row_per_page_type_timing_only_uncached_requests(self):
        rows = [json.dumps({'route': 'product', 'status': status, 'cache': cache, 'upstream': duration})
                for cache, duration, status in [('HIT', '0.001', 200), ('MISS', '1.000', 200), ('BYPASS', '3.000', 502)]]
        requests, invalid = request_groups(rows)
        self.assertEqual(invalid, 0)
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE samples(at INTEGER PRIMARY KEY,payload TEXT NOT NULL)')
            db.execute('INSERT INTO samples VALUES(?,?)', (60, json.dumps({'requests': requests})))
            db.execute('INSERT INTO samples VALUES(?,?)', (120, json.dumps({'requests': request_groups(rows[:1])[0]})))
            window = export(db, 300)['windows']['1h']
        self.assertEqual(len(window['routes']), 1)
        product = window['routes'][0]
        self.assertEqual((product['count'], product['hits'], product['misses'], product['errors']), (4, 2, 1, 1))
        # The cache hits' 1 ms never lowers the uncached timings.
        self.assertEqual(product['timed'], 2)
        self.assertTrue(1000 <= product['typical_ms'] <= 1100)
        self.assertTrue(3000 <= product['slowest_ms'] <= 3300)
        self.assertEqual(window['errors'], [])

    def test_cloudpanel_dated_rotation_preserves_unread_lines_once(self):
        for day in (0, -1, 1):
            with self.subTest(date_offset=day), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'error.log'
                path.write_text('old history\n')
                _, cursor, _ = tail(path, None)
                with path.open('a') as stream:
                    stream.write('just before midnight\n')
                date = datetime.now(timezone.utc).date() + timedelta(days=day)
                path.rename(Path(str(path) + '-' + str(date)))
                path.write_text('after midnight\n')
                rows, cursor, gap = tail(path, cursor)
                self.assertEqual(rows, ['just before midnight', 'after midnight'])
                self.assertEqual(gap, 0)
                self.assertEqual(tail(path, cursor)[0], [])

    def test_missing_or_linked_rotation_is_an_explicit_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'error.log'
            path.write_text('history\n')
            _, cursor, _ = tail(path, None)
            old = Path(directory) / 'unregistered-old-log'
            path.rename(old)
            Path(str(path) + '.1').symlink_to(old)
            path.write_text('new log\n')
            rows, _, gap = tail(path, cursor)
            self.assertEqual(rows, ['new log'])
            self.assertEqual(gap, 1)

    def test_no_raw_error_data_is_exported(self):
        result = error_groups(['PHP Warning: secret customer@example.com /home/user/site/wp-content/plugins/test-plugin/file.php?token=private',
                               'upstream timed out for 1.2.3.4 at /account/customer'])
        self.assertEqual(result, {'PHP warning in plugin test-plugin': 1, 'Upstream timeout': 1})
        self.assertNotIn('secret', json.dumps(result))

    def test_history_has_gaps_and_never_fabricates_missing_samples(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE samples(at INTEGER PRIMARY KEY,payload TEXT NOT NULL)')
            db.executemany('INSERT INTO samples VALUES(?,?)', [(60, '{"cpu":10}'), (240, '{"cpu":30}')])
            data = export(db, 300)
            self.assertEqual(len(data['windows']['1h']['points']), 2)
            self.assertEqual(data['started_at'], 60)
            self.assertIsNone(data['windows']['1h']['points'][0]['php_queue'])

    def test_queue_peak_is_not_hidden_by_chart_averaging(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE samples(at INTEGER PRIMARY KEY,payload TEXT NOT NULL)')
            db.executemany('INSERT INTO samples VALUES(?,?)', [(60, '{"php_queue":0}'), (120, '{"php_queue":3}')])
            data = export(db, 300)
            self.assertEqual(data['windows']['24h']['points'][0]['php_queue'], 1.5)
            self.assertEqual(data['windows']['24h']['php_queue_max'], 3)

    def test_disk_trend_is_a_fitted_line_with_an_estimated_full_date(self):
        now, gigabyte = 8 * 86400, 1024 ** 3
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE samples(at INTEGER PRIMARY KEY,payload TEXT NOT NULL)')
            # Free space falls 1 GB a day, with one large clean-up in the middle.
            db.executemany('INSERT INTO samples VALUES(?,?)', [
                (at, json.dumps({'disk_free': 50 * gigabyte - at * gigabyte // 86400 + (5 * gigabyte if at == 4 * 86400 else 0)}))
                for at in range(now - 604800, now + 1, 3600)])
            trend = export(db, now)['disk_trend']
        self.assertAlmostEqual(trend['growth'] / gigabyte, 7, delta=0.2)
        self.assertEqual(trend['free'], 42 * gigabyte)
        self.assertAlmostEqual((trend['full_at'] - now) / 86400, 42, delta=1.5)
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE samples(at INTEGER PRIMARY KEY,payload TEXT NOT NULL)')
            db.executemany('INSERT INTO samples VALUES(?,?)', [(at, json.dumps({'disk_free': 9 * gigabyte}))
                                                               for at in range(now - 172800, now + 1, 600)])
            flat = export(db, now)['disk_trend']
            self.assertIsNone(flat['full_at'])
            self.assertEqual(flat['growth'], 0)
            # Less than a day of samples is not a trend.
            db.execute('DELETE FROM samples WHERE at<?', (now - 3600,))
            self.assertIsNone(export(db, now)['disk_trend'])

    def test_wordpress_health_is_read_through_the_site_pool_and_bounded(self):
        raw = {'core': {'version': '6.8.1', 'update': '6.8.3'},
               'plugins': [{'name': 'Forms' + 'x' * 300, 'version': '2.1', 'update': '3.0', 'package': False},
                           {'name': 'Shop', 'version': '1.0', 'update': '1.1', 'package': True}] + [
                   {'name': 'Plugin', 'version': '1', 'update': '2', 'package': True}] * 150,
               'themes': [], 'updates_checked': 1000,
               'cron': {'overdue': 3, 'oldest': 900, 'hooks': {'a': 1, 'b': 2, 'c': 0, 'd': 0, 'e': 0, 'f': 0}}}
        config = {'user': 'shop', 'host': 'shop.example.com', 'php': '8.3', 'wordpress_probe': '/home/shop/probe.php'}
        with mock.patch.object(telemetry, 'pool', return_value=('', 18001)), \
                mock.patch.object(telemetry, 'operator_file', side_effect=str), \
                mock.patch.object(telemetry, 'fastcgi_json', return_value=raw) as call:
            report = telemetry.wordpress_sample(config, 5000)
        # The site's own pool runs the probe for its own host; the threshold is the collector's.
        self.assertEqual(call.call_args.args, (18001, '/home/shop/probe.php', 'overdue=3600', 'shop.example.com'))
        self.assertTrue(report['available'])
        self.assertEqual(report['checked_at'], 5000)
        self.assertEqual(len(report['plugins']), 100)
        self.assertEqual(len(report['plugins'][0]['name']), 120)
        self.assertFalse(report['plugins'][0]['package'])
        self.assertEqual(report['cron']['hooks'][0], ('b', 2))
        self.assertEqual(len(report['cron']['hooks']), 5)
        for broken in ({'core': {}}, {**raw, 'plugins': 'many'}, {**raw, 'cron': {'overdue': '3', 'oldest': None, 'hooks': {}}}):
            with self.subTest(broken=broken), mock.patch.object(telemetry, 'pool', return_value=('', 18001)), \
                    mock.patch.object(telemetry, 'operator_file', side_effect=str), \
                    mock.patch.object(telemetry, 'fastcgi_json', return_value=broken):
                self.assertEqual(telemetry.wordpress_sample(config, 5000), {'checked_at': 5000, 'available': False})


@unittest.skipUnless(os.name == 'posix', 'Runs stand-in commands')
class CommandLinesTests(unittest.TestCase):
    def script(self, body):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = folder / 'command'
        path.write_text('#!/bin/sh\n' + body)
        path.chmod(0o700)
        return [str(path)]

    def test_lines_are_kept_up_to_the_limit_and_long_lines_are_skipped(self):
        command = self.script("echo '{\"n\": 1}'\nhead -c 300 /dev/zero | tr '\0' x; echo\necho '{\"n\": 2}'\nexit 3\n")
        self.assertEqual(telemetry.json_lines(command, 5, 10, lambda item: item['n'], 200), ([1, 2], False, 3))
        command = self.script("echo '{\"n\": 1}'\necho '{\"n\": 2}'\necho '{\"n\": 3}'\n")
        # Stopped at the limit on purpose: no exit status to judge.
        self.assertEqual(telemetry.json_lines(command, 5, 2, lambda item: item['n']), ([1, 2], False, None))
        self.assertEqual(telemetry.json_lines(command, 5, 3, lambda item: item['n']), ([1, 2, 3], True, 0))
        with self.assertRaises(ValueError):
            telemetry.json_lines(self.script('echo not-json\n'), 5, 10)

    def test_a_command_that_does_not_finish_is_killed_at_its_deadline(self):
        import time
        started = time.monotonic()
        with self.assertRaises(telemetry.subprocess.TimeoutExpired):
            telemetry.json_lines(self.script("echo '{\"n\": 1}'\nexec sleep 30\n"), 0.5, 10)
        self.assertLess(time.monotonic() - started, 5)
