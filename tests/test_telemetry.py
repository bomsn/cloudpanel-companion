import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest
from companion.telemetry import aggregate, cpu_delta, error_groups, export, request_groups, tail


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

    def test_cache_split_and_estimated_percentile(self):
        rows = [json.dumps({'route': 'product', 'status': 200, 'cache': cache, 'upstream': duration})
                for cache, duration in [('HIT', '0.001'), ('MISS', '1.000'), ('MISS', '3.000')]]
        requests, invalid = request_groups(rows)
        self.assertEqual(invalid, 0)
        groups, errors = aggregate([{'requests': requests}])
        miss = next(item for item in groups if item['cache'] == 'MISS')
        self.assertEqual(miss['mean_ms'], 2000)
        self.assertTrue(3000 <= miss['p95_ms'] <= 3300)
        self.assertEqual(errors, [])

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
