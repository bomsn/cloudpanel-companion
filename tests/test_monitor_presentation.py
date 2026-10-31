import json
from pathlib import Path
import tempfile
import unittest
from companion_web.monitoring import chart, presentation


class MonitoringPresentationTests(unittest.TestCase):
    def test_missing_intervals_break_the_line(self):
        value = chart([{'at': 60, 'cpu': 10}, {'at': 120, 'cpu': None}, {'at': 180, 'cpu': 30}],
                      'cpu', 'CPU use', '%', 'Measured CPU', 60, 100)
        self.assertEqual(len(value['segments']), 2)
        self.assertEqual(value['points'], 2)
        self.assertEqual(value['latest'], '30.0')

    def test_missing_export_has_no_health_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(presentation(Path(directory) / 'absent.json')['history'])

    def test_private_bypasses_do_not_reduce_public_hit_rate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.json'
            routes = [{'cache': cache, 'count': count, 'errors': 0} for cache,count in [('HIT', 3), ('MISS', 1), ('BYPASS', 96)]]
            path.write_text(json.dumps({'observed_at': 100, 'started_at': 100, 'latest': {}, 'windows': {
                '1h': {'points': [], 'routes': routes, 'errors': [], 'gaps': 0, 'sample_count': 1}}}))
            value = presentation(path, now=100)
            self.assertEqual(value['cache_percent'], 75)
            self.assertEqual(value['request_count'], 100)

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
