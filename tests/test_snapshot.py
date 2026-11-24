import json
from pathlib import Path
import tempfile
import time
import unittest
from companion.health import Observation
from companion.incidents import IncidentStore
from companion.snapshot import export
from companion.snapshot import host_resources
from unittest.mock import patch


class SnapshotTests(unittest.TestCase):
    def test_unavailable_host_counters_do_not_invent_measurements(self):
        with patch('companion.snapshot.Path.read_text', side_effect=OSError):
            self.assertIsNone(host_resources())

    def test_only_completed_inventory_is_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = IncidentStore(root / 'monitor.sqlite3')
            for name in ('current', 'removed'):
                store.observe(Observation(name, True, 'http', 200, 10))
            store.close()
            (root / 'last-completed.json').write_text(json.dumps({
                'completed_at': int(time.time()), 'target_names': ['current']}))
            export(root, root / 'snapshot.json')
            data = json.loads((root / 'snapshot.json').read_text())
            self.assertEqual([row['name'] for row in data['checks']], ['current'])

    def test_missing_observation_never_replaces_last_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            IncidentStore(root / 'monitor.sqlite3').close()
            (root / 'last-completed.json').write_text(json.dumps({
                'completed_at': int(time.time()), 'target_names': ['missing']}))
            target = root / 'snapshot.json'
            target.write_text('previous')
            with self.assertRaises(ValueError):
                export(root, target)
            self.assertEqual(target.read_text(), 'previous')
