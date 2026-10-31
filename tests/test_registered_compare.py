import json
import os
from pathlib import Path
import tempfile
import unittest
from companion.monitor import private_json
from companion.operations import write_private
from companion.registered_compare import Comparison


@unittest.skipUnless(os.geteuid() == 0, 'Private root-owned comparison metadata')
class ComparisonRecordTests(unittest.TestCase):
    def test_file_details_cannot_silently_switch_to_a_new_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            comparison = object.__new__(Comparison)
            comparison.parent = Path(directory)
            folder = 'a' * 64
            for number in (1, 2):
                state = comparison.parent / (str(1000000000 + number) + '-' + str(number) * 16)
                state.mkdir(mode=0o700)
                write_private(state / 'summary.json', json.dumps({'generation': state.name, 'folders': [{'id': folder}]}))
                write_private(state / (folder + '.json'), json.dumps({'rows': [{'file': str(number)}], 'excluded': []}))
                write_private(comparison.parent / 'latest.json', json.dumps({'state': str(state)}))
                if number == 1:
                    previous = state.name
            with self.assertRaises(ValueError):
                comparison.detail(folder, generation=previous)
            result = comparison.detail(folder, generation=state.name)
            self.assertEqual(result['rows'], [{'file': '2'}])

    def test_large_plans_need_explicit_size_limit_without_weakening_secret_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.json'
            payload = {'files': ['x' * 100 for _ in range(1000)]}
            write_private(path, json.dumps(payload))
            with self.assertRaises(ValueError):
                private_json(path)
            self.assertEqual(private_json(path, max_bytes=1024 * 1024), payload)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                private_json(path, max_bytes=1024 * 1024)
