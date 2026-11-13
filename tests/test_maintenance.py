import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from companion.maintenance import admissions, require_idle
from companion.operations import write_private


@unittest.skipUnless(os.geteuid() == 0, 'Root-owned installation admissions boundary')
class UpgradeBoundaryTests(unittest.TestCase):
    def test_exclusive_upgrade_refuses_a_concurrent_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'update.lock'
            with admissions(exclusive=True, path=path):
                process = subprocess.run([sys.executable, '-c',
                    'from pathlib import Path;import sys;from companion.maintenance import admissions;'
                    '\nwith admissions(path=Path(sys.argv[1])): pass', str(path)], capture_output=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn(b'Try again shortly', process.stderr)
            with admissions(path=path):
                pass

    def test_live_request_prevents_upgrade_and_releases_its_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'update.lock'
            with admissions(path=path):
                with self.assertRaises(ValueError):
                    with admissions(exclusive=True, path=path):
                        self.fail('An upgrade must not overlap a request')
            with admissions(exclusive=True, path=path):
                pass

    def test_async_job_and_unresolved_recovery_block_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state'
            state.mkdir(mode=0o700)
            record = {'returncode': None, 'state': str(state)}
            write_private(root / 'site.json', json.dumps(record))
            with self.assertRaises(ValueError):
                require_idle(root)
            record['returncode'] = 0
            write_private(root / 'site.json', json.dumps(record))
            write_private(state / 'receipt.json', json.dumps({'phase': 'completed', 'result': 'recovery-needs-review'}))
            with self.assertRaises(ValueError):
                require_idle(root)
            write_private(state / 'receipt.json', json.dumps({'phase': 'completed', 'result': 'rolled-back'}))
            require_idle(root)
