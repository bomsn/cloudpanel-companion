import os
from pathlib import Path
import tempfile
import unittest
from companion.operations import write_private


class OperationsStorageTests(unittest.TestCase):
    def test_explicit_policy_permissions_survive_private_service_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / 'policy.json'
            secret = Path(directory) / 'secret.json'
            previous = os.umask(0o077)
            try:
                write_private(policy, '{}', 0o640)
                write_private(secret, '{}')
            finally:
                os.umask(previous)
            self.assertEqual(policy.stat().st_mode & 0o777, 0o640)
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
    def test_interrupted_old_temporary_file_does_not_block_a_new_atomic_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            legacy = path.with_suffix('.new')
            legacy.write_text('interrupted previous write')
            write_private(path, '{"enabled": false}', 0o640)
            self.assertEqual(path.read_text(), '{"enabled": false}')
            self.assertEqual(legacy.read_text(), 'interrupted previous write')


if __name__ == '__main__':
    unittest.main()
