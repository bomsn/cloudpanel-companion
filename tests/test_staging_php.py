import shutil
import subprocess
import unittest
from pathlib import Path


class StagingPhpTests(unittest.TestCase):
    """The staging must-use plugin's own checks, when PHP is installed."""

    def test_staging_php_checks(self):
        php = shutil.which('php')
        if not php:
            self.skipTest('PHP is not installed')
        for name in ('staging-policy.php', 'staging-relay-report.php'):
            with self.subTest(name=name):
                result = subprocess.run([php, str(Path(__file__).with_name(name))], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
