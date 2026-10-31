"""Exercise the actual owner-side provisioning program against real files."""
import ast
import io
import os
from pathlib import Path
import pwd
import subprocess
import tarfile
import tempfile
import unittest


@unittest.skipUnless(os.geteuid() == 0 and Path('/usr/bin/php8.3').exists(), 'Linux operator and PHP CLI required')
class PluginProvisionTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='companion-plugin-install-')
        self.root = Path(self.work.name)
        self.root.chmod(0o755)
        self.home = self.root / 'owner'
        self.home.mkdir(mode=0o700)
        actor = pwd.getpwnam('nobody')
        os.chown(self.home, actor.pw_uid, actor.pw_gid)
        self.target = self.home / 'wp-content/plugins/cache-manager-for-cloudpanel'
        self.command = ['/usr/sbin/runuser', '-u', 'nobody', '--', '/usr/bin/env', 'HOME=' + str(self.home)]
        subprocess.run(self.command + ['mkdir', '-p', str(self.target.parent)], check=True)
        source = Path(__file__).resolve().parents[1] / 'install-cache.py'
        tree = ast.parse(source.read_text())
        self.program = next(node.value.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                            and any(isinstance(target, ast.Name) and target.id == 'installer' for target in node.targets)
                            and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))

    def tearDown(self):
        self.work.cleanup()

    def install(self, content):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w:gz') as archive:
            member = tarfile.TarInfo('plugin.php')
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        return subprocess.run(self.command + ['python3', '-c', self.program, str(self.target), '8.3'],
                              input=payload.getvalue(), capture_output=True)

    def test_initial_install_replay_and_different_code_refusal(self):
        content = b'<?php echo "version one";'
        result = self.install(content)
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = (self.target / 'plugin.php').stat().st_ino
        self.assertEqual(self.install(content).returncode, 0)
        self.assertEqual((self.target / 'plugin.php').stat().st_ino, identity)
        result = self.install(b'<?php echo "unreviewed replacement";')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Installed plugin code differs', result.stderr)
        self.assertEqual((self.target / 'plugin.php').read_bytes(), content)
        self.assertEqual(list(self.home.glob('.companion-plugin-*')), [])

    def test_invalid_php_never_becomes_a_visible_plugin(self):
        self.assertNotEqual(self.install(b'<?php broken {{{').returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.home.glob('.companion-plugin-*')), [])

    def test_destination_link_is_not_replaced_or_followed(self):
        outside = self.home / 'outside'
        subprocess.run(self.command + ['mkdir', str(outside)], check=True)
        self.target.symlink_to(outside, target_is_directory=True)
        result = self.install(b'<?php echo "safe";')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(list(outside.iterdir()), [])
