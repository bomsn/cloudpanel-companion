"""Run as an unprivileged user on Linux with a root-owned PHP CLI installed."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from companion.deployment import apply, recover
from companion.promotion import preview


@unittest.skipIf(os.geteuid() == 0, 'Deployment acceptance requires a non-root identity')
class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source, self.target, self.state = [self.root / name for name in ('source', 'target', 'state')]
        self.relative = 'wp-content/themes/example/functions.php'
        for root in (self.source, self.target):
            (root / self.relative).parent.mkdir(parents=True)
            (root / self.relative).write_text('<?php echo "before";')
        self.state.mkdir(mode=0o700)
        self.php = shutil.which('php8.3') or shutil.which('php')
        if not self.php:
            self.skipTest('PHP CLI is required')
        (self.source / self.relative).write_text('<?php echo "after";')
        self.plan = preview(self.source, self.target, [self.relative])

    def tearDown(self):
        self.temp.cleanup()

    def deploy(self, check=lambda: True):
        return apply(self.source, self.target, self.plan, self.state, self.php, check)

    def test_real_apply_keeps_recovery_copy(self):
        receipt = self.deploy()
        self.assertEqual((self.target / self.relative).read_bytes(), (self.source / self.relative).read_bytes())
        self.assertEqual(json.loads(receipt.read_text())['status'], 'completed')
        self.assertEqual((receipt.parent / '0.before').read_text(), '<?php echo "before";')

    def test_failure_restores_original(self):
        with self.assertRaises(ValueError):
            self.deploy(lambda: False)
        self.assertEqual((self.target / self.relative).read_text(), '<?php echo "before";')
        receipt = next(self.state.glob('*/receipt.json'))
        self.assertEqual(json.loads(receipt.read_text())['status'], 'rolled-back')

    def test_recovery_preserves_a_newer_edit(self):
        def check():
            (self.target / self.relative).write_text('<?php echo "newer edit";')
            return False
        with self.assertRaises(ValueError):
            self.deploy(check)
        self.assertEqual((self.target / self.relative).read_text(), '<?php echo "newer edit";')
        receipt = json.loads(next(self.state.glob('*/receipt.json')).read_text())
        self.assertEqual(receipt['status'], 'recovery-needs-review')
        self.assertEqual(receipt['recovery_conflicts'], [self.relative])

    def test_invalid_php_never_reaches_target(self):
        (self.source / self.relative).write_text('<?php broken syntax {')
        self.plan = preview(self.source, self.target, [self.relative])
        with self.assertRaises(ValueError):
            self.deploy()
        self.assertEqual((self.target / self.relative).read_text(), '<?php echo "before";')

    def test_later_target_edit_blocks_apply(self):
        (self.target / self.relative).write_text('<?php echo "newer";')
        with self.assertRaises(ValueError):
            self.deploy()
        self.assertEqual((self.target / self.relative).read_text(), '<?php echo "newer";')

    def test_new_file_removed_after_failed_check(self):
        added = 'wp-content/themes/example/extra.css'
        (self.source / added).write_text('body { color: red; }')
        self.plan = preview(self.source, self.target, [self.relative, added])
        with self.assertRaises(ValueError):
            self.deploy(lambda: False)
        self.assertFalse((self.target / added).exists())

    def test_new_plugin_folder_and_nested_files_can_release_and_recover(self):
        from companion.promotion import expand_selection
        relative = 'wp-content/plugins/new-example/assets/css/style.css'
        (self.source / relative).parent.mkdir(parents=True)
        (self.source / relative).write_text('body{color:red}')
        (self.target / 'wp-content/plugins').mkdir()
        self.plan = preview(self.source, self.target, expand_selection(self.source, ['wp-content/plugins/new-example/']))
        old_mask = os.umask(0o077)
        try:
            receipt = self.deploy()
        finally:
            os.umask(old_mask)
        self.assertEqual((self.target / relative).read_text(), 'body{color:red}')
        self.assertEqual((self.target / relative).parent.stat().st_mode & 0o777, 0o755)
        result = recover(self.target, self.state, receipt.parent.name, lambda: True)
        self.assertEqual(result['status'], 'rolled-back')
        self.assertFalse((self.target / 'wp-content/plugins/new-example').exists())

    def test_new_nested_directory_removed_on_failed_health_check(self):
        added = 'wp-content/themes/example/assets/deep/extra.css'
        (self.source / added).parent.mkdir(parents=True)
        (self.source / added).write_text('body{}')
        self.plan = preview(self.source, self.target, [added])
        with self.assertRaises(ValueError):
            self.deploy(lambda: False)
        self.assertFalse((self.target / 'wp-content/themes/example/assets').exists())

    def test_new_directories_preserve_later_unrelated_file_on_recovery(self):
        added = 'wp-content/themes/example/assets/deep/extra.css'
        (self.source / added).parent.mkdir(parents=True)
        (self.source / added).write_text('body{}')
        self.plan = preview(self.source, self.target, [added])
        receipt = self.deploy()
        later = self.target / 'wp-content/themes/example/assets/later.txt'
        later.write_text('newer')
        result = recover(self.target, self.state, receipt.parent.name, lambda: True)
        self.assertEqual(result['status'], 'rolled-back')
        self.assertEqual(later.read_text(), 'newer')
        self.assertFalse((self.target / added).exists())

    def test_parent_symlink_cannot_write_outside_target(self):
        outside = self.root / 'outside'
        outside.mkdir()
        shutil.rmtree(self.target / 'wp-content/themes/example')
        (self.target / 'wp-content/themes/example').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.deploy()
        self.assertEqual(list(outside.iterdir()), [])

    def test_interrupted_write_can_be_recovered_twice(self):
        # SystemExit represents a terminated executor, outside ordinary error
        # recovery. The durable write intent must remain sufficient to restore.
        def interrupted():
            raise SystemExit('simulated process interruption')
        with self.assertRaises(SystemExit):
            self.deploy(interrupted)
        receipt = next(self.state.glob('*/receipt.json'))
        self.assertEqual(json.loads(receipt.read_text())['status'], 'applying')
        for _ in range(2):
            result = recover(self.target, self.state, receipt.parent.name, lambda: True)
            self.assertEqual(result['status'], 'rolled-back')
            self.assertEqual((self.target / self.relative).read_text(), '<?php echo "before";')

    def test_altered_recovery_copy_cannot_be_applied(self):
        receipt = self.deploy()
        (receipt.parent / '0.before').write_text('altered')
        with self.assertRaises(ValueError):
            recover(self.target, self.state, receipt.parent.name, lambda: True)
        self.assertEqual((self.target / self.relative).read_text(), '<?php echo "after";')
