from pathlib import Path
import tempfile
import unittest
from companion.promotion import preview, verify_preview, expand_selection, folder_choices


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.staging = self.root / 'staging'
        self.live = self.root / 'live'
        self.relative = 'wp-content/themes/example/functions.php'
        for root in [self.staging, self.live]:
            (root / self.relative).parent.mkdir(parents=True)
            (root / self.relative).write_text('<?php // original')

    def tearDown(self):
        self.temp.cleanup()

    def test_preview_does_not_modify_target(self):
        (self.staging / self.relative).write_text('<?php // changed')
        plan = preview(self.staging, self.live, [self.relative])
        self.assertEqual(plan['changes'][0]['action'], 'replace')
        self.assertEqual((self.live / self.relative).read_text(), '<?php // original')
        verify_preview(self.staging, self.live, plan)

    def test_newer_live_edit_blocks_plan(self):
        plan = preview(self.staging, self.live, [self.relative])
        (self.live / self.relative).write_text('<?php // newer live change')
        with self.assertRaises(ValueError):
            verify_preview(self.staging, self.live, plan)

    def test_newer_staging_edit_blocks_plan(self):
        plan = preview(self.staging, self.live, [self.relative])
        (self.staging / self.relative).write_text('<?php // changed after preview')
        with self.assertRaises(ValueError):
            verify_preview(self.staging, self.live, plan)

    def test_configuration_database_media_and_traversal_rejected(self):
        for relative in ['wp-config.php', 'database.sql', 'wp-content/uploads/image.jpg',
                         '../live/wp-config.php', 'wp-content/themes/example/../../wp-config.php']:
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                preview(self.staging, self.live, [relative])

    def test_missing_source_is_not_delete(self):
        (self.staging / self.relative).unlink()
        with self.assertRaises(ValueError):
            preview(self.staging, self.live, [self.relative])

    def test_identical_other_target_cannot_reuse_approval(self):
        plan = preview(self.staging, self.live, [self.relative])
        other = self.root / 'other-live'
        (other / self.relative).parent.mkdir(parents=True)
        (other / self.relative).write_text('<?php // original')
        with self.assertRaises(ValueError):
            verify_preview(self.staging, other, plan)

    def test_identical_other_source_cannot_reuse_approval(self):
        plan = preview(self.staging, self.live, [self.relative])
        other = self.root / 'other-staging'
        (other / self.relative).parent.mkdir(parents=True)
        (other / self.relative).write_text('<?php // original')
        with self.assertRaises(ValueError):
            verify_preview(other, self.live, plan)

    def test_folder_expands_recursively_and_deduplicates_overlap(self):
        added = self.staging / 'wp-content/themes/example/assets/css/style.css'
        added.parent.mkdir(parents=True)
        added.write_text('body{}')
        expected = [added.relative_to(self.staging).as_posix(), self.relative]
        self.assertEqual(expand_selection(self.staging, ['wp-content/themes/example/', self.relative]), expected)

    def test_folder_links_and_private_artifacts_reject_whole_selection(self):
        folder = 'wp-content/themes/example'
        for name in ('.env', 'backup.sql'):
            path = self.staging / folder / name
            path.write_text('private')
            with self.assertRaises(ValueError):
                expand_selection(self.staging, [folder])
            path.unlink()
        link = self.staging / folder / 'linked'
        link.symlink_to(self.live, target_is_directory=True)
        with self.assertRaises(ValueError):
            expand_selection(self.staging, [folder])

    def test_folder_cannot_select_all_plugins_or_uploads(self):
        for folder in ('wp-content/plugins', 'wp-content/uploads', '/wp-content/themes/example', '../elsewhere'):
            with self.subTest(folder=folder), self.assertRaises(ValueError):
                expand_selection(self.staging, [folder])

    def test_folder_picker_hides_links_private_and_managed_infrastructure(self):
        base = self.staging / 'wp-content/plugins'
        base.mkdir()
        for name in ('ordinary', 'cache-manager-for-cloudpanel', 'redis-cache', '.private'):
            (base / name).mkdir()
        (base / 'linked').symlink_to(self.live, target_is_directory=True)
        self.assertEqual([row['path'] for row in folder_choices(self.staging)],
                         ['wp-content/plugins/ordinary', 'wp-content/themes/example'])


if __name__ == '__main__':
    unittest.main()
