import tempfile
from pathlib import Path
import unittest
from companion.code_compare import inventory, differences


class CodeComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.live, self.stage = self.base / 'live', self.base / 'stage'
        for root in (self.live, self.stage):
            (root / 'wp-content/themes/example').mkdir(parents=True)
            (root / 'wp-content/plugins').mkdir()
            (root / 'wp-content/themes/example/same.php').write_text('<?php // same')

    def tearDown(self):
        self.temp.cleanup()

    def test_content_hashes_detect_changes_even_with_same_size(self):
        for root, content in ((self.live, 'one'), (self.stage, 'two')):
            (root / 'wp-content/themes/example/change.css').write_text(content)
        folders, details = differences(inventory(self.live), inventory(self.stage))
        self.assertEqual(folders[0]['changed'], 1)
        self.assertEqual(details[folders[0]['id']]['rows'][0]['status'], 'modified')
        self.assertEqual(folders[0]['unchanged'], 1)

    def test_added_and_website_only_are_distinct_and_no_deletion_is_offered(self):
        (self.stage / 'wp-content/themes/example/new.js').write_text('new')
        (self.live / 'wp-content/themes/example/keep.js').write_text('keep')
        folders, details = differences(inventory(self.live), inventory(self.stage))
        self.assertEqual(folders[0]['changed'], 1)
        self.assertEqual(folders[0]['website_only'], 1)
        rows = details[folders[0]['id']]['rows']
        self.assertFalse(next(row for row in rows if row['status'] == 'website-only')['releasable'])

    def test_private_files_and_symlinks_are_explicit_not_hashed_or_followed(self):
        directory = self.stage / 'wp-content/themes/example'
        (directory / '.env').write_text('secret must not be read')
        (directory / 'linked').symlink_to(self.live, target_is_directory=True)
        result = inventory(self.stage)
        record = result['folders']['wp-content/themes/example']
        self.assertEqual(len(record['excluded']), 2)
        self.assertNotIn('secret', str(result))
        folders, _ = differences(inventory(self.live), result)
        self.assertFalse(folders[0]['whole_folder'])

    def test_new_folder_and_managed_infrastructure(self):
        (self.stage / 'wp-content/plugins/new').mkdir()
        (self.stage / 'wp-content/plugins/new/plugin.php').write_text('<?php')
        (self.stage / 'wp-content/plugins/redis-cache').mkdir()
        (self.stage / 'wp-content/plugins/redis-cache/plugin.php').write_text('managed separately')
        folders, _ = differences(inventory(self.live), inventory(self.stage))
        self.assertEqual(len(folders), 2)
        added = next(folder for folder in folders if folder['name'] == 'new')
        self.assertTrue(added['whole_folder'])
        self.assertEqual(added['changed'], 1)

    def test_large_unchanged_folder_can_select_a_small_changed_release(self):
        files = {f'wp-content/plugins/example/{n}.php': {'sha256': 'same', 'bytes': 10} for n in range(6000)}
        before = {'folders': {'wp-content/plugins/example': {'name': 'example', 'kind': 'plugins', 'files': files, 'excluded': []}}}
        after = {'folders': {'wp-content/plugins/example': {'name': 'example', 'kind': 'plugins', 'files': {**files,
            'wp-content/plugins/example/0.php': {'sha256': 'changed', 'bytes': 12}}, 'excluded': []}}}
        folders, _ = differences(before, after)
        self.assertTrue(folders[0]['whole_folder'])
        self.assertEqual(folders[0]['changed'], 1)
        self.assertEqual(folders[0]['unchanged'], 5999)
