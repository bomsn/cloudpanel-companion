import tempfile
from pathlib import Path
import unittest

from companion.cache_config import render
from companion.cache_control import RevisionController


class CacheControlTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.root = Path(self.work.name).resolve()
        self.instance = self.root / 'instance'
        self.instance.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.ready = self.root / 'ready'
        self.ready.mkdir(mode=0o755)
        self.config = {'backend_port': 8080, 'sites': [
            {'host': 'one.example', 'purge_key': 'a' * 64},
            {'host': 'two.example', 'purge_key': 'b' * 64},
        ]}

    def tearDown(self):
        self.work.cleanup()

    def test_credentials_cannot_cross_sites(self):
        controller = RevisionController(self.config, '# policy', self.state, self.instance, self.ready)
        try:
            self.assertTrue(controller.authenticated('one.example', 'a' * 64))
            self.assertFalse(controller.authenticated('two.example', 'a' * 64))
            self.assertFalse(controller.authenticated('unknown.example', 'a' * 64))
            self.assertFalse(controller.authenticated('one.example', 'a' * 63))
        finally:
            controller.close()

    def test_second_controller_cannot_race_revisions(self):
        controller = RevisionController(self.config, '# policy', self.state, self.instance, self.ready)
        try:
            with self.assertRaises(BlockingIOError):
                RevisionController(self.config, '# policy', self.state, self.instance, self.ready)
        finally:
            controller.close()

    def test_site_revision_does_not_change_other_site_namespace(self):
        revisions = {'one.example': '1' * 32, 'two.example': '2' * 32}
        first = render(self.config, '# policy', revisions)
        second = render(self.config, '# policy', {**revisions, 'one.example': '3' * 32})
        self.assertEqual([line for line in first.splitlines() if 'host == "two.example"' in line],
                         [line for line in second.splitlines() if 'host == "two.example"' in line])
        self.assertNotEqual(first, second)

    def test_availability_is_explicit_and_removed_on_shutdown(self):
        controller = RevisionController(self.config, '# policy', self.state, self.instance, self.ready)
        self.assertFalse(controller.marker('one.example').exists())
        controller.set_ready('one.example', True)
        self.assertTrue(controller.marker('one.example').is_file())
        controller.close()
        self.assertFalse(controller.marker('one.example').exists())

    def test_policy_change_also_changes_namespace(self):
        revisions = {'one.example': '1' * 32, 'two.example': '2' * 32}
        first = render(self.config, '# old policy', revisions)
        second = render(self.config, '# new policy', revisions)
        self.assertNotEqual([line for line in first.splitlines() if 'set req.http.' in line],
                            [line for line in second.splitlines() if 'set req.http.' in line])

    def test_revision_injection_rejected(self):
        with self.assertRaises(ValueError):
            render(self.config, '', {'one.example': '"; return(synth(200));', 'two.example': '2' * 32})


if __name__ == '__main__':
    unittest.main()
