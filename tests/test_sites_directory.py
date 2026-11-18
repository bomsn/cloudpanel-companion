import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from companion import operations


class SitesDirectoryTest(unittest.TestCase):
    def test_traversable_under_the_service_private_umask(self):
        """A staging site's PHP user must reach its own policy file inside the folder."""
        with tempfile.TemporaryDirectory() as root:
            sites = Path(root) / 'sites'
            previous = os.umask(0o077)
            try:
                with mock.patch.object(operations, 'SITES', sites):
                    self.assertEqual(operations.sites_directory(), sites)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(sites.stat().st_mode), 0o711)

    def test_repairs_an_existing_private_folder(self):
        with tempfile.TemporaryDirectory() as root:
            sites = Path(root) / 'sites'
            sites.mkdir(mode=0o700)
            sites.chmod(0o700)
            with mock.patch.object(operations, 'SITES', sites):
                operations.sites_directory()
            self.assertEqual(stat.S_IMODE(sites.stat().st_mode), 0o711)


if __name__ == '__main__':
    unittest.main()
