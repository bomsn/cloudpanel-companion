import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from companion.clone_worker import receive_archive, php_string


class ArchiveBoundaryTests(unittest.TestCase):
    def archive(self, name, kind=tarfile.REGTYPE, link=''):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = link
            info.size = 4 if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(b'data') if info.size else None)
        data.seek(0)
        return data

    def test_regular_nested_files_are_received(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receive_archive(self.archive('./wp-content/uploads/example.jpg'), root)
            self.assertEqual((root / 'wp-content/uploads/example.jpg').read_bytes(), b'data')

    def test_links_devices_and_traversal_are_rejected(self):
        cases = [('../outside.php', tarfile.REGTYPE, ''), ('/outside.php', tarfile.REGTYPE, ''),
                 ('link', tarfile.SYMTYPE, '../outside'), ('hard', tarfile.LNKTYPE, '../outside'),
                 ('device', tarfile.CHRTYPE, '')]
        for name, kind, link in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    receive_archive(self.archive(name, kind, link), Path(directory))
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_php_literal_escapes_configuration_values(self):
        self.assertEqual(php_string("a'b\\c"), "'a\\'b\\\\c'")
