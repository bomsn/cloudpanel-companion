import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from companion.package_install import PackageTransaction, require_package, recover


@unittest.skipUnless(os.geteuid() == 0, 'Operator-owned package transaction')
class PackageInstallTests(unittest.TestCase):
    def test_completed_update_cannot_restore_older_operator_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, installed, database = self.fixture(root)
            with PackageTransaction(source, installed, root / 'updates', database, services=(), managed=()) as change:
                pass
            with sqlite3.connect(database) as connection:
                connection.execute("UPDATE account SET name='later credential change'")
            with self.assertRaisesRegex(ValueError, 'Only an interrupted'):
                recover(change.state, root / 'updates')
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute('SELECT name FROM account').fetchone()[0], 'later credential change')

    def test_real_process_kill_recovers_previous_package_and_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, installed, database = self.fixture(root)
            before = (installed / 'companion/example.py').read_bytes()
            script = '''import os,signal,sqlite3,sys
from pathlib import Path
from companion.package_install import PackageTransaction
source,installed,state,database=map(Path,sys.argv[1:])
with PackageTransaction(source,installed,state,database,services=(),managed=()):
 with sqlite3.connect(database) as db: db.execute("UPDATE account SET name='interrupted'")
 os.kill(os.getpid(),signal.SIGKILL)
'''
            result = subprocess.run([sys.executable, '-c', script, str(source), str(installed), str(root / 'updates'), str(database)])
            self.assertEqual(result.returncode, -9)
            receipt = next((root / 'updates').iterdir())
            recover(receipt, root / 'updates')
            self.assertEqual((installed / 'companion/example.py').read_bytes(), before)
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute('SELECT name FROM account').fetchone()[0], 'retained')

    def test_successful_updates_bound_old_packages_and_account_backups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, installed, database = self.fixture(root)
            for version in range(4):
                (source / 'companion/example.py').write_text('version=' + str(version))
                with PackageTransaction(source, installed, root / 'updates', database, services=(), managed=()):
                    pass
            self.assertEqual(len(list(root.glob('.companion-package-*'))), 2)
            self.assertEqual(len(list((root / 'updates').glob('*/accounts.sqlite3'))), 2)
            require_package(source, installed)

    def fixture(self, root):
        source, installed, private = root / 'source', root / 'installed', root / 'private'
        for path in (source, installed):
            for package in ('companion', 'companion_web', 'assets'):
                (path / package).mkdir(parents=True)
            (path / 'companion/example.py').write_text('value = ' + repr(path.name))
        database = private / 'accounts.sqlite3'
        private.mkdir(mode=0o700)
        with sqlite3.connect(database) as connection:
            connection.execute('CREATE TABLE account (name TEXT)')
            connection.execute("INSERT INTO account VALUES ('retained')")
        return source, installed, database

    def test_failed_install_restores_real_package_and_account_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, installed, database = self.fixture(root)
            before = (installed / 'companion/example.py').read_bytes()
            with self.assertRaisesRegex(RuntimeError, 'deliberate'):
                with PackageTransaction(source, installed, root / 'updates', database, services=(), managed=()):
                    require_package(source, installed)
                    with sqlite3.connect(database) as connection:
                        connection.execute("UPDATE account SET name='changed'")
                    raise RuntimeError('deliberate activation failure')
            self.assertEqual((installed / 'companion/example.py').read_bytes(), before)
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute('SELECT name FROM account').fetchone()[0], 'retained')

    def test_update_refreshes_installed_units_and_failure_restores_them(self):
        # `git pull` + install.sh must also bring installed systemd units to the new
        # version, inside the same transaction, without installing new components.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, installed, database = self.fixture(root)
            systemd = root / 'systemd'
            systemd.mkdir()
            for name, content in (('companion-example.service', '[Service]\nExecStart=/bin/true new\n'),
                                  ('companion-example.timer', '[Timer]\nOnUnitActiveSec=60\n'),
                                  ('companion-unchosen.service', '[Service]\nExecStart=/bin/true\n')):
                (source / 'assets' / name).write_text(content)
            (source / 'assets' / 'notes.conf').write_text('not a unit\n')
            service, timer = systemd / 'companion-example.service', systemd / 'companion-example.timer'
            service.write_text('[Service]\nExecStart=/bin/true old\n')
            service.chmod(0o640)
            timer.write_text('[Timer]\nOnUnitActiveSec=60\n')
            with self.assertRaisesRegex(RuntimeError, 'deliberate'):
                with PackageTransaction(source, installed, root / 'updates', database, services=(), managed=(), systemd=systemd):
                    self.assertIn('new', service.read_text())
                    raise RuntimeError('deliberate activation failure')
            self.assertEqual(service.read_text(), '[Service]\nExecStart=/bin/true old\n')
            self.assertEqual(service.stat().st_mode & 0o777, 0o640)
            with PackageTransaction(source, installed, root / 'updates', database, services=(), managed=(), systemd=systemd) as change:
                pass
            self.assertEqual(service.read_text(), '[Service]\nExecStart=/bin/true new\n')
            self.assertEqual(service.stat().st_mode & 0o777, 0o640)
            self.assertEqual(sorted(path.name for path in systemd.iterdir()), ['companion-example.service', 'companion-example.timer'])
            self.assertEqual(change.units, [service, timer])

    def test_successful_install_removes_obsolete_files_without_deleting_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, installed, database = self.fixture(root)
            (installed / 'obsolete.py').write_text('old = True')
            with PackageTransaction(source, installed, root / 'updates', database, services=(), managed=()) as change:
                require_package(source, installed)
            self.assertFalse((installed / 'obsolete.py').exists())
            self.assertTrue((change.candidate / 'obsolete.py').exists())
            self.assertTrue((change.state / 'accounts.sqlite3').is_file())
