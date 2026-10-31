"""Pure policy tests plus real private-file rollback; no PHP restart required."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

module = Path(__file__).resolve().parents[1] / 'assets/cloudpanel-application-hardening.py'
spec = importlib.util.spec_from_file_location('application_hardening', module)
hardening = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hardening)


class PolicyTests(unittest.TestCase):
    def test_egress_is_uid_scoped_and_keeps_other_firewalls(self):
        policy = hardening.egress_policy(1234, ['108.61.10.10', '2001:db8::53'])
        self.assertIn('ct direction reply return', policy)
        # Kernel-sent ACKs/RSTs of closed connections carry no owner and match neither
        # `skuid 1234` nor `skuid != 1234`; only a positive match may lead to the rejects,
        # or every user's loopback connections lose their final ACK (LAST-ACK stalls).
        base = policy.split(' chain output {', 1)[1].split(' }', 1)[0].split('\n')
        self.assertEqual([line.strip() for line in base if line.strip()],
                         ['type filter hook output priority 20; policy accept;', 'meta skuid 1234 jump website'])
        self.assertNotIn('skuid !=', policy)
        self.assertLess(policy.index(' chain website {'), policy.index('reject'))
        self.assertIn('169.254.0.0/16', policy)
        self.assertIn('108.61.10.10 udp dport 53 return', policy)
        self.assertNotIn('flush ruleset', policy)
        self.assertNotIn('dport 22', policy)
        for uid in (0, '1234', -1):
            with self.assertRaises(ValueError):
                hardening.egress_policy(uid, [])

    def test_sensitive_routes_keep_public_media(self):
        routes = hardening.sensitive_routes()
        self.assertIn('wp-config.php', routes)
        self.assertIn('ai1wm-backups', routes)
        self.assertNotIn('pdf', routes)
        self.assertNotIn('glb', routes)
        self.assertNotIn('usdz', routes)

    def test_php_runtime_keeps_code_change_detection(self):
        files = hardening.php_runtime('8.3')
        conf = Path('/etc/php/8.3/fpm/conf.d')
        self.assertEqual(set(files), {conf / '99-companion-security.ini', conf / '99-companion-performance.ini'})
        settings = {}
        for path, (content, mode) in files.items():
            self.assertEqual(mode, 0o644)
            for line in content.splitlines():
                key, value = line.split('=', 1)
                self.assertNotIn(key, settings, 'each setting has one owner file')
                settings[key] = value
        self.assertEqual(settings, {'opcache.validate_permission': '1', 'opcache.interned_strings_buffer': '64',
                                    'opcache.enable_file_override': '1'})
        # The file-existence cache is only safe while OPcache still checks timestamps;
        # these drop-ins must never turn that off or override CloudPanel's other defaults.
        self.assertNotIn('opcache.validate_timestamps', settings)
        self.assertNotIn('opcache.revalidate_freq', settings)

    def test_php_configuration_uses_native_ini_comment_syntax(self):
        self.assertTrue(hardening.managed_header(Path('/etc/php/8.3/fpm/conf.d/99-companion-security.ini')).startswith(';'))
        self.assertTrue(hardening.managed_header(Path('/etc/php/8.3/fpm/pool.d/zz-companion-resource-limits.conf')).startswith(';'))
        self.assertTrue(hardening.managed_header(Path('/etc/sudoers.d/example')).startswith('#'))


@unittest.skipUnless(os.geteuid() == 0, 'Operator-owned file tests require root on Linux')
class PrivateFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hardening-test-', dir='/root')
        self.base = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_symlink_or_foreign_configuration_is_never_replaced(self):
        other = self.base / 'other'
        other.write_text('keep')
        link = self.base / 'linked'
        link.symlink_to(other)
        with self.assertRaises(ValueError):
            hardening.owned(link, 'changed')
        with self.assertRaises(ValueError):
            hardening.owned(other, 'changed')
        self.assertEqual(other.read_text(), 'keep')

    def test_atomic_files_have_explicit_modes_with_restrictive_umask(self):
        path = self.base / 'private.json'
        old = os.umask(0o077)
        try:
            hardening.atomic(path, 'private', 0o600)
            hardening.owned(self.base / 'public.conf', 'approved', 0o644)
        finally:
            os.umask(old)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.base / 'public.conf').stat().st_mode & 0o777, 0o644)

    def test_failed_real_validation_restores_previous_file_before_any_restart(self):
        path = self.base / 'rollback.conf'
        hardening.owned(path, 'original', 0o640)
        # Never write test records into the operator's real rollback directory.
        receipts = self.base / 'recovery'
        before = set()
        with mock.patch.object(hardening, 'RECOVERY_DIRECTORY', receipts), self.assertRaises(RuntimeError):
            hardening.configure({path: ('changed', 0o644)}, ['invalid-test-version'], [], [])
        self.assertEqual(path.read_text(), hardening.HEADER + 'original')
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        created = set(receipts.glob('before-*.json')) - before
        self.assertEqual(len(created), 1)
        receipt = json.loads(created.pop().read_text())
        self.assertEqual(receipt['phase'], 'rolled-back')
        self.assertFalse(receipt['rollback_errors'])
