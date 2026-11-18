import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from companion import php_runtime

STATUS = {'opcache_used': 500 * 1024 ** 2, 'opcache_free': 40 * 1024 ** 2, 'opcache_wasted': 211 * 1024 ** 2,
          'opcache_wasted_percent': 27.47, 'opcache_full': False, 'opcache_scripts': 14570, 'opcache_restarts': 0}
# What `php-fpm -tt` reports on a CloudPanel server, whose pool.d/global.conf sets the timeout.
CHECKED = ('[09-Nov-2026 17:40:30] NOTICE: [global]\n'
           '[09-Nov-2026 17:40:30] NOTICE: \tprocess_control_timeout = 10s\n'
           '[09-Nov-2026 17:40:30] NOTICE: configuration file /etc/php/8.3/fpm/php-fpm.conf test is successful\n')


class SettingsTests(unittest.TestCase):
    def test_one_ini_drop_in_owns_the_settings(self):
        files = php_runtime.files('8.3')
        ini = Path('/etc/php/8.3/fpm/conf.d/99-companion-performance.ini')
        self.assertEqual(set(files), {ini})
        settings = dict(line.split('=', 1) for line in files[ini].splitlines()[1:])
        self.assertEqual(settings, {'opcache.memory_consumption': '768', 'opcache.interned_strings_buffer': '64',
                                    'opcache.max_accelerated_files': '100000', 'opcache.enable_file_override': '1'})
        # Code changes are still noticed, and PHP's own restart threshold is left at its default.
        for untouched in ('opcache.validate_timestamps', 'opcache.revalidate_freq', 'opcache.max_wasted_percentage'):
            self.assertNotIn(untouched, files[ini])
        # PHP's INI parser rejects hash comments.
        self.assertTrue(files[ini].startswith(';'))
        with self.assertRaises(ValueError):
            php_runtime.files('7.4')

    def test_a_reload_needs_a_configuration_php_fpm_accepts_and_a_graceful_timeout(self):
        self.assertEqual(php_runtime.graceful_timeout(CHECKED), 10)
        for output, code, refused in ((CHECKED, 0, None), (CHECKED.replace('10s', '0s'), 0, 'process_control_timeout is 0'),
                                      (CHECKED.replace('process_control_timeout', 'other'), 0, 'process_control_timeout is 0'),
                                      ('ERROR: failed to post process the configuration', 78, 'refused its configuration')):
            with self.subTest(output=output), mock.patch.object(
                    php_runtime.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, '', output)) as run:
                refusal = php_runtime.reload_refusal('8.3')
                self.assertEqual(run.call_args.args[0], ['/usr/sbin/php-fpm8.3', '-tt'])
                if refused is None:
                    self.assertIsNone(refusal)
                else:
                    self.assertIn(refused, refusal)

    def test_the_upkeep_runs_at_night_by_default_and_the_time_is_configurable(self):
        self.assertIsNone(php_runtime.schedule(php_runtime.UPKEEP_TIME))
        self.assertEqual(php_runtime.schedule('02:15').splitlines()[1:], ['[Timer]', 'OnCalendar=', 'OnCalendar=*-*-* 02:15:00'])
        timer = (Path(__file__).resolve().parents[1] / 'assets/companion-opcache-upkeep.timer').read_text()
        self.assertIn(f'OnCalendar=*-*-* {php_runtime.UPKEEP_TIME}:00\n', timer)
        self.assertIn('Persistent=false\n', timer)
        for value in ('4:30', '24:00', '04:60', '04:30; rm'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                php_runtime.schedule(value)


class UpkeepTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.locks = self.folder / 'locks'
        self.locks.mkdir()
        (self.locks / 'shop.lock').touch()

    def upkeep(self, status, reload_code=0, previous=None, checked=CHECKED):
        config, record = self.folder / 'telemetry.json', self.folder / 'opcache-upkeep.json'
        settings = {'host': 'shop.example.com', 'user': 'shop', 'php': '8.3', 'probe': '/home/shop/x.php'}
        if previous:
            record.write_text(json.dumps(previous))
        calls = []

        def run(arguments, **kwargs):
            calls.append(arguments)
            if arguments[-1] == '-tt':
                return subprocess.CompletedProcess(arguments, 0, '', checked)
            return subprocess.CompletedProcess(arguments, reload_code, b'', b'')
        sample = mock.patch('companion.telemetry.opcache_sample', side_effect=status if isinstance(status, Exception) else None,
                            return_value=status)
        written = lambda path, text: path.write_text(text)
        with sample, mock.patch.object(php_runtime.os, 'geteuid', return_value=0), \
                mock.patch.object(php_runtime, 'private_json', return_value=settings), \
                mock.patch.object(php_runtime.subprocess, 'run', side_effect=run), \
                mock.patch.object(php_runtime, 'write_export', side_effect=written):
            result = php_runtime.upkeep(config, record, now=1794195000, locks=self.locks)
        self.assertEqual(json.loads(record.read_text()), result)
        return result, calls

    def test_a_cache_that_wastes_ten_percent_or_is_full_is_reloaded_gracefully(self):
        result, calls = self.upkeep(STATUS)
        self.assertEqual(calls, [['/usr/sbin/php-fpm8.3', '-tt'], ['/usr/bin/systemctl', 'reload', 'php8.3-fpm.service']])
        self.assertEqual((result['action'], result['last_reload'], result['opcache_wasted_percent']), ('reloaded', 1794195000, 27.47))
        result, calls = self.upkeep({**STATUS, 'opcache_wasted_percent': 2.0, 'opcache_full': True})
        self.assertEqual(result['action'], 'reloaded')

    def test_a_healthy_cache_is_left_alone_and_the_last_reload_kept(self):
        result, calls = self.upkeep({**STATUS, 'opcache_wasted_percent': 9.99}, previous={'last_reload': 1794100000})
        self.assertEqual((calls, result['action'], result['last_reload']), ([], 'not-needed', 1794100000))

    def test_no_reload_while_a_workflow_runs_or_php_fpm_fails_its_check(self):
        # A release or refresh holds its site's lock while it runs.
        held = os.open(self.locks / 'shop.lock', os.O_RDWR)
        self.addCleanup(os.close, held)
        fcntl.flock(held, fcntl.LOCK_EX)
        result, calls = self.upkeep(STATUS, previous={'last_reload': 1794100000})
        self.assertEqual((calls, result['action'], result['last_reload']), ([], 'workflow-running', 1794100000))
        fcntl.flock(held, fcntl.LOCK_UN)
        result, calls = self.upkeep(STATUS, checked=CHECKED.replace('10s', '0s'))
        self.assertEqual((calls, result['action'], result['last_reload']), ([['/usr/sbin/php-fpm8.3', '-tt']], 'refused', 1794100000))
        self.assertIn('process_control_timeout is 0', result['reason'])

    def test_unreadable_status_and_a_failed_reload_are_recorded(self):
        result, calls = self.upkeep(ValueError('busy'))
        self.assertEqual((calls, result['action']), ([], 'unavailable'))
        result, _ = self.upkeep(STATUS, reload_code=1)
        self.assertEqual((result['action'], result['last_reload']), ('reload-failed', None))


if __name__ == '__main__':
    unittest.main()
