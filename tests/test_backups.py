import base64
from datetime import datetime
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from companion import backups


def at(text):
    return int(datetime.strptime(text, '%Y-%m-%d %H:%M').timestamp())


class CronScheduleTests(unittest.TestCase):
    def test_latest_scheduled_run_for_the_tool_schedules(self):
        now = at('2026-11-04 10:00')  # a Wednesday
        self.assertEqual(backups.previous_run('00 03 * * *', now), at('2026-11-04 03:00'))
        self.assertEqual(backups.previous_run('30 11 * * *', now), at('2026-11-03 11:30'))
        self.assertEqual(backups.previous_run('00 02 * * 1', now), at('2026-11-02 02:00'))   # Monday
        self.assertEqual(backups.previous_run('00 02 * * 0', now), at('2026-11-01 02:00'))   # Sunday
        self.assertEqual(backups.previous_run('00 02 * * 7', now), at('2026-11-01 02:00'))
        self.assertEqual(backups.previous_run('15 04 15 * *', now), at('2026-10-15 04:15'))
        self.assertEqual(backups.previous_run('00 01 * * *', now, last_day_only=True), at('2026-10-31 01:00'))
        self.assertEqual(backups.previous_run('0 */4 * * *', now), at('2026-11-04 08:00'))
        self.assertEqual(backups.previous_run('0 0,12 1-7 * 1', now), at('2026-11-04 00:00'))  # either day field
        for invalid in ('* * *', 'x 1 * * *', '60 1 * * *', '1 1 * * 8'):
            with self.assertRaises(ValueError):
                backups.previous_run(invalid, now)


@unittest.skipUnless(os.geteuid() == 0, 'The backup tool state is root-owned')
class MissedBackupTests(unittest.TestCase):
    """A scheduled backup that has not succeeded within its window is reported."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.state = Path(self.folder.name) / 'state'
        (self.state / 'cron_scripts').mkdir(parents=True, mode=0o700)
        (self.state / 'status').mkdir(mode=0o700)
        self.cron = Path(self.folder.name) / 'rclone-automated-backups'
        self.lines = []

    def tearDown(self):
        self.folder.cleanup()

    def job(self, name, expression, domain='shop.example.com', kind='full', created=None):
        script = self.state / 'cron_scripts' / name
        encode = lambda value: base64.b64encode(value.encode()).decode()
        script.write_text('#!/bin/bash\ndomain_b64=' + encode(domain) + '\ntype_b64=' + encode(kind) + '\n')
        script.chmod(0o700)
        if created:
            os.utime(script, (created, created))
        self.lines.append(expression + ' root /bin/bash ' + str(script))
        self.write_cron()
        return name

    def write_cron(self):
        # The tool's cron file is root-owned 0644.
        self.cron.write_text('\n'.join(self.lines) + '\n')
        self.cron.chmod(0o644)

    def succeeded(self, name, finished):
        record = self.state / 'status' / (name + '.json')
        record.write_text(json.dumps({'job': name, 'finished_at': finished}))
        record.chmod(0o600)

    def observe(self, now):
        return {item['job']: item for item in backups.observe(now, (self.cron,))}

    def test_missed_and_succeeded_runs(self):
        created = at('2026-10-01 12:00')
        daily = self.job('a' * 32 + '_03-00_daily', '00 03 * * *', created=created)
        weekly = self.job('b' * 32 + '_02-00_weekly', '00 02 * * 1', kind='database', created=created)
        self.succeeded(daily, at('2026-11-03 03:04'))
        self.succeeded(weekly, at('2026-11-02 02:01'))
        # 4 Nov 05:30: today's 03:00 run is still inside its window; yesterday's succeeded.
        result = self.observe(at('2026-11-04 05:30'))
        self.assertEqual(result[daily]['state'], 'succeeded')
        self.assertEqual(result[daily]['name'], 'Backup: shop.example.com full, daily 03:00')
        self.assertEqual(result[weekly]['name'], 'Backup: shop.example.com database, weekly 02:00')
        # 06:30: today's run should have finished by 06:00 and has no success record.
        result = self.observe(at('2026-11-04 06:30'))
        self.assertEqual((result[daily]['state'], result[daily]['healthy']), ('missed', False))
        self.assertEqual(result[daily]['due_at'], at('2026-11-04 03:00'))
        self.assertEqual(result[daily]['last_success'], at('2026-11-03 03:04'))
        self.assertTrue(result[weekly]['healthy'])
        self.succeeded(daily, at('2026-11-04 06:40'))
        self.assertTrue(self.observe(at('2026-11-04 06:45'))[daily]['healthy'])

    def test_new_jobs_and_unsafe_or_missing_records(self):
        fresh = self.job('c' * 32 + '_03-00_daily', '00 03 * * *', created=at('2026-11-04 10:00'))
        old = self.job('d' * 32 + '_01-30_daily', '30 01 * * *', created=at('2026-10-01 10:00'))
        result = self.observe(at('2026-11-04 12:00'))
        # Created after its latest scheduled run: nothing was due yet.
        self.assertEqual((result[fresh]['state'], result[fresh]['healthy']), ('not-due-yet', True))
        # An older job with no success record (for example created by an older tool
        # version, which writes none) counts as missed once a run was due.
        self.assertEqual(result[old]['state'], 'missed')
        self.succeeded(old, at('2026-11-04 01:31'))
        (self.state / 'status' / (old + '.json')).chmod(0o666)
        self.assertEqual(self.observe(at('2026-11-04 12:00'))[old]['state'], 'missed')
        record = self.state / 'status' / (old + '.json')
        record.unlink()
        record.symlink_to(Path(self.folder.name) / 'elsewhere.json')
        self.assertEqual(self.observe(at('2026-11-04 12:00'))[old]['state'], 'missed')

    def test_schedule_and_job_come_from_the_tool_files(self):
        last = self.job('e' * 32 + '_23-00_monthly', '00 23 * * *', created=at('2026-01-01 00:00'))
        (self.state / 'cron_scripts' / ('f' * 32 + '_04-00_daily')).unlink(missing_ok=True)
        self.lines.append('00 04 * * * root /bin/bash ' + str(self.state / 'cron_scripts' / ('f' * 32 + '_04-00_daily')))
        self.lines.append('# 00 05 * * * root /bin/bash ' + str(self.state / 'cron_scripts' / ('0' * 32 + '_05-00_daily')))
        self.lines.append('00 05 * * * root /usr/bin/other-tool')
        self.write_cron()
        result = self.observe(at('2026-11-15 12:00'))
        self.assertEqual(sorted(result), [last, 'f' * 32 + '_04-00_daily'])
        # A monthly job on a daily cron line runs on the last day of the month.
        self.assertEqual(result[last]['name'], 'Backup: shop.example.com full, last day of the month 23:00')
        self.assertEqual(result[last]['due_at'], at('2026-10-31 23:00'))
        # A schedule whose job script is gone can never run.
        self.assertEqual(result['f' * 32 + '_04-00_daily']['state'], 'job-script-missing')
        # A cron file other users can change is ignored.
        self.cron.chmod(0o666)
        self.assertEqual(self.observe(at('2026-11-15 12:00')), {})

    def test_a_missed_backup_raises_an_incident_on_the_service_path(self):
        from companion import system_watch
        from companion.incidents import IncidentStore
        name = self.job('a' * 32 + '_03-00_daily', '00 03 * * *', created=at('2026-10-01 12:00'))
        root = Path(self.folder.name)
        state, output = root / 'system', root / 'observations' / 'latest.json'
        state.mkdir(mode=0o700)
        output.parent.mkdir(mode=0o755)
        configuration = root / 'system-watch.json'
        configuration.write_text(json.dumps({'units': [{'name': 'ssh.service', 'label': 'SSH', 'recover': False}]}))
        configuration.chmod(0o600)
        with mock.patch.object(system_watch, 'unit_state', return_value='active'), \
                mock.patch.object(system_watch.os, 'chown'), \
                mock.patch.object(system_watch.grp, 'getgrnam'):
            for _ in range(2):
                system_watch.run(configuration, state, output, (self.cron,))
        exported = json.loads(output.read_text())
        self.assertEqual([job['job'] for job in exported['backups']], [name])
        self.assertFalse(exported['backups'][0]['healthy'])
        self.assertEqual(exported['backup_grace'], backups.GRACE)
        store = IncidentStore(state / 'monitor.sqlite3')
        try:
            pending = [(event[1], event[2]) for event in store.pending()]
        finally:
            store.close()
        self.assertEqual(pending, [('Backup: shop.example.com full, daily 03:00', 'down')])
        self.succeeded(name, int(time.time()))
        with mock.patch.object(system_watch, 'unit_state', return_value='active'), \
                mock.patch.object(system_watch.os, 'chown'), \
                mock.patch.object(system_watch.grp, 'getgrnam'):
            for _ in range(2):
                system_watch.run(configuration, state, output, (self.cron,))
        store = IncidentStore(state / 'monitor.sqlite3')
        try:
            self.assertIn(('Backup: shop.example.com full, daily 03:00', 'healthy'),
                          [(event[1], event[2]) for event in store.pending()])
        finally:
            store.close()


if __name__ == '__main__':
    unittest.main()
