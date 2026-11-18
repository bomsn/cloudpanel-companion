import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock
from companion import system_watch


def shown(*blocks):
    """`systemctl show` output for several units: one block each, separated by a blank line."""
    return subprocess.CompletedProcess([], 0, '\n\n'.join('\n'.join(f'{key}={value}' for key, value in block.items())
                                                       for block in blocks).encode() + b'\n', b'')


class UnitStateTests(unittest.TestCase):
    def test_properties_follow_argument_order_so_aliases_keep_their_name(self):
        output = shown({'LoadState': 'loaded', 'ActiveState': 'active', 'ActiveEnterTimestamp': '@1000'},
                       {'LoadState': 'not-found', 'ActiveState': 'inactive', 'ActiveEnterTimestamp': ''})
        with mock.patch.object(system_watch.subprocess, 'run', return_value=output) as run:
            units = system_watch.unit_properties(['mysql.service', 'varnish.service'])
        self.assertIn('--timestamp=unix', run.call_args.args[0])
        self.assertEqual(units['mysql.service']['ActiveState'], 'active')
        self.assertEqual(system_watch.service_state(units['varnish.service']), 'not-installed')
        self.assertEqual(system_watch.moment(units['mysql.service']['ActiveEnterTimestamp']), 1000)
        self.assertIsNone(system_watch.moment(units['varnish.service']['ActiveEnterTimestamp']))
        # A reply that does not cover every unit is no observation, not a partial one.
        with mock.patch.object(system_watch.subprocess, 'run', return_value=shown({'LoadState': 'loaded'})):
            self.assertEqual(system_watch.unit_properties(['a.service', 'b.service']), {'a.service': {}, 'b.service': {}})
        self.assertEqual(system_watch.service_state({}), 'unknown')
        self.assertEqual(system_watch.service_state({'LoadState': 'masked'}), 'masked')

    def test_a_timer_driven_job_reports_its_last_run_and_result_not_inactive(self):
        timer = {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled'}
        finished = {'ActiveState': 'inactive', 'Result': 'success', 'ExecMainStartTimestamp': '@900', 'ConditionResult': 'yes'}
        job = system_watch.scheduled_job(timer, finished, 960)
        self.assertEqual((job['last_run'], job['result'], job['next_run'], job['healthy']), (900, 'success', 960, True))
        failed = system_watch.scheduled_job(timer, {**finished, 'ActiveState': 'failed', 'Result': 'exit-code'}, 960)
        self.assertEqual((failed['result'], failed['healthy']), ('exit-code', False))
        skipped = system_watch.scheduled_job(timer, {'ActiveState': 'inactive', 'ConditionResult': 'no',
                                                     'ConditionTimestamp': '@950'}, 960)
        self.assertEqual((skipped['last_run'], skipped['result'], skipped['healthy']), (950, 'skipped', True))
        never = system_watch.scheduled_job(timer, {'ActiveState': 'inactive', 'Result': 'success', 'ConditionResult': 'no',
                                                   'ConditionTimestamp': '', 'ExecMainStartTimestamp': ''}, 960)
        self.assertEqual((never['last_run'], never['result'], never['healthy']), (None, None, True))
        running = system_watch.scheduled_job(timer, {**finished, 'ActiveState': 'activating'}, None)
        self.assertEqual((running['running'], running['result'], running['healthy']), (True, None, True))
        # Off by choice is fine; enabled but not scheduled means the job stopped running.
        off = system_watch.scheduled_job({**timer, 'ActiveState': 'inactive', 'UnitFileState': 'disabled'}, finished, None)
        self.assertEqual((off['scheduled'], off['next_run'], off['healthy']), (False, None, True))
        stopped = system_watch.scheduled_job({**timer, 'ActiveState': 'inactive'}, finished, None)
        self.assertFalse(stopped['healthy'])
        self.assertIsNone(system_watch.scheduled_job({'LoadState': 'not-found'}, {}, None))


@unittest.skipUnless(os.name == 'posix', 'Runs a stand-in postqueue')
class MailQueueTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.postqueue = Path(self.folder.name) / 'postqueue'

    def tearDown(self):
        self.folder.cleanup()

    def queue(self, entries, status=0):
        lines = ''.join(json.dumps(entry) + '\n' for entry in entries)
        self.postqueue.write_text("#!/bin/sh\ncat <<'END'\n" + lines + 'END\nexit ' + str(status) + '\n')
        self.postqueue.chmod(0o700)

    def test_counts_and_oldest_arrival_without_recipients(self):
        now = int(time.time())
        entry = {'queue_name': 'deferred', 'queue_id': 'ABC', 'sender': 'shop@example.com', 'message_size': 900,
                 'recipients': [{'address': 'customer@example.com', 'delay_reason': 'connection timed out'}]}
        self.queue([{**entry, 'arrival_time': now - 7200}, {**entry, 'arrival_time': now - 60}])
        result = system_watch.mail_queue(now, self.postqueue)
        self.assertEqual({key: result[key] for key in ('available', 'count', 'oldest_at', 'stuck', 'complete')},
                         {'available': True, 'count': 2, 'oldest_at': now - 7200, 'stuck': True, 'complete': True})
        self.assertNotIn('example.com', json.dumps(result))
        self.queue([{**entry, 'arrival_time': now - 60}])
        self.assertFalse(system_watch.mail_queue(now, self.postqueue)['stuck'])
        self.queue([])
        self.assertEqual((system_watch.mail_queue(now, self.postqueue)['count'],
                          system_watch.mail_queue(now, self.postqueue)['oldest_at']), (0, None))

    def test_unreadable_queue_and_absent_postfix(self):
        self.queue([], status=69)
        self.assertEqual(system_watch.mail_queue(0, self.postqueue), {'available': False, 'stuck_after': 3600})
        self.queue([{'arrival_time': 'yesterday'}])
        self.assertFalse(system_watch.mail_queue(0, self.postqueue)['available'])
        self.assertIsNone(system_watch.mail_queue(0, Path(self.folder.name) / 'absent'))


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Service watch state is root-owned')
class WatchRunTests(unittest.TestCase):
    def test_failed_job_and_stuck_mail_alert_like_a_failed_service(self):
        from companion.incidents import IncidentStore
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state, output = root / 'system', root / 'observations' / 'latest.json'
            state.mkdir(mode=0o700)
            output.parent.mkdir(mode=0o755)
            configuration = root / 'system-watch.json'
            configuration.write_text(json.dumps({'units': [{'name': 'nginx.service', 'label': 'Shop: Nginx', 'recover': False},
                                                           {'name': 'mysql.service', 'label': 'Shop: Database', 'recover': False}]}))
            configuration.chmod(0o600)

            def properties(names):
                result = {name: {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled',
                                 'ActiveEnterTimestamp': '@1000'} for name in names}
                result['companion-telemetry.service'] = {'LoadState': 'loaded', 'ActiveState': 'failed', 'Result': 'exit-code',
                                                         'ExecMainStartTimestamp': '@1000'}
                # Where MariaDB is installed, mysql.service is its alias.
                result['mysql.service'] = dict(result['mysql.service'], Id='mariadb.service')
                return result
            stuck = {'available': True, 'count': 3, 'complete': True, 'oldest_at': 1, 'stuck': True, 'stuck_after': 3600}
            with mock.patch.object(system_watch, 'unit_properties', side_effect=properties), \
                    mock.patch.object(system_watch, 'next_runs', return_value={'companion-monitor.timer': 2000}), \
                    mock.patch.object(system_watch, 'mail_queue', return_value=stuck), \
                    mock.patch.object(system_watch.os, 'chown'), mock.patch('grp.getgrnam'):
                for _ in range(2):
                    system_watch.run(configuration, state, output, ())
            exported = json.loads(output.read_text())
            self.assertEqual(exported['services'][0]['since'], 1000)
            # The export names the unit systemd runs, so the interface names the installed product.
            self.assertEqual([(item['unit'], item['name']) for item in exported['services']],
                             [('nginx.service', 'Shop: Nginx'), ('mariadb.service', 'Shop: Database')])
            self.assertEqual(exported['mail'], stuck)
            failed = next(item for item in exported['scheduled'] if item['unit'] == 'companion-telemetry.timer')
            self.assertEqual((failed['result'], failed['healthy']), ('exit-code', False))
            store = IncidentStore(state / 'monitor.sqlite3')
            try:
                pending = {(event[1], event[2]) for event in store.pending()}
            finally:
                store.close()
            self.assertEqual(pending, {('Scheduled job: Performance history', 'down'), ('Outgoing mail', 'down')})


if __name__ == '__main__':
    unittest.main()
