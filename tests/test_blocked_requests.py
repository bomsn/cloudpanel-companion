import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from companion import relay
from companion.operations import Operations
from companion.relay import BlockedLog, Relay, blocked_entry, default_policy, normalize_policy


def report(**changes):
    value = {'kind': 'http', 'source_type': 'plugin', 'source': 'example-mailer', 'label': 'Example Mailer',
             'method': 'POST', 'scheme': 'https', 'host': 'api.example.com', 'path': '/v3/subscribers'}
    value.update(changes)
    return value


class BlockedEntryTests(unittest.TestCase):
    def test_a_report_names_only_the_destination_and_its_source(self):
        self.assertEqual(blocked_entry(report()), report())
        for change in [{'path': '/v3/subscribers?apikey=secret'}, {'path': '/v3/a/b'}, {'path': '/v3/../live'},
                       {'path': 'v3'}, {'method': 'post'}, {'scheme': 'ftp'}, {'host': 'API.example.com'},
                       {'host': 'example.com/path'}, {'source': '../plugin'}, {'source_type': 'library'},
                       {'kind': 'mail'}, {'label': 'Name\nInjected'}, {'label': ''}, {'body': 'secret'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                blocked_entry(report(**change))
        for value in ({'host': 'example.com:8443'}, {'host': '[::1]'}, {'scheme': 'http'}, {'path': '/'}):
            with self.subTest(value=value):
                blocked_entry(report(**value))


class BlockedLogTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / 'blocked.json'

    def tearDown(self):
        self.folder.cleanup()

    def test_repeats_are_counted_and_written_at_most_once_a_minute(self):
        log = BlockedLog(self.path)
        with mock.patch.object(BlockedLog, 'save', wraps=log.save) as save:
            log.record(report(), 1000)
            log.record(report(), 1010)
            log.record(report(), 1020)
            self.assertEqual(save.call_count, 1)
            log.record(report(), 1061)
            self.assertEqual(save.call_count, 2)
            log.record(report(path='/v3/lists'), 1062)
            self.assertEqual(save.call_count, 3)
        entries = log.listing(1063)
        self.assertEqual([entry['count'] for entry in entries if entry['path'] == '/v3/subscribers'], [4])
        self.assertEqual(len(entries), 2)

    def test_the_log_survives_a_restart(self):
        log = BlockedLog(self.path)
        log.record(report(), 1000)
        log.record(report(), 1070)
        saved = BlockedLog(self.path).listing(1080)
        self.assertEqual((saved[0]['count'], saved[0]['first_seen'], saved[0]['last_seen']), (2, 1000, 1070))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_bounded_by_entries_and_age(self):
        log = BlockedLog(self.path)
        for number in range(relay.BLOCKED_ENTRIES + 5):
            log.record(report(path='/p' + str(number)), 1000 + number)
        entries = log.listing(2000)
        self.assertEqual(len(entries), relay.BLOCKED_ENTRIES)
        self.assertNotIn('/p0', [entry['path'] for entry in entries])
        self.assertEqual(log.listing(1000 + relay.BLOCKED_ENTRIES + 4 + relay.BLOCKED_RETENTION + 1), [])

    def test_report_flood_is_dropped_not_counted(self):
        log = BlockedLog(self.path)
        for number in range(relay.REPORTS_PER_MINUTE):
            log.record(report(path='/p' + str(number % 50)), 1000)
        self.assertEqual(log.record(report(path='/late'), 1001), {'recorded': False})
        self.assertNotIn('/late', [entry['path'] for entry in log.listing(1002)])

    def test_clear_and_unreadable_files(self):
        log = BlockedLog(self.path)
        log.record(report(), 1000)
        log.clear(1001)
        self.assertEqual(BlockedLog(self.path).listing(1002), [])
        self.path.write_text('{"not": "a list"')
        self.assertEqual(BlockedLog(self.path).listing(1003), [])


class RelayBlockedTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.relay = Relay({'staging_uid': 1005, 'policy_path': '/unused', 'forbidden_hosts': []}, Path(self.folder.name))

    def tearDown(self):
        self.folder.cleanup()

    def test_staging_reports_without_a_worker_or_the_test_budget(self):
        with mock.patch('companion.relay.subprocess.run') as worker:
            for _ in range(40):
                self.assertEqual(self.relay.action(1005, {'operation': 'blocked', 'entry': report()}), {'recorded': True})
        worker.assert_not_called()
        self.assertEqual(self.relay.events, [])
        with self.assertRaises(ValueError):
            self.relay.action(1005, {'operation': 'blocked', 'entry': report(path='/a?b=c')})

    def test_only_root_lists_or_clears(self):
        self.relay.action(1005, {'operation': 'blocked', 'entry': report()})
        # Staging's own identity sends list or clear to the test worker, which refuses them.
        for uid in (1005, 1006):
            for operation in ('blocked_list', 'blocked_clear'):
                with self.subTest(uid=uid, operation=operation), self.assertRaises(ValueError),                         mock.patch('companion.relay.subprocess.run', side_effect=ValueError('worker refused')):
                    self.relay.action(uid, {'operation': operation})
        self.assertEqual(len(self.relay.action(0, {'operation': 'blocked_list'})['entries']), 1)
        self.assertEqual(self.relay.action(0, {'operation': 'blocked_clear'}), {'cleared': True})
        self.assertEqual(self.relay.action(0, {'operation': 'blocked_list'})['entries'], [])


class OperationsBlockedTests(unittest.TestCase):
    def setUp(self):
        site = {'host': 'stg.example.com', 'source_host': 'shop.example.com', 'user': 'shopstg',
                'relay_socket': relay.socket_path('shopstg')}
        self.operations = Operations({'sites': {'shop': site}})
        include = 'include /etc/cloudpanel-companion/sites/shopstg-access.conf;'
        self.patches = [mock.patch.object(Path, 'read_text', return_value=include + '\n' + include),
                        mock.patch.object(Path, 'exists', return_value=False)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def test_list_and_clear_go_to_the_site_relay(self):
        with mock.patch('companion.relay.operator_relay', return_value={'entries': []}) as call:
            self.assertEqual(self.operations.action({'site': 'shop', 'operation': 'blocked_list', 'actor': 'operator'}), {'entries': []})
            call.assert_called_once_with(relay.socket_path('shopstg'), 'blocked_list', None)
        audit = mock.mock_open()
        with mock.patch('companion.relay.operator_relay', return_value={'cleared': True}) as call, mock.patch.object(Path, 'open', audit):
            self.assertEqual(self.operations.action({'site': 'shop', 'operation': 'blocked_clear', 'actor': 'operator'}), {'saved': True})
            call.assert_called_once_with(relay.socket_path('shopstg'), 'blocked_clear')
        self.assertEqual(json.loads(audit().write.call_args.args[0])['operation'], 'blocked_clear')

    def test_an_operator_identity_is_required(self):
        with mock.patch('companion.relay.operator_relay') as call, self.assertRaises(ValueError):
            self.operations.action({'site': 'shop', 'operation': 'blocked_list'})
        call.assert_not_called()


class AllowPolicyTests(unittest.TestCase):
    def test_an_allowed_request_cannot_target_a_protected_host(self):
        policy = default_policy()
        policy.update(http_enabled=True, http_rules=[{'host': 'shop.example.com', 'path': '/wp-json', 'methods': ['POST']}])
        with self.assertRaises(ValueError):
            normalize_policy(policy, {'shop.example.com', 'stg.example.com'})


if __name__ == '__main__':
    unittest.main()
