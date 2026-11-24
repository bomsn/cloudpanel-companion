from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
from companion import probe_guard, security_log
from companion.incidents import IncidentStore

NOW = 1793500000


def database():
    db = sqlite3.connect(':memory:')
    db.executescript(security_log.SCHEMA)
    return db


def entry(at, ip, path='login', status=302, next_='login', method='POST', country=''):
    return {'at': at, 'ip': ip, 'country': country, 'method': method, 'path': path, 'status': status, 'next': next_}


def created(at):
    """CloudPanel's created_at text for a UTC timestamp."""
    return datetime.fromtimestamp(at, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def journal_entry(at, pid, message):
    return {'MESSAGE': message, '__REALTIME_TIMESTAMP': str(at * 1000000), '_PID': str(pid), '_BOOT_ID': 'b'}


class RuleTests(unittest.TestCase):
    def test_first_sign_in_sets_the_baseline_and_new_sources_are_named(self):
        self.assertEqual(security_log.new_source(set(), set(), '198.51.100.7', 'DE'), '')
        known = ({'198.51.100.7'}, {'DE'})
        self.assertEqual(security_log.new_source(*known, '198.51.100.7', 'DE'), '')
        self.assertEqual(security_log.new_source(*known, '198.51.100.8', 'DE'), 'ip')
        self.assertEqual(security_log.new_source(*known, '198.51.100.8', 'FR'), 'country')
        # A known address whose country Cloudflare reports differently is still a new country.
        self.assertEqual(security_log.new_source(*known, '198.51.100.7', 'FR'), 'country')
        # Without a Cloudflare country only the address can be judged.
        for unknown in ('', 'XX'):
            self.assertEqual(security_log.new_source(*known, '198.51.100.7', unknown), '')
            self.assertEqual(security_log.new_source(*known, '203.0.113.5', unknown), 'ip')

    def test_bursts_need_the_threshold_and_respect_the_quiet_period(self):
        self.assertFalse(security_log.burst_due(9, 'cloudpanel', None, NOW))
        self.assertTrue(security_log.burst_due(10, 'cloudpanel', None, NOW))
        self.assertFalse(security_log.burst_due(59, 'ssh', None, NOW))
        self.assertFalse(security_log.burst_due(80, 'cloudpanel', NOW - 3600, NOW))
        self.assertTrue(security_log.burst_due(80, 'cloudpanel', NOW - security_log.BURST_QUIET, NOW))

    def test_browser_is_a_short_label(self):
        cases = {
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0': 'Firefox 133 on Windows',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36': 'Chrome 142 on macOS',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0': 'Edge 142 on Windows',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1': 'Safari 18 on iOS',
            'curl/8.5.0': 'curl 8', '': 'Not reported', 'Unknown agent': 'Other client',
        }
        for agent, label in cases.items():
            with self.subTest(agent=agent):
                self.assertEqual(security_log.browser(agent), label)

    def test_attempted_names_are_inert(self):
        self.assertEqual(security_log.clean_user('root\n<b>\x1b[31m'), 'root?<b>?[31m')
        self.assertEqual(len(security_log.clean_user('a' * 500)), 64)


class SshTests(unittest.TestCase):
    def test_journal_lines_become_sign_ins_and_failures(self):
        accepted = security_log.ssh_entry(journal_entry(NOW, 10, 'Accepted publickey for deploy from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:x'))
        self.assertEqual((accepted['outcome'], accepted['user'], accepted['ip'], accepted['method']),
                         ('signin', 'deploy', '192.0.2.10', 'key'))
        password = security_log.ssh_entry(journal_entry(NOW, 11, 'Accepted password for deploy from 2001:db8::5 port 1 ssh2'))
        self.assertEqual(password['method'], 'password')
        for message, user in (('Invalid user admin from 203.0.113.4 port 4000', 'admin'),
                              ('Invalid user  from 203.0.113.4 port 4000', ''),
                              ('Failed password for root from 203.0.113.4 port 4000 ssh2', 'root'),
                              ('Failed password for invalid user test from 203.0.113.4 port 4000 ssh2', 'test'),
                              ('Connection closed by authenticating user root 203.0.113.4 port 4000 [preauth]', 'root')):
            with self.subTest(message=message):
                failed = security_log.ssh_entry(journal_entry(NOW, 12, message))
                self.assertEqual((failed['outcome'], failed['user'], failed['ip']), ('failed', user, '203.0.113.4'))
        for message in ('Disconnected from authenticating user root 203.0.113.4 port 4000 [preauth]',
                        'Connection reset by invalid user admin 203.0.113.4 port 4000 [preauth]'):
            with self.subTest(message=message):
                self.assertEqual(security_log.ssh_entry(journal_entry(NOW, 12, message))['ip'], '203.0.113.4')
        # A name the client chose cannot put another address in front of the one sshd appends.
        for message in ('Invalid user x from 192.0.2.66 port 1 from 203.0.113.4 port 4000',
                        'Failed password for invalid user x from 192.0.2.66 port 1 ssh2 from 203.0.113.4 port 4000 ssh2',
                        'Connection closed by invalid user x 192.0.2.66 port 1 [preauth] 203.0.113.4 port 4000 [preauth]'):
            with self.subTest(message=message):
                forged = security_log.ssh_entry(journal_entry(NOW, 14, message))
                self.assertEqual(forged['ip'], '203.0.113.4')
                self.assertNotIn(' ', forged['user'])
        for message in ('Received disconnect from 203.0.113.4 port 4000:11: Bye Bye [preauth]',
                        'Accepted publickey for deploy from not-an-address port 1 ssh2', None):
            self.assertIsNone(security_log.ssh_entry(journal_entry(NOW, 13, message)))

    def test_only_sshd_entries_recorded_by_journald_are_read(self):
        with mock.patch.object(security_log, 'json_lines', return_value=([], True, 0)) as read:
            security_log.journal(None, NOW - 60)
        arguments, timeout, limit = read.call_args.args
        self.assertIn('_UID=0', arguments)
        self.assertIn('_COMM=sshd', arguments)
        self.assertFalse(any(item.startswith('SYSLOG_IDENTIFIER') for item in arguments))
        # The journal is read against its own deadline, well inside the service's 45 seconds.
        self.assertEqual((timeout, limit), (security_log.JOURNAL_TIMEOUT, security_log.JOURNAL_LIMIT))
        self.assertLess(timeout, 45)

    def test_an_unreadable_cursor_continues_from_the_saved_time(self):
        found = [{'MESSAGE': 'x', '__CURSOR': 'c-1'}, {'MESSAGE': 'y', '__CURSOR': 'c-2'}]
        with mock.patch.object(security_log, 'json_lines', side_effect=[([], True, 1), (found, True, 0)]) as read:
            self.assertEqual(security_log.journal('stale', NOW - 60), (found, 'c-2'))
        self.assertIn('--after-cursor=stale', read.call_args_list[0].args[0])
        self.assertIn('--since=@' + str(NOW - 60), read.call_args_list[1].args[0])

    def test_a_failed_connection_counts_once(self):
        db = database()
        lines = [journal_entry(NOW - 30, 20, 'Invalid user admin from 203.0.113.4 port 4000'),
                 journal_entry(NOW - 29, 20, 'Connection closed by invalid user admin 203.0.113.4 port 4000 [preauth]'),
                 journal_entry(NOW - 20, 21, 'Connection closed by authenticating user root 203.0.113.4 port 4001 [preauth]'),
                 journal_entry(NOW - 10, 22, 'Accepted publickey for deploy from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:x')]
        with mock.patch.object(security_log, 'journal', return_value=(lines, 'cursor-1')):
            saved = security_log.ssh(db, None, NOW, [])
        self.assertEqual(saved, {'cursor': 'cursor-1', 'at': NOW - 10})
        outcomes = db.execute('SELECT outcome, user FROM events ORDER BY id').fetchall()
        self.assertEqual(outcomes, [('failed', 'admin'), ('failed', 'root'), ('signin', 'deploy')])
        # The same connection's closing line read in a later run is not counted again.
        with mock.patch.object(security_log, 'journal', return_value=([lines[1]], 'cursor-2')):
            security_log.ssh(db, saved, NOW, [])
        self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE outcome='failed'").fetchone()[0], 2)


class CloudPanelTests(unittest.TestCase):
    def panel_database(self, folder, rows):
        path = Path(folder) / 'db.sq3'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE event (id INTEGER PRIMARY KEY, created_at DATETIME, user_name TEXT, user_role TEXT, '
                       'event_name TEXT, event_data TEXT, source_ip_address TEXT, user_agent TEXT)')
            db.execute('CREATE TABLE user (id INTEGER PRIMARY KEY, user_name TEXT, mfa BOOLEAN, password TEXT)')
            db.execute("INSERT INTO user(user_name, mfa, password) VALUES('admin', 1, 'hash')")
            db.executemany("INSERT INTO event(created_at, user_name, user_role, event_name, source_ip_address, user_agent) "
                           "VALUES(?, ?, 'ROLE_ADMIN', ?, ?, 'Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0')", rows)
        return 'file:' + str(path) + '?mode=ro'

    def test_rejected_password_and_code_are_failures(self):
        db = database()
        security_log.cloudpanel_outcomes(db, [
            entry(NOW - 50, '198.51.100.7', country='DE'),
            entry(NOW - 40, '198.51.100.7', path='code', status=200, next_=''),
            entry(NOW - 30, '198.51.100.7', path='code', status=302, next_='other'),
            entry(NOW - 20, '198.51.100.7', method='GET', status=200, next_=''),
            entry(NOW - 10, '198.51.100.7', next_='other', country='DE')], NOW, [])
        self.assertEqual(db.execute('SELECT outcome, method, country FROM events ORDER BY id').fetchall(),
                         [('failed', 'password', 'DE'), ('failed', 'code', '')])
        self.assertEqual(db.execute('SELECT ip, country FROM pending_logins').fetchall(), [('198.51.100.7', 'DE')])

    def test_sign_in_takes_its_address_from_the_companion_log(self):
        db = database()
        # CloudPanel recorded a Cloudflare edge address; the panel log recorded the real client.
        security_log.cloudpanel_outcomes(db, [entry(NOW - 299.6, '198.51.100.7', next_='other', country='DE')], NOW, [])
        with tempfile.TemporaryDirectory() as folder:
            source = self.panel_database(folder, [
                (created(NOW - 300), 'admin', 'LOGIN', '198.51.100.200'),
                (created(NOW - 250), 'admin', 'SITE_DELETE', '198.51.100.200'),
                (created(NOW - 120), 'admin', 'LOGIN', '203.0.113.50')])
            last = security_log.cloudpanel_signins(db, None, NOW, [], source)
        self.assertEqual(last, 3)
        rows = db.execute('SELECT ip, country, verified, two_factor, browser FROM events ORDER BY id').fetchall()
        self.assertEqual(rows, [('198.51.100.7', 'DE', 1, 1, 'Firefox 133 on Linux'), ('203.0.113.50', '', 0, 1, 'Firefox 133 on Linux')])
        self.assertEqual(db.execute('SELECT COUNT(*) FROM pending_logins').fetchone()[0], 0)

    def test_a_record_waits_until_its_log_line_can_have_been_read(self):
        db = database()
        with tempfile.TemporaryDirectory() as folder:
            source = self.panel_database(folder, [(created(NOW), 'admin', 'LOGIN', '198.51.100.7')])
            at = NOW
            self.assertEqual(security_log.cloudpanel_signins(db, None, at + 5, [], source), 0)
            self.assertEqual(security_log.cloudpanel_signins(db, None, at + security_log.PANEL_SETTLE + 1, [], source), 1)


class StoreTests(unittest.TestCase):
    def test_ssh_sign_ins_alert_once_per_user_and_address_a_day_and_name_new_sources(self):
        db, alerts = database(), []
        # Read while catching up on older history: recorded and judged, never alerted.
        security_log.record(db, 'ssh', 'signin', NOW - 7200, '192.0.2.10', NOW, alerts, user='deploy', method='key')
        security_log.record(db, 'ssh', 'signin', NOW - 7100, '192.0.2.11', NOW, alerts, user='deploy', method='key')
        self.assertEqual(alerts, [])
        security_log.record(db, 'ssh', 'signin', NOW - 60, '192.0.2.12', NOW, alerts, user='deploy', method='key')
        # Automation reconnecting from the same address within a day alerts no more.
        security_log.record(db, 'ssh', 'signin', NOW - 30, '192.0.2.12', NOW, alerts, user='deploy', method='key')
        security_log.record(db, 'ssh', 'signin', NOW - 20, '192.0.2.12', NOW, alerts, user='backup', method='password')
        self.assertEqual([row[0] for row in db.execute('SELECT new_source FROM events ORDER BY id')], ['', 'ip', 'ip', '', ''])
        self.assertEqual([alert['event'] for alert in alerts], ['SSH sign-in from a new IP address: deploy from 192.0.2.12',
                                                                'SSH sign-in: backup from 192.0.2.12'])
        self.assertEqual(alerts[0]['details'], [('Account', 'deploy'), ('Source IP', '192.0.2.12'), ('Method', 'SSH key'),
                                                ('Source', 'New IP address'), ('Time', '01 Nov 2026, 02:25 UTC')])
        self.assertEqual(dict(alerts[1]['details'])['Source'], 'Known IP address')
        later = NOW + security_log.SSH_ALERT_WINDOW + 60
        security_log.record(db, 'ssh', 'signin', later, '192.0.2.12', later, alerts, user='deploy', method='key')
        self.assertEqual(alerts[-1]['event'], 'SSH sign-in: deploy from 192.0.2.12')
        self.assertEqual(len(alerts), 3)

    def test_every_panel_sign_in_alerts_and_an_unverified_address_is_never_judged(self):
        db, alerts = database(), []
        for second in (0, 30):
            security_log.record(db, 'cloudpanel', 'signin', NOW - 60 + second, '198.51.100.7', NOW, alerts, user='admin',
                                country='DE', browser_label='Firefox 133 on Linux', method='password', two_factor=True)
        self.assertEqual([alert['event'] for alert in alerts], ['CloudPanel sign-in: admin from 198.51.100.7, DE'] * 2)
        self.assertEqual(alerts[0]['details'], [
            ('Account', 'admin'), ('Source IP', '198.51.100.7'), ('Country', 'DE'), ('Method', 'Password'),
            ('Two-factor', 'Yes'), ('Browser', 'Firefox 133 on Linux'), ('Source', 'First recorded sign-in'),
            ('Time', '01 Nov 2026, 02:25 UTC')])
        self.assertEqual(dict(alerts[1]['details'])['Source'], 'Known IP address')
        # CloudPanel's own record (behind Cloudflare an edge address) still alerts, but is never called new.
        security_log.record(db, 'cloudpanel', 'signin', NOW, '172.70.1.2', NOW, alerts, user='admin', verified=False)
        self.assertEqual(alerts[-1]['event'], 'CloudPanel sign-in: admin from 172.70.1.2')
        self.assertEqual(dict(alerts[-1]['details'])['Source IP'], "172.70.1.2 (CloudPanel's own record, not verified)")
        self.assertEqual(dict(alerts[-1]['details'])['Source'], 'Not judged: the address is not verified')
        self.assertEqual(db.execute("SELECT new_source FROM events WHERE verified=0").fetchone()[0], '')
        # Failed attempts never alert one by one.
        security_log.record(db, 'cloudpanel', 'failed', NOW, '203.0.113.9', NOW, alerts)
        self.assertEqual(len(alerts), 3)

    def test_slack_gets_at_most_the_hourly_limit_and_one_note(self):
        db = database()
        alerts = [{'event': f'Sign-in {number}', 'details': []} for number in range(security_log.ALERT_LIMIT + 5)]
        admitted = security_log.admit(db, alerts, NOW)
        self.assertEqual(len(admitted), security_log.ALERT_LIMIT + 1)
        self.assertEqual(admitted[:-1], alerts[:security_log.ALERT_LIMIT])
        self.assertIn('More than 20 security alerts within an hour', admitted[-1]['event'])
        self.assertEqual(dict(admitted[-1]['details'])['Held back so far'], '5')
        # The rest of the hour stays quiet, with no second note; the next hour starts again.
        self.assertEqual(security_log.admit(db, alerts[:3], NOW + 600), [])
        security_log.prune(db, NOW + 3601)
        self.assertEqual(security_log.admit(db, alerts[:3], NOW + 3601), alerts[:3])

    def test_a_burst_alerts_once_per_quiet_period(self):
        db, alerts = database(), []
        for second in range(10):
            security_log.record(db, 'cloudpanel', 'failed', NOW - 300 + second, '203.0.113.9', NOW, alerts, country='NL')
        security_log.detect_burst(db, 'cloudpanel', NOW, alerts)
        security_log.detect_burst(db, 'cloudpanel', NOW + 60, alerts)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['event'], '10 failed CloudPanel sign-in attempts within 10 minutes, latest from 203.0.113.9, NL')
        later = NOW + security_log.BURST_QUIET + 1
        for second in range(10):
            security_log.record(db, 'cloudpanel', 'failed', later - 60 + second, '203.0.113.9', later, alerts)
        security_log.detect_burst(db, 'cloudpanel', later, alerts)
        self.assertEqual(len(alerts), 2)

    def test_retention_and_bounds_are_enforced(self):
        db = database()
        for at in (NOW - security_log.RETENTION - 1, NOW - 10):
            security_log.record(db, 'ssh', 'failed', at, '203.0.113.9', NOW, [])
        db.execute("INSERT INTO visits VALUES(?, 'cloudpanel', '203.0.113.9', '', 1)", (NOW - security_log.RETENTION - 86400,))
        db.execute('INSERT INTO pending_logins VALUES(?, ?, ?)', (NOW - 7200, '203.0.113.9', ''))
        with mock.patch.object(security_log, 'MAX_EVENTS', 1):
            security_log.record(db, 'ssh', 'failed', NOW - 5, '203.0.113.9', NOW, [])
            security_log.prune(db, NOW)
        self.assertEqual(db.execute('SELECT at FROM events').fetchall(), [(NOW - 5,)])
        self.assertEqual(db.execute('SELECT COUNT(*) FROM visits').fetchone()[0], 0)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM pending_logins').fetchone()[0], 0)

    def test_matching_records_are_bounded_and_ssh_connections_age_from_the_newest(self):
        db = database()
        db.executemany('INSERT INTO pending_logins VALUES(?, ?, ?)', [(NOW - 60 + n, '203.0.113.9', '') for n in range(5)])
        # Catching up on old journal history: an hour before the newest counted connection, not before now.
        db.executemany('INSERT INTO ssh_failed_connections VALUES(?, ?)',
                       [('b:1', NOW - 86400 * 30), ('b:2', NOW - 86400 * 30 + 3000), ('b:3', NOW - 86400 * 30 + 3700)])
        with mock.patch.object(security_log, 'MAX_PENDING', 2):
            security_log.prune(db, NOW)
        self.assertEqual([row[0] for row in db.execute('SELECT at FROM pending_logins ORDER BY at')], [NOW - 57, NOW - 56])
        self.assertEqual([row[0] for row in db.execute('SELECT connection FROM ssh_failed_connections ORDER BY at')], ['b:2', 'b:3'])
        with mock.patch.object(security_log, 'MAX_CONNECTIONS', 1):
            security_log.prune(db, NOW)
        self.assertEqual([row[0] for row in db.execute('SELECT connection FROM ssh_failed_connections')], ['b:3'])

    def test_a_full_database_frees_its_own_space_before_reading(self):
        db = database()
        db.execute('PRAGMA max_page_count=' + str(db.execute('PRAGMA page_count').fetchone()[0] + 40))
        expired = NOW - security_log.RETENTION - 60

        def add(at):
            with db:
                security_log.record(db, 'ssh', 'failed', at, '203.0.113.9', NOW, [], user='u' * 64)
        # Committed one at a time until the database is full: even one more entry is refused.
        for _ in range(100000):
            try:
                add(expired)
            except sqlite3.OperationalError:
                break
        with self.assertRaisesRegex(sqlite3.OperationalError, 'full'):
            add(NOW - 20)
        lines = [journal_entry(NOW - 10, 30, 'Invalid user admin from 203.0.113.4 port 4000')]
        cursor = {}
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(security_log.client_address, 'LOGS', {'cloudpanel': Path(folder) / 'absent.log'}), \
                mock.patch.object(security_log.probe_guard, 'CONFIG', Path(folder) / 'no-probe-guard.json'), \
                mock.patch.object(security_log, 'cloudpanel_signins', return_value=7), \
                mock.patch.object(security_log, 'journal', return_value=(lines, 'cursor-1')), db:
            self.assertEqual(security_log.gather(db, cursor, NOW, []), [])
        self.assertEqual(db.execute('SELECT at, user FROM events').fetchall(), [(NOW - 10, 'admin')])
        self.assertEqual((cursor['panel_event'], cursor['journal']['cursor']), (7, 'cursor-1'))

    def test_the_largest_database_the_bounds_allow_fits_the_limit(self):
        # Every table at its bound plus one run's intake, at a tenth of the size, with IPv6
        # addresses and the longest names written in random order.
        import random
        scale, pick = 10, random.Random(7)
        def address():
            return ':'.join('%04x' % pick.randrange(65536) for _ in range(8))
        intake = security_log.JOURNAL_LIMIT + security_log.PANEL_RECORDS + 3 * 1024 * 1024 // 100
        db = database()
        before = db.execute('PRAGMA page_count').fetchone()[0]
        db.executemany("INSERT INTO events(panel,outcome,at,user,ip,country,browser,method,two_factor,verified,new_source,burst) "
                       "VALUES('cloudpanel','failed',?,?,?,'XX','Python requests 123 on ChromeOS','password',1,1,'country',99999)",
                       [(NOW - pick.randrange(security_log.RETENTION), 'u' * 64, address())
                        for _ in range((security_log.MAX_EVENTS + intake) // scale)])
        days = security_log.RETENTION // 86400 + 2
        db.executemany("INSERT INTO visits VALUES(?, ?, ?, 'XX', 2000000000)",
                       [(day * 86400, panel, address()) for day in range(days) for panel in security_log.client_address.LOGS
                        for _ in range((security_log.MAX_DAILY_SOURCES + 1) // scale)])
        db.executemany("INSERT INTO pending_logins VALUES(?, ?, 'XX')",
                       [(NOW - pick.random() * 3600, address()) for _ in range((security_log.MAX_PENDING + intake) // scale)])
        db.executemany('INSERT INTO ssh_failed_connections VALUES(?, ?)',
                       [('%032x:%07d' % (pick.getrandbits(128), number), NOW) for number in
                        range((security_log.MAX_CONNECTIONS + security_log.JOURNAL_LIMIT) // scale)])
        for table in security_log.PROBE_TABLES:
            key = (lambda: '/' + ''.join(pick.choice('abcdefghij/.') for _ in range(probe_guard.PATH_LIMIT - 1))) \
                if table.endswith('_paths') else address
            db.executemany(f"INSERT INTO {table} VALUES(?, ?, 'XX', 2000000000)",
                           [(day * 86400, key()) for day in range(days) for _ in range((security_log.PROBE_DAILY + 1) // scale)])
        db.executemany('INSERT INTO probe_bans VALUES(?, ?, ?, ?)',
                       [(address(), NOW - number, NOW + 604800, NOW) for number in range(security_log.MAX_BANS // scale)])
        used = (db.execute('PRAGMA page_count').fetchone()[0] - before) * db.execute('PRAGMA page_size').fetchone()[0]
        # At least a quarter of the limit stays free for fragmentation (about a third does).
        self.assertLess(used * scale, security_log.DATABASE_LIMIT * 3 / 4)

    def test_visits_are_counted_per_day_and_bounded(self):
        db = database()
        day = NOW // 86400 * 86400
        security_log.count_visits(db, 'companion', [entry(day + 10, '198.51.100.7', country='DE'),
                                                    entry(day + 20, '198.51.100.7', country='DE'),
                                                    entry(day + 30, '2001:db8::1', country='FR'),
                                                    entry(day - 86400, '198.51.100.7', country='DE')])
        with mock.patch.object(security_log, 'MAX_DAILY_SOURCES', 2):
            security_log.count_visits(db, 'companion', [entry(day + 40, '203.0.113.9', country='NL')])
        summary = security_log.visits_summary(db, 'companion', NOW)
        self.assertEqual(len(summary['days']), 7)
        self.assertEqual(summary['days'][0], {'day': day, 'requests': 4, 'ips': 2})
        self.assertEqual(summary['days'][1], {'day': day - 86400, 'requests': 1, 'ips': 1})
        self.assertEqual((summary['requests'], summary['ips'], summary['country_count']), (5, 2, 2))
        self.assertEqual(summary['top_ips'][0], {'ip': '198.51.100.7', 'country': 'DE', 'requests': 3})
        self.assertEqual(summary['countries'][0]['country'], 'DE')

    def test_summary_counts_windows_and_groups_failed_sources(self):
        rows = [{'outcome': outcome, 'at': at, 'user': user, 'ip': ip, 'country': '', 'browser': '', 'method': '',
                 'two_factor': False, 'verified': True, 'new_source': '', 'burst': 0}
                for outcome, at, user, ip in (('signin', NOW - 60, 'deploy', '192.0.2.10'),
                                              ('failed', NOW - 120, 'root', '203.0.113.4'),
                                              ('failed', NOW - 130, 'admin', '203.0.113.4'),
                                              ('failed', NOW - 3 * 86400, 'root', '203.0.113.5'))]
        summary = security_log.panel_summary(rows, rows[:1], NOW)
        self.assertEqual((summary['signins_24h'], summary['signins_7d'], summary['failed_24h'], summary['failed_7d']), (1, 1, 2, 3))
        self.assertEqual(summary['failed_sources'][0], {'ip': '203.0.113.4', 'country': '', 'attempts': 2, 'first_at': NOW - 130,
                                                        'last_at': NOW - 120, 'users': ['admin', 'root'], 'more_users': 0,
                                                        'unnamed': 0, 'steps': [], 'burst': 0})
        self.assertEqual((summary['source_count'], summary['more_sources']), (2, 0))
        # Seven UTC days, oldest first, for the Security page's chart.
        self.assertEqual(len(summary['days']), 7)
        self.assertEqual(summary['days'][-1]['day'], NOW // 86400 * 86400)
        self.assertEqual(sum(day['signins'] for day in summary['days']), 1)
        self.assertEqual(sum(day['failed'] for day in summary['days']), 3)

    def test_attempts_without_a_name_are_counted_not_listed(self):
        rows = [{'outcome': 'failed', 'at': NOW - number, 'user': user, 'ip': '203.0.113.4', 'country': '', 'browser': '',
                 'method': 'password', 'two_factor': False, 'verified': True, 'new_source': '', 'burst': 0}
                for number, user in enumerate(('operator', '', ''))]
        source = security_log.failed_sources(rows)[0]
        self.assertEqual((source['attempts'], source['users'], source['unnamed']), (3, ['operator'], 2))

    def test_failed_attempts_are_one_row_per_source_newest_activity_first(self):
        def failed(at, user, ip, country='NL', method='password', burst=0):
            return {'outcome': 'failed', 'at': at, 'user': user, 'ip': ip, 'country': country, 'browser': '',
                    'method': method, 'two_factor': False, 'verified': True, 'new_source': '', 'burst': burst}
        bot = [failed(NOW - 600 + second, name, '203.0.113.77', burst=10 if second == 9 else 0)
               for second, name in enumerate(['admin', 'root', 'admin', 'test', 'admin', 'root', 'oracle', 'git', 'admin', 'ubuntu'])]
        person = [failed(NOW - 60, 'operator', '198.51.100.24', 'GB', 'code')]
        others = [failed(NOW - 7200 - number, 'root', '192.0.2.' + str(number)) for number in range(security_log.SOURCES)]
        summary = security_log.panel_summary(bot + person + others, [], NOW)
        first, second = summary['failed_sources'][:2]
        self.assertEqual((first['ip'], first['country'], first['attempts'], first['steps']), ('198.51.100.24', 'GB', 1, ['code']))
        self.assertEqual((second['ip'], second['attempts'], second['first_at'], second['last_at'], second['burst']),
                         ('203.0.113.77', 10, NOW - 600, NOW - 591, 10))
        self.assertEqual((second['users'], second['more_users']), (['admin', 'root', 'git'], 3))
        self.assertEqual(len(summary['failed_sources']), security_log.SOURCES)
        self.assertEqual((summary['source_count'], summary['more_sources']), (security_log.SOURCES + 2, 2))


class SpoolTests(unittest.TestCase):
    def spool(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory())) / 'security-alerts'
        folder.mkdir(mode=0o700)
        return folder

    def test_interface_alerts_are_validated_and_worded_here(self):
        folder = self.spool()
        signin = {'kind': 'signin', 'source': 'country', 'first': False, 'user': 'operator', 'two_factor': True,
                  'browser': 'Firefox 133 on Windows', 'at': NOW, 'ip': '198.51.100.7', 'country': 'DE'}
        (folder / '1793500000-0123456789abcdef.json').write_text(json.dumps(signin))
        # A browser label browser() could never produce is message text, and is refused.
        (folder / '1793500000-1123456789abcdef.json').write_text(json.dumps({**signin, 'browser': 'Click https://attacker.example'}))
        (folder / '1793500001-0123456789abcdef.json').write_text(json.dumps(
            {'kind': 'burst', 'count': 12, 'at': NOW, 'ip': '198.51.100.7, 203.0.113.1', 'country': ''}))
        (folder / '1793500002-0123456789abcdef.json').write_text(json.dumps(
            {'kind': 'message', 'text': 'Click https://attacker.example', 'at': NOW, 'ip': '198.51.100.7'}))
        (folder / '.1793500003-0123456789abcdef.json.new').write_text('{')
        os.symlink('/etc/hostname', folder / '1793500004-0123456789abcdef.json')
        alerts, handle = security_log.spool_alerts(folder, os.getuid())
        self.assertEqual(alerts, [{'event': 'Companion sign-in from a new country: operator from 198.51.100.7, DE', 'details': [
            ('Account', 'operator'), ('Source IP', '198.51.100.7'), ('Country', 'DE'), ('Method', 'Password'),
            ('Two-factor', 'Yes'), ('Browser', 'Firefox 133 on Windows'), ('Source', 'New country'),
            ('Time', '01 Nov 2026, 02:26 UTC')]}])
        security_log.clear_spool(handle)
        # Read entries are removed; a file still being written is left for the next run.
        self.assertEqual(sorted(path.name for path in folder.iterdir()), ['.1793500003-0123456789abcdef.json.new'])

    def test_a_pipe_in_the_spool_cannot_stall_the_collector(self):
        folder = self.spool()
        os.mkfifo(folder / '1793500000-0123456789abcdef.json', 0o600)
        alerts, handle = security_log.spool_alerts(folder, os.getuid())
        self.assertEqual(alerts, [])
        security_log.clear_spool(handle)

    def test_a_spool_others_can_write_is_refused(self):
        folder = self.spool()
        folder.chmod(0o770)
        with self.assertRaises(ValueError):
            security_log.spool_alerts(folder, os.getuid())

    def test_alerts_join_the_system_outbox_only_with_slack(self):
        alert = {'event': 'SSH sign-in from a new IP address', 'details': [('Account', 'deploy'), ('Method', 'SSH key')]}
        with tempfile.TemporaryDirectory() as folder:
            store, slack = Path(folder), Path(folder) / 'slack.json'
            self.assertEqual(security_log.deliver([alert], NOW, store, slack), 0)
            slack.write_text('{}')
            self.assertEqual(security_log.deliver([alert], NOW, store, slack), 1)
            incidents = IncidentStore(store / 'monitor.sqlite3')
            try:
                self.assertEqual([(row[1], row[2], json.loads(row[5])) for row in incidents.pending(NOW)],
                                 [('SSH sign-in from a new IP address', 'security', [['Account', 'deploy'], ['Method', 'SSH key']])])
            finally:
                incidents.close()


if __name__ == '__main__':
    unittest.main()


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.probes, self.access = self.folder / 'probes.log', self.folder / 'access.log'
        self.enterContext(mock.patch.object(probe_guard, 'PROBE_LOG', self.probes))
        self.probes.write_text('')
        self.access.write_text('')

    def probe(self, at, ip, path, country='DE'):
        return json.dumps({'at': at + 0.5, 'ip': ip, 'edge': '172.70.1.2', 'country': country, 'host': 'shop.example.com',
                           'method': 'GET', 'path': path, 'status': 404, 'agent': 'curl/8.5.0'}) + '\n'

    def not_found(self, at, ip, target):
        stamp = datetime.fromtimestamp(at, timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')
        return f'{ip} - - [{stamp}] "GET {target} HTTP/2.0" 404 162 "-" "curl/8.5.0" "{ip}"\n'

    def gather(self, db, cursor, now, bans=()):
        with mock.patch.object(probe_guard, 'active_bans', return_value=list(bans)):
            return security_log.gather_probes(db, cursor, now, str(self.access))

    def test_probes_not_found_pages_and_bans_are_counted_and_summarised(self):
        db, cursor = database(), {}
        # The first run starts at the end of each log; nothing earlier is invented.
        self.probes.write_text(self.probe(NOW - 99, '203.0.113.9', '/.env'))
        self.assertEqual(self.gather(db, cursor, NOW), [])
        self.assertEqual(db.execute('SELECT COUNT(*) FROM probe_paths').fetchone()[0], 0)
        with self.probes.open('a') as stream:
            for path in ('/.env', '/.env', '/.git/config', '/backup.sql'):
                stream.write(self.probe(NOW - 60, '203.0.113.9', path, 'NL'))
            stream.write(self.probe(NOW - 86400 - 60, '2001:db8::7', '/.env', ''))
            stream.write('{"at": "not a probe line"}\n')
        with self.access.open('a') as stream:
            stream.write(self.not_found(NOW - 50, '198.51.100.20', '/config/aws.json?key=secret'))
            stream.write(self.not_found(NOW - 40, '198.51.100.20', '/.env'))
            stream.write(self.not_found(NOW - 30, '198.51.100.21', '/alfa.php'))
        bans = [('203.0.113.9', NOW - 30, NOW + 86370)]
        self.assertEqual(self.gather(db, cursor, NOW, bans), [])
        summary = security_log.probes_summary(db, NOW)
        self.assertEqual((summary['requests'], summary['sources'], summary['missing']), (5, 2, 2))
        self.assertEqual(sum(day['requests'] for day in summary['days']), 5)
        self.assertEqual(summary['days'][-1]['requests'], 4)
        self.assertEqual(summary['paths'][0], {'key': '/.env', 'label': '', 'requests': 3})
        self.assertEqual(summary['top_sources'][0], {'key': '203.0.113.9', 'label': 'NL', 'requests': 4})
        # A probe answered here never appears among the pages that reached the website; no query string is kept.
        self.assertEqual([item['key'] for item in summary['missing_paths']], ['/alfa.php', '/config/aws.json'])
        self.assertNotIn('secret', json.dumps(summary))
        self.assertEqual(summary['active'], [{'ip': '203.0.113.9', 'start': NOW - 30, 'until': NOW + 86370, 'country': 'NL'}])
        self.assertEqual(summary['recent_count'], 1)
        self.assertIn('(http.request.uri.path contains "/.env")', summary['patterns']['expression'])
        # A ban Fail2ban no longer lists is history, not active.
        self.gather(db, cursor, NOW + 60)
        later = security_log.probes_summary(db, NOW + 60)
        self.assertEqual((later['active'], later['recent_count']), ([], 1))

    def test_unreadable_sources_are_reported_and_bans_need_the_jail(self):
        db = database()
        self.probes.unlink()
        self.probes.mkdir()
        with mock.patch.object(probe_guard, 'active_bans', side_effect=ValueError('not running')):
            self.assertEqual(security_log.gather_probes(db, {}, NOW, None), ['Website probe log', 'Website probe bans'])

    def test_each_day_keeps_a_bounded_number_of_keys_and_an_exact_total(self):
        db = database()
        day = NOW // 86400 * 86400
        with mock.patch.object(security_log, 'PROBE_DAILY', 2):
            security_log.tally(db, 'probe_paths', [(day + 1, '/a', ''), (day + 2, '/b', ''), (day + 3, '/c', ''),
                                                   (day + 4, '/a', ''), (day + 5, '/d', '')])
        self.assertEqual(dict(db.execute('SELECT key, requests FROM probe_paths')), {'/a': 2, '/b': 1, '': 2})
        db.execute("INSERT INTO probe_bans VALUES('192.0.2.1', ?, ?, ?)", (NOW - security_log.RETENTION - 1, NOW, NOW))
        db.execute("INSERT INTO probe_sources VALUES(?, '192.0.2.1', '', 1)", (NOW - security_log.RETENTION - 86400,))
        security_log.prune(db, NOW)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM probe_bans').fetchone()[0], 0)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM probe_sources').fetchone()[0], 0)
