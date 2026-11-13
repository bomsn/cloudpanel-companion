import subprocess
import unittest
from unittest import mock
from companion import isolation
from companion.network import deny_outbound, table_name, deny_local_submission

# A table as 0.2.3 rendered it and `nft list table` prints it back.
LOADED_023 = '''table inet companion_staging_1005 {
\tchain output {
\t\ttype filter hook output priority filter + 10; policy accept;
\t\tmeta skuid != 1005 return
\t\tct direction reply return
\t\tip daddr 127.0.0.1 tcp dport 6083 return
\t\tmeta l4proto tcp counter packets 9 bytes 540 reject with tcp reset
\t\tcounter packets 0 bytes 0 reject with icmpx admin-prohibited
\t}
}
'''


def chains_of(policy):
    """Rules per chain of a rendered single-table nftables policy."""
    chains, current = {}, None
    for line in (raw.strip() for raw in policy.splitlines()):
        if line.startswith('chain '):
            current = chains.setdefault(line.split()[1], [])
        elif line == '}':
            current = None
        elif line and current is not None:
            current.append(line)
    return chains


class NetworkTests(unittest.TestCase):
    def test_system_and_invalid_identities_rejected(self):
        for uid in (0, 999, -1, True, '1003', 2147483648):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                deny_outbound(uid)

    def test_policy_is_scoped_and_does_not_flush_other_firewalls(self):
        policy = deny_outbound(1003)
        self.assertEqual(table_name(1003), 'companion_staging_1003')
        self.assertIn('meta skuid 1003 jump staging', policy)
        self.assertIn('ct direction reply return', policy)
        self.assertNotIn('flush', policy)
        self.assertNotIn('ct state established', policy)

    def test_packets_without_an_owner_never_reach_a_reject(self):
        # Kernel-sent ACKs/RSTs of closed connections have no owner; `skuid != UID return`
        # does not match them, so they fell through to the rejects for every user and
        # left loopback servers in LAST-ACK. Only a positive owner match may lead there.
        for ports in ((), (6083,)):
            chains = chains_of(deny_outbound(1003, ports))
            self.assertEqual(chains['output'], ['type filter hook output priority 10; policy accept;',
                                                'meta skuid 1003 jump staging'])
            self.assertEqual(chains['staging'][0], 'ct direction reply return')
            self.assertTrue(chains['staging'][-1].endswith('reject with icmpx type admin-prohibited'))
            self.assertNotIn('skuid !=', deny_outbound(1003, ports))

    def test_update_rerenders_loaded_tables_with_their_exceptions(self):
        tables = ('table ip filter\ntable inet f2b-table\ntable inet companion_staging_1005\n'
                  'table inet companion_staging_1007\ntable inet companion_web_1004\n')
        read = {'companion_staging_1005': LOADED_023,
                'companion_staging_1007': LOADED_023.replace('1005', '1007').replace(
                    '\t\tip daddr 127.0.0.1 tcp dport 6083 return\n', '')}
        self.assertEqual(isolation.loaded_policies(tables, read.__getitem__), [(1005, (6083,)), (1007, ())])

        applied = []

        def nft(arguments, input=None, **kwargs):
            if arguments[1:] == ['list', 'tables']:
                return subprocess.CompletedProcess(arguments, 0, tables.encode(), b'')
            if arguments[1:3] == ['list', 'table']:
                return subprocess.CompletedProcess(arguments, 0, read[arguments[-1]].encode(), b'')
            if arguments[1:] == ['-f', '-']:
                applied.append(input.decode())
            return subprocess.CompletedProcess(arguments, 0, b'', b'')
        with mock.patch.object(isolation.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(isolation.subprocess, 'run', side_effect=nft):
            self.assertEqual(isolation.refresh_loaded(), [(1005, (6083,)), (1007, ())])
        # One atomic batch per table: the old table goes in the same transaction as the new one arrives.
        self.assertEqual(applied, ['delete table inet companion_staging_1005\n' + deny_outbound(1005, (6083,)),
                                   'delete table inet companion_staging_1007\n' + deny_outbound(1007)])

    def test_mail_exclusion_keeps_existing_restrictions(self):
        self.assertEqual(deny_local_submission(['stage'], 'root'), '!stage, root')
        self.assertEqual(deny_local_submission(['stage'], ''), '!stage')
        self.assertEqual(deny_local_submission(['stage'], '!stage, !stage, root'), '!stage, root')
        self.assertEqual(deny_local_submission(['stage'], '!other, !stage, static:anyone'), '!stage, !other, static:anyone')
        with self.assertRaises(ValueError):
            deny_local_submission(['stage,static:all'], 'root')

    def test_optional_local_service_is_explicit_and_never_broadens_external_network(self):
        policy = deny_outbound(1003, (6083,))
        self.assertIn('ip daddr 127.0.0.1 tcp dport 6083 return', policy)
        self.assertIn('counter reject with icmpx type admin-prohibited', policy)
        self.assertNotIn('ip daddr 127.0.0.1 tcp dport', deny_outbound(1003))
        with self.assertRaises(ValueError):
            deny_outbound(1003, (443,))


if __name__ == '__main__':
    unittest.main()
