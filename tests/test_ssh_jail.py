from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock
from companion import probe_guard, ssh_jail

# Any file that exists stands in for fail2ban-client, which the installer requires.
CLIENT = __file__
# `sshd -T` as Ubuntu 24.04 prints it while SSH listens on 22 and PORT (4022 here).
SSHD = 'port 22\nport 4022\naddressfamily any\nlistenaddress [::]:4022\nlistenaddress 0.0.0.0:4022\n' \
       'listenaddress [::]:22\nlistenaddress 0.0.0.0:22\npermitrootlogin prohibit-password\n'
# `systemctl show ssh.socket` with the generator's ports, socket activation off as on these servers.
SOCKET_OFF = 'Listen=0.0.0.0:4022 (Stream)\nListen=[::]:4022 (Stream)\nActiveState=inactive\nUnitFileState=disabled\n'


def done(code=0, out=''):
    return subprocess.CompletedProcess([], code, out, '')


class FakeServer:
    """sshd, systemd and a Fail2ban whose running sshd jail takes its port from the files it loads."""

    def __init__(self, sshd=SSHD, socket=SOCKET_OFF, running=True, test=0, later_port=None):
        self.sshd, self.socket, self.running, self.test = sshd, socket, running, test
        # A port another setting read after the Companion's file sets (jail.local, a later jail.d file).
        self.later_port = later_port
        self.port = later_port or 'ssh'
        self.calls = []

    def load(self):
        try:
            match = re.search(r'^port = (.+)$', ssh_jail.OVERRIDE.read_text(), re.M)
        except FileNotFoundError:
            match = None
        self.port = self.later_port or (match[1] if match else 'ssh')
        self.running = True

    def run(self, arguments, **kwargs):
        arguments = [str(item) for item in arguments]
        self.calls.append(arguments)
        if arguments == [ssh_jail.SSHD, '-T']:
            return done(0, self.sshd) if self.sshd else done(255)
        if arguments[:3] == [ssh_jail.SYSTEMCTL, 'show', ssh_jail.SOCKET]:
            return done(0, self.socket)
        if arguments == [CLIENT, 'status', 'sshd']:
            return done(0 if self.running else 255)
        if arguments == [CLIENT, 'get', 'sshd', 'actions']:
            return done(0, 'The jail sshd has the following actions:\nnftables, sendmail-whois\n') if self.running else done(255)
        if arguments == [CLIENT, 'get', 'sshd', 'action', 'nftables', 'port']:
            return done(0, self.port + '\n')
        if arguments == [CLIENT, 'get', 'sshd', 'action', 'sendmail-whois', 'port']:
            return done(255)
        if arguments == [CLIENT, '--test']:
            return done(self.test)
        if arguments in ([CLIENT, 'reload', '--restart', 'sshd'], [ssh_jail.SYSTEMCTL, 'restart', 'fail2ban']):
            self.load()
            return done()
        raise AssertionError(arguments)

    def applied(self):
        return [call for call in self.calls if call[1:2] in (['reload'], ['restart'])]


class SshJailTests(unittest.TestCase):
    def setUp(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (folder / 'jail.d').mkdir()
        self.enterContext(mock.patch.object(ssh_jail, 'OVERRIDE', folder / 'jail.d' / 'companion-sshd.conf'))
        self.enterContext(mock.patch.object(ssh_jail, 'FAIL2BAN_CLIENT', CLIENT))
        self.enterContext(mock.patch.object(probe_guard, 'FAIL2BAN_CLIENT', CLIENT))

    def server(self, **kwargs):
        server = FakeServer(**kwargs)
        self.enterContext(mock.patch.object(ssh_jail.subprocess, 'run', side_effect=server.run))
        return server

    def test_ports_are_every_port_sshd_names_and_ssh_socket_listens_on(self):
        self.assertEqual(ssh_jail.sshd_ports(SSHD), {22, 4022})
        # A listen address with its own port adds that port.
        self.assertEqual(ssh_jail.sshd_ports('port 22\nlistenaddress 192.0.2.10:2200\n'), {22, 2200})
        self.assertEqual(ssh_jail.socket_ports(SOCKET_OFF), set())
        active = 'Listen=0.0.0.0:4022 (Stream)\nListen=[::]:2200 (Stream)\nListen=/run/x.sock (Stream)\n' \
                 'ActiveState=active\nUnitFileState=enabled\n'
        self.assertEqual(ssh_jail.socket_ports(active), {4022, 2200})
        # Enabled but not started yet: it listens on these ports from the next boot.
        self.assertEqual(ssh_jail.socket_ports('Listen=4022 (Stream)\nActiveState=inactive\nUnitFileState=enabled\n'), {4022})
        self.server(sshd='port 4022\n', socket=active)
        self.assertEqual(ssh_jail.ssh_ports(), [2200, 4022])

    def test_ports_need_a_valid_ssh_configuration(self):
        self.server(sshd='')
        with self.assertRaisesRegex(ValueError, 'sshd rejects its configuration'):
            ssh_jail.ssh_ports()

    def test_the_jail_port_is_read_as_fail2ban_reports_it(self):
        self.assertEqual(ssh_jail.port_ranges('ssh'), [(22, 22)])
        self.assertEqual(ssh_jail.port_ranges('4022, ssh'), [(4022, 4022), (22, 22)])
        self.assertEqual(ssh_jail.port_ranges('2000:5000,6000-6100'), [(2000, 5000), (6000, 6100)])
        self.assertEqual(ssh_jail.uncovered([22, 4022], {'nftables': 'ssh'}), [4022])
        self.assertEqual(ssh_jail.uncovered([22, 4022], {'nftables': '22,4022'}), [])
        self.assertEqual(ssh_jail.uncovered([22, 4022], {'iptables-multiport': '2000:5000'}), [22])
        # A jail without ban actions bans on no port.
        self.assertEqual(ssh_jail.uncovered([22, 4022], {}), [22, 4022])
        server = self.server()
        # The mail report has no port setting and bans nothing.
        self.assertEqual(ssh_jail.action_ports(), {'nftables': 'ssh'})
        server.running = False
        self.assertIsNone(ssh_jail.action_ports())

    def test_the_file_names_every_ssh_port_under_the_companion_header(self):
        server = self.server()
        self.assertFalse(ssh_jail.ready())
        self.assertEqual(ssh_jail.install(), "Fail2ban's SSH jail bans on SSH ports 22, 4022.")
        text = ssh_jail.OVERRIDE.read_text()
        self.assertEqual(text, ssh_jail.configuration([22, 4022]))
        self.assertTrue(text.startswith(ssh_jail.OWNED_PREFIX))
        self.assertIn('\n[sshd]\nport = 22,4022\n', text)
        # Tested before the jail restarts; a plain reload would keep the firewall rule built with port 22.
        self.assertLess(server.calls.index([CLIENT, '--test']), server.calls.index([CLIENT, 'reload', '--restart', 'sshd']))
        self.assertEqual(server.applied(), [[CLIENT, 'reload', '--restart', 'sshd']])
        self.assertTrue(ssh_jail.ready())
        self.assertEqual(ssh_jail.coverage(), {'ports': [22, 4022], 'uncovered': []})

    def test_a_jail_that_is_not_loaded_starts_with_fail2ban(self):
        server = self.server(running=False)
        ssh_jail.install()
        self.assertEqual(server.applied(), [[ssh_jail.SYSTEMCTL, 'restart', 'fail2ban']])
        self.assertTrue(ssh_jail.ready())

    def test_a_file_the_companion_did_not_write_is_never_replaced(self):
        server = self.server()
        ssh_jail.OVERRIDE.write_text('[sshd]\nport = 22\n')
        with self.assertRaisesRegex(ValueError, 'not written by the Companion'):
            ssh_jail.install()
        self.assertEqual(ssh_jail.OVERRIDE.read_text(), '[sshd]\nport = 22\n')
        self.assertEqual(server.applied(), [])
        # When it already names every SSH port, there is nothing to do.
        ssh_jail.OVERRIDE.write_text('[sshd]\nport = 22,4022\n')
        server.load()
        self.assertTrue(ssh_jail.ready())

    def test_done_when_the_running_jail_covers_every_ssh_port(self):
        server = self.server()
        self.assertFalse(ssh_jail.ready())
        # Covered by the operator's own setting: nothing is written.
        server.port = '4022,ssh'
        self.assertTrue(ssh_jail.ready())
        self.assertFalse(ssh_jail.OVERRIDE.exists())
        server.running = False
        self.assertFalse(ssh_jail.ready())
        self.assertIsNone(ssh_jail.coverage())
        # The Companion's file must name exactly today's ports: after port 22 closes, it is rewritten.
        server.running, server.sshd = True, 'port 4022\nlistenaddress 0.0.0.0:4022\n'
        ssh_jail.OVERRIDE.write_text(ssh_jail.configuration([22, 4022]))
        server.load()
        self.assertFalse(ssh_jail.ready())
        ssh_jail.install()
        self.assertEqual(ssh_jail.OVERRIDE.read_text(), ssh_jail.configuration([4022]))
        self.assertTrue(ssh_jail.ready())
        server.sshd = ''
        self.assertFalse(ssh_jail.ready())

    def test_a_setting_fail2ban_refuses_is_taken_back_before_any_reload(self):
        server = self.server(test=255)
        with self.assertRaisesRegex(ValueError, '--test failed'):
            ssh_jail.install()
        self.assertFalse(ssh_jail.OVERRIDE.exists())
        self.assertEqual(server.applied(), [])
        earlier = ssh_jail.configuration([22])
        ssh_jail.OVERRIDE.write_text(earlier)
        with self.assertRaises(ValueError):
            ssh_jail.install()
        self.assertEqual(ssh_jail.OVERRIDE.read_text(), earlier)
        self.assertEqual(server.applied(), [])

    def test_a_jail_still_missing_a_port_gets_its_previous_configuration_back(self):
        server = self.server(later_port='ssh')
        with self.assertRaisesRegex(ValueError, 'still does not ban on SSH port 4022'):
            ssh_jail.install()
        self.assertFalse(ssh_jail.OVERRIDE.exists())
        # Restarted with the file, then again without it.
        self.assertEqual(server.applied(), [[CLIENT, 'reload', '--restart', 'sshd']] * 2)


if __name__ == '__main__':
    unittest.main()
