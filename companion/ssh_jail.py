"""Fail2ban's SSH jail bans on every port SSH listens on.

Ubuntu's `sshd` jail bans on port 22 (`port = ssh` in jail.conf), while these servers run
SSH on the port prepare-server.sh chose, so an address the jail banned could keep trying
on the real one. This module is the one owner of that setting: a jail.d file naming every
SSH port, tested with `fail2ban-client --test` before the sshd jail restarts with it. It
reads SSH's configuration and never changes SSH itself.

The ports are those sshd's effective configuration names (`sshd -T`: its port lines and
the port of each listen address) and, while Ubuntu's socket activation is on, those
ssh.socket listens on. Done means what Fail2ban reports for the running jail: its ban
actions' ports cover every SSH port. A file the Companion did not write is never
replaced, and when other settings already cover the ports nothing is written at all.
The file is a `.conf`, so an operator's own jail.local or jail.d/*.local still wins.
"""
from pathlib import Path
import re
import socket
import subprocess
from .operations import write_private
from .probe_guard import FAIL2BAN, FAIL2BAN_CLIENT, HEADER, OWNED_PREFIX, jail_running, wait_for_jail

JAIL = 'sshd'
OVERRIDE = FAIL2BAN / 'jail.d' / 'companion-sshd.conf'
SSHD = '/usr/sbin/sshd'
SYSTEMCTL = '/usr/bin/systemctl'
SOCKET = 'ssh.socket'
LISTEN = re.compile(r'Listen=(?:.*:)?(\d+) \(Stream\)')


def sshd_ports(effective):
    """The ports in `sshd -T` output: each port line, and the port of each listen address."""
    ports = set()
    for line in effective.splitlines():
        key, _, value = line.strip().partition(' ')
        if key == 'port' and value.isdigit():
            ports.add(int(value))
        elif key == 'listenaddress' and (match := re.search(r':(\d+)$', value)):
            ports.add(int(match[1]))
    return ports


def socket_ports(properties):
    """The ports ssh.socket listens on, from `systemctl show`, while socket activation is on."""
    values = dict(line.split('=', 1) for line in properties.splitlines() if '=' in line and not line.startswith('Listen='))
    if values.get('ActiveState') != 'active' and not values.get('UnitFileState', '').startswith('enabled'):
        return set()
    return {int(match[1]) for line in properties.splitlines() if (match := LISTEN.fullmatch(line))}


def ssh_ports():
    """Every port SSH listens on, sorted."""
    effective = subprocess.run([SSHD, '-T'], capture_output=True, text=True, timeout=10)
    if effective.returncode:
        raise ValueError('sshd rejects its configuration: ' + effective.stderr.strip()[-300:])
    listening = subprocess.run([SYSTEMCTL, 'show', SOCKET, '--property=Listen,ActiveState,UnitFileState'],
                               capture_output=True, text=True, timeout=10)
    ports = sshd_ports(effective.stdout) | socket_ports(listening.stdout if listening.returncode == 0 else '')
    if not ports:
        raise ValueError('sshd reports no port')
    return sorted(ports)


def port_ranges(value):
    """The (first, last) ranges a Fail2ban port setting names: ports, service names and ranges, comma separated."""
    ranges = []
    for item in value.replace(' ', '').split(','):
        if match := re.fullmatch(r'(\d+)[:-](\d+)', item):
            ranges.append((int(match[1]), int(match[2])))
        elif item.isdigit():
            ranges.append((int(item), int(item)))
        elif item:
            try:
                number = socket.getservbyname(item, 'tcp')
            except OSError:
                continue
            ranges.append((number, number))
    return ranges


def action_ports():
    """{action: port setting} for the running sshd jail, as Fail2ban reports it; None while the jail is not running.

    An action without a port setting (a mail report) bans nothing by port and is left out.
    """
    try:
        listing = subprocess.run([FAIL2BAN_CLIENT, 'get', JAIL, 'actions'], capture_output=True, text=True, timeout=10)
        if listing.returncode:
            return None
        ports = {}
        # "The jail sshd has the following actions:" then the names, separated by commas.
        for name in re.split(r'[,\s]+', ' '.join(listing.stdout.splitlines()[1:])):
            if not name:
                continue
            result = subprocess.run([FAIL2BAN_CLIENT, 'get', JAIL, 'action', name, 'port'],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                ports[name] = result.stdout.strip()
        return ports
    except (OSError, subprocess.SubprocessError):
        return None


def uncovered(ports, reported):
    """The SSH ports none of the jail's actions bans on."""
    ranges = [item for value in reported.values() for item in port_ranges(value)]
    return [port for port in ports if not any(first <= port <= last for first, last in ranges)]


def configuration(ports):
    return f'''{HEADER}
# Generated from SSH's own configuration by companion/ssh_jail.py; changes here are overwritten.
# Fail2ban's sshd jail bans on port 22 by default; SSH listens on these ports.
[{JAIL}]
port = {",".join(str(port) for port in ports)}
'''


def coverage():
    """The SSH ports and those the running sshd jail's bans miss, for the Security page; None while either is unknown."""
    try:
        ports = ssh_ports()
    except (ValueError, OSError, subprocess.SubprocessError):
        return None
    reported = action_ports()
    return None if reported is None else {'ports': ports, 'uncovered': uncovered(ports, reported)}


def ready():
    """The running jail bans on every SSH port, and the Companion's file, where it wrote one, names exactly those."""
    state = coverage()
    if state is None or state['uncovered']:
        return False
    try:
        text = OVERRIDE.read_text()
    except FileNotFoundError:
        return True
    return not text.startswith(OWNED_PREFIX) or text == configuration(state['ports'])


def restore(previous):
    if previous is None:
        OVERRIDE.unlink(missing_ok=True)
    else:
        write_private(OVERRIDE, previous, 0o644)


def run(arguments, timeout=60):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f'{" ".join(arguments)} failed: ' + (result.stderr or result.stdout).strip()[-600:])


def apply():
    """Load the jail's configuration into the running Fail2ban.

    A plain reload keeps the firewall rule an action already built with the old port;
    restarting only this jail rebuilds it, and Fail2ban restores the jail's current
    bans from its database. A jail that is not loaded needs Fail2ban itself restarted.
    """
    if jail_running(JAIL):
        run([FAIL2BAN_CLIENT, 'reload', '--restart', JAIL])
    else:
        run([SYSTEMCTL, 'restart', 'fail2ban'], timeout=120)
    wait_for_jail(JAIL)


def install():
    """Make the sshd jail ban on every SSH port; returns what was done, in a sentence."""
    if not Path(FAIL2BAN_CLIENT).exists():
        raise ValueError('Fail2ban is not installed (CloudPanel installs it); install it with apt-get install fail2ban')
    ports = ssh_ports()
    if OVERRIDE.is_symlink():
        raise ValueError(f'{OVERRIDE} is a link; review it, then remove it and run this again')
    previous = OVERRIDE.read_text() if OVERRIDE.exists() else None
    if previous is not None and not previous.startswith(OWNED_PREFIX):
        raise ValueError(f'{OVERRIDE} was not written by the Companion; review it, then remove it and run this again')
    text = configuration(ports)
    if previous != text:
        OVERRIDE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        write_private(OVERRIDE, text, 0o644)
        try:
            run([FAIL2BAN_CLIENT, '--test'])
        except BaseException:
            restore(previous)
            raise
    try:
        apply()
        missing = uncovered(ports, action_ports() or {})
        if missing:
            raise ValueError(f"Fail2ban's sshd jail still does not ban on SSH port {', '.join(map(str, missing))}: "
                             'a setting read after this file sets its port. Check the [sshd] sections in '
                             f'{FAIL2BAN / "jail.local"} and {FAIL2BAN / "jail.d"}.')
    except BaseException:
        # Fail2ban comes back with the setting it had.
        if previous != text:
            restore(previous)
            apply()
        raise
    return f"Fail2ban's SSH jail bans on SSH port{'s' if len(ports) > 1 else ''} {', '.join(map(str, ports))}."
