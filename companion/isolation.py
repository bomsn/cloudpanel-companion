"""Atomically install only this staging UID's outbound network table."""
import argparse
import os
import re
import subprocess
from .network import deny_outbound, table_name


def install(uid, local_ports=()):
    if os.geteuid() != 0:
        raise ValueError('Network policy requires root')
    name = table_name(uid)
    exists = subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', name], capture_output=True).returncode == 0
    policy = ('delete table inet ' + name + '\n' if exists else '') + deny_outbound(uid, tuple(local_ports))
    subprocess.run(['/usr/sbin/nft', '--check', '-f', '-'], input=policy.encode(), check=True, capture_output=True)
    # nft applies the whole batch atomically, so refreshing a policy never leaves
    # an interval with its previous protection removed and no replacement.
    subprocess.run(['/usr/sbin/nft', '-f', '-'], input=policy.encode(), check=True, capture_output=True)


def loaded_policies(tables, read_table):
    """(uid, loopback exceptions) of each staging table in `nft list tables` output."""
    policies = []
    for uid in sorted(int(value) for value in re.findall(r'^table inet companion_staging_([0-9]+)$', tables, re.M)):
        current = read_table(table_name(uid))
        policies.append((uid, tuple(sorted({int(port) for port in re.findall(
            r'ip daddr 127\.0\.0\.1 tcp dport ([0-9]+) return', current)}))))
    return policies


def refresh_loaded():
    """Re-render every loaded staging table with this package's rules, keeping its exceptions.

    Tables are rendered only at provisioning and at boot, so without this an update that
    changes the rules (the owner match in network.deny_outbound) would leave the old
    table in force until the next reboot. Restarting the isolation units instead would
    restart PHP-FPM, which Requires= them. Each table keeps the loopback exceptions it
    has now, whichever unit installed it, and install() swaps it atomically.
    """
    def read(name):
        return subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', name],
                              capture_output=True, check=True).stdout.decode()
    tables = subprocess.run(['/usr/sbin/nft', 'list', 'tables'], capture_output=True, check=True).stdout.decode()
    policies = loaded_policies(tables, read)
    for uid, ports in policies:
        install(uid, ports)
    return policies


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--allow-local-port', type=int, action='append', default=[])
    arguments = parser.parse_args()
    install(arguments.uid, arguments.allow_local_port)
