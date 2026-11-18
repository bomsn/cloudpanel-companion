"""Install scan blocking: bots asking for secret files get a 404 and repeat scanners are banned (companion/probe_guard.py).

Run as root after install-web.py, whose client-address rules decide the visitor
address the bans use. The website's and staging's vhosts already include the
per-site security file written here (setup adds it to their stored vhosts where it is
missing), so no vhost changes. Running it again changes only what is out of date.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
from companion import client_address, probe_guard
from companion.maintenance import component_install
from companion.operations import write_private

USER = r'[a-z][a-z0-9-]{2,30}'


def run(*arguments):
    subprocess.run(arguments, check=True)


def replace(wanted):
    """Write each changed file and return what it held before (None: it did not exist)."""
    previous = {}
    for path, (content, mode) in wanted.items():
        if path.is_symlink():
            raise ValueError('A managed configuration cannot be a link: ' + str(path))
        old = path.read_text() if path.exists() else None
        if old == content:
            continue
        if path.parent == probe_guard.SITE_INCLUDES and old is not None and not old.startswith(probe_guard.OWNED_PREFIX):
            raise ValueError(f'{path} was not written by the Companion; review it, then remove it and run this again')
        path.parent.mkdir(mode=0o700 if path.parent == probe_guard.SITE_INCLUDES else 0o755, parents=True, exist_ok=True)
        previous[path] = old
        write_private(path, content, mode)
    return previous


def restore(previous):
    for path, old in previous.items():
        if old is None:
            path.unlink(missing_ok=True)
        else:
            write_private(path, old, 0o600 if path == probe_guard.CONFIG else 0o644)


def install(args):
    source = Path(__file__).resolve().parent
    if not client_address.HTTP_CONFIG.is_file():
        raise ValueError('Install the interface with install-web.py first; it installs the client-address rules')
    if not Path(probe_guard.FAIL2BAN_CLIENT).exists():
        raise ValueError('Fail2ban is not installed (CloudPanel installs it); install it with apt-get install fail2ban')
    users = [args.site_user] + ([args.staging_user] if args.staging_user else [])
    allowed = probe_guard.allowlist(args.allow)
    wanted = probe_guard.files(users, allowed, probe_guard.site_access_log(args.site_user))
    probe_guard.prepare()
    replace(wanted['settings'])
    previous = replace(wanted['nginx'])
    if previous:
        try:
            run('nginx', '-t')
        except BaseException:
            restore(previous)
            raise
        run('systemctl', 'reload', 'nginx')
    unit = probe_guard.SYSTEMD / probe_guard.RELOAD_UNIT
    changed = replace(wanted['fail2ban'])
    content = (source / 'assets' / unit.name).read_text()
    if not unit.is_file() or unit.read_text() != content:
        changed[unit] = unit.read_text() if unit.is_file() else None
        write_private(unit, content, 0o644)
    if changed:
        try:
            run('systemd-analyze', 'verify', str(unit))
            # The filter must find the address in a line exactly as Nginx writes it.
            sample = ('{"at":1700000000.000,"ip":"192.0.2.1","edge":"192.0.2.2","country":"","host":"example.com",'
                      '"method":"GET","path":"/.env","status":404,"agent":"curl/8.5.0"}')
            result = subprocess.run(['fail2ban-regex', sample, str(probe_guard.FILTER)], capture_output=True, text=True)
            if result.returncode or 'Lines: 1 lines, 0 ignored, 1 matched' not in result.stdout:
                raise ValueError('fail2ban-regex did not match a probe-log line with the generated filter')
            run(probe_guard.FAIL2BAN_CLIENT, '--test')
        except BaseException:
            restore(changed)
            raise
        run('systemctl', 'daemon-reload')
        # A restart applies the server setting and the start-up check; Fail2ban restores its bans.
        try:
            run('systemctl', 'restart', 'fail2ban')
        except BaseException:
            # Fail2ban also guards SSH: it comes back with its previous configuration.
            restore(changed)
            run('systemctl', 'daemon-reload')
            run('systemctl', 'restart', 'fail2ban')
            raise
    probe_guard.wait_for_jail()
    # Brings the Nginx ban list in line with the bans Fail2ban restored.
    run('systemctl', 'start', probe_guard.RELOAD_UNIT)
    print(f'Scan blocking installed: requests for secret files get a "not found" without starting WordPress, and '
          f'{probe_guard.MAX_RETRY} within {probe_guard.FIND_TIME} ban the address for {probe_guard.BAN_TIME}. '
          f'List the bans with: sudo fail2ban-client status {probe_guard.JAIL}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site-user', required=True)
    parser.add_argument('--staging-user')
    parser.add_argument('--allow', action='append', default=[],
                        help='an address or network never to ban (the uptime monitor, an office); repeatable')
    arguments = parser.parse_args()
    if not all(re.fullmatch(USER, user) for user in filter(None, (arguments.site_user, arguments.staging_user))):
        raise SystemExit('Use the explicit CloudPanel site users')
    if os.geteuid() != 0:
        raise SystemExit('Run as the server operator')
    with component_install(Path(__file__).resolve().parent):
        install(arguments)
