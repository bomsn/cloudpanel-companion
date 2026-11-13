"""Install sign-in and visit history for the Security page, and CloudPanel's private access log.

Run as root after install-web.py, which installs the trusted client-address rules
this log uses. CloudPanel's custom-domain vhost gets one include line for the log;
CloudPanel rewrites that file when its custom domain or certificate changes, and
running this again (sudo bash install.sh does) adds the line back.
"""
import argparse
import grp
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from companion import client_address, security_log
from companion.maintenance import component_install
from companion.operations import write_private
from companion.staging import HOSTNAME

UNITS = ('companion-security-log.service', 'companion-security-log.timer')
EXPORTS = security_log.OUTPUT.parent


def run(*arguments):
    subprocess.run(arguments, check=True)


def write_like(path, text, info):
    """Replace a file CloudPanel owns, keeping the owner and mode CloudPanel gave it."""
    write_private(path, text, stat.S_IMODE(info.st_mode))
    os.chown(path, info.st_uid, info.st_gid)


def connect_panel_log(host):
    """Add the access-log include to CloudPanel's custom-domain vhost; restore it if Nginx refuses."""
    vhost = client_address.PANEL_VHOST
    try:
        current, info = vhost.read_text(), vhost.stat()
    except FileNotFoundError:
        print('CloudPanel has no custom domain on this server, so its sign-in attempts cannot be logged.')
        return
    if client_address.panel_server_name(host) not in current:
        print(f'CloudPanel\'s custom domain is not {host}; its access log was not connected.')
        return
    include = client_address.PANEL_INCLUDE
    previous = include.read_text() if include.exists() else None
    directive = client_address.access_directive('cloudpanel') + '\n'
    try:
        wanted = client_address.panel_vhost(current, host)
    except ValueError as error:
        # The collector still installs; the Security page shows CloudPanel's log as not connected.
        print(f'{error}. CloudPanel\'s access log was not connected; the rest of the Security page works.')
        return
    if wanted == current and previous == directive:
        return
    write_private(include, directive, 0o644)
    write_like(vhost, wanted, info)
    try:
        run('nginx', '-t')
    except BaseException:
        write_like(vhost, current, info)
        if previous is None:
            include.unlink()
        else:
            write_private(include, previous, 0o644)
        raise
    run('systemctl', 'reload', 'nginx')


def install(args):
    source = Path(__file__).resolve().parent
    if not client_address.HTTP_CONFIG.is_file():
        raise ValueError('Install the interface with install-web.py first; it installs the client-address rules')
    if EXPORTS.is_symlink() or (EXPORTS.exists() and (EXPORTS.stat().st_uid != 0 or EXPORTS.stat().st_mode & 0o027)):
        raise ValueError('The security export directory must be operator-owned')
    EXPORTS.mkdir(mode=0o750, exist_ok=True)
    os.chown(EXPORTS, 0, grp.getgrnam('companion-web').gr_gid)
    EXPORTS.chmod(0o750)
    if args.panel_host:
        connect_panel_log(args.panel_host)
    for unit in UNITS:
        shutil.copyfile(source / 'assets' / unit, Path('/etc/systemd/system') / unit)
    run('systemd-analyze', 'verify', *('/etc/systemd/system/' + unit for unit in UNITS))
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'companion-security-log.service')
    run('systemctl', 'enable', '--now', 'companion-security-log.timer')
    print('Sign-in and visit history installed: sign-ins, SSH connections and panel visits are recorded every minute.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--panel-host', help="CloudPanel's custom domain, for its private access log")
    arguments = parser.parse_args()
    if arguments.panel_host and not re.fullmatch(HOSTNAME, arguments.panel_host):
        raise SystemExit('Use the explicit lowercase CloudPanel hostname')
    if os.geteuid() != 0:
        raise SystemExit('Run as the server operator')
    with component_install(Path(__file__).resolve().parent):
        install(arguments)
