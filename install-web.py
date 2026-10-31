"""Install the private web service; never alter CloudPanel, DNS or site files.

Run as root after installing requirements.txt into the dedicated virtualenv.
An HTTPS frontend and locally provisioned operator are separate explicit steps.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess


def run(*args):
    subprocess.run(args, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--site-host', required=True)
    parser.add_argument('--panel-host', required=True)
    parser.add_argument('--link-monitor', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    for host in (args.host, args.site_host, args.panel_host):
        if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', host):
            raise SystemExit('Use explicit lowercase DNS hostnames')
    if len({args.host, args.site_host, args.panel_host}) != 3:
        raise SystemExit('Website, panel and operations hostnames must be distinct')
    from companion.maintenance import admissions, require_idle
    with admissions(exclusive=True):
        require_idle()
        from companion.package_install import PackageTransaction
        with PackageTransaction(Path(__file__).resolve().parent) as change:
            install(args)
            change.activate.append('companion-web.service')
            if Path('/etc/cloudpanel-companion/operations.json').exists():
                change.activate.append('companion-operations.service')
        # Staging network tables from an earlier release stay loaded until reboot otherwise.
        from companion.isolation import refresh_loaded
        refresh_loaded()


def install(args):
    source = Path(__file__).resolve().parent
    destination = Path('/opt/cloudpanel-companion')
    configuration = Path('/etc/cloudpanel-companion')
    state = Path('/var/lib/cloudpanel-companion-web')
    python = '/opt/cloudpanel-companion-venv/bin/python'
    for path in (destination, configuration, state):
        if path.is_symlink():
            raise SystemExit('Installation path cannot be a symlink')
    config_path = configuration / 'web.json'
    if config_path.exists():
        if config_path.is_symlink() or config_path.stat().st_uid != 0 or config_path.stat().st_mode & 0o077:
            raise SystemExit('Existing configuration must be root-owned and private')
        current = json.loads(config_path.read_text())
        if current['host'] != args.host or current['site_url'] != 'https://' + args.site_host:
            raise SystemExit('Existing installation belongs to another site')
    for user, group in [('companion-web', 'companion-web'), ('companion-cache', 'companion-web')]:
        try:
            identity = pwd.getpwnam(user)
            if identity.pw_shell not in ('/usr/sbin/nologin', '/bin/false'):
                raise SystemExit('Service identity has an interactive shell; review it first')
        except KeyError:
            arguments = ['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin']
            arguments += ['--user-group'] if user == group else ['--gid', group]
            run(*arguments, user)
    identity = pwd.getpwnam('companion-web')
    destination.mkdir(mode=0o755, exist_ok=True)
    configuration.mkdir(mode=0o755, exist_ok=True)
    shutil.copyfile(source / 'assets/companion-web-proxy.conf', configuration / 'companion-web-proxy.conf')
    os.chmod(configuration / 'companion-web-proxy.conf', 0o644)
    state.mkdir(mode=0o700, exist_ok=True)
    os.chown(state, identity.pw_uid, identity.pw_gid)
    os.chmod(state, 0o700)
    if not config_path.exists():
        with config_path.open('x') as stream:
            os.chmod(config_path, 0o600)
            json.dump({'secret_key': secrets.token_urlsafe(64), 'host': args.host,
                       'state_directory': str(state),
                       'security_cache_url': 'unix:///run/cloudpanel-companion-security/redis.sock',
                       'snapshot_path': '/var/lib/cloudpanel-companion-observations/latest.json',
                       'panel_url': 'https://' + args.panel_host,
                       'site_url': 'https://' + args.site_host, 'site_name': args.site_host}, stream)
    for filename in ('companion-web.service', 'companion-security-cache.service'):
        shutil.copyfile(source / 'assets' / filename, Path('/etc/systemd/system') / filename)
    shutil.copyfile(source / 'assets/security-cache.conf', configuration / 'security-cache.conf')
    os.chmod(configuration / 'security-cache.conf', 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'companion-security-cache.service')
    # systemd credentials avoid exposing the private configuration to the web
    # account outside its service, or placing a secret on a process command line.
    for arguments in [('migrate', '--noinput'), ('collectstatic', '--noinput')]:
        run('systemd-run', '--quiet', '--wait', '--pipe', '--collect',
            '--uid=companion-web', '--gid=companion-web',
            '--working-directory=' + str(destination),
            '--property=LoadCredential=web.json:' + str(config_path),
            '--setenv=DJANGO_SETTINGS_MODULE=companion_web.settings',
            python, '-c',
            'import os,sys; os.environ["COMPANION_WEB_CONFIG"] = '
            'os.environ["CREDENTIALS_DIRECTORY"] + "/web.json"; '
            'from django.core.management import execute_from_command_line; '
            'execute_from_command_line(["django"] + sys.argv[1:])', *arguments)
    run('systemctl', 'enable', 'companion-web.service')
    if args.link_monitor:
        from companion.installation import monitor_export
        monitor_export(source)
        run('systemctl', 'daemon-reload')
        if Path('/etc/systemd/system/companion-monitor.service').exists():
            run('systemctl', 'start', 'companion-monitor.service')
    print('Private services installed. HTTPS frontend and operator setup remain separate.')


if __name__ == '__main__':
    main()
