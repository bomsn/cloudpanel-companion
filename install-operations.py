"""Register an already isolated staging copy without resetting operator choices.

Initial site creation is performed by companion.provision. This step adds its
private health endpoint, fixed operations service and retained-generation timer.
It never patches CloudPanel or invents credentials from a website request.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from companion.monitor import private_json
from companion.operations import render_access, write_private
from companion.provision import site_wp
from companion.staging import Site, validate_pair


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, capture_output=True, timeout=90, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--specification', type=Path, required=True)
    parser.add_argument('--site', required=True)
    parser.add_argument('--automatic-cleanup', action='store_true',
                        help='retire superseded staging copies every 6 hours (off by default; see install.sh cleanup-staging)')
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', args.site):
        raise ValueError('Root invocation and explicit registered site ID required')
    from companion.maintenance import component_install
    with component_install(Path(__file__).resolve().parent):
        install(args)


def install(args):
    specification = private_json(args.specification)
    source, target = Site(**specification['source']), Site(**specification['target'])
    validate_pair(source, target)
    for site in (source, target):
        if run(site_wp(site) + ['option', 'get', 'home']).stdout.decode().strip() != 'https://' + site.host:
            raise ValueError('Registered website URL differs from WordPress')
    directory = Path('/etc/cloudpanel-companion')
    registry_path, web_path = directory / 'operations.json', directory / 'web.json'
    registry = private_json(registry_path) if registry_path.exists() else {'sites': {}}
    web = private_json(web_path)
    if web.get('operations_site', args.site) != args.site or web['site_url'] != 'https://' + source.host:
        raise ValueError('This Companion interface belongs to another website')
    current = registry['sites'].get(args.site)
    if current and (current['source_host'] != source.host or current['host'] != target.host or current['user'] != target.user
                    or private_json(Path(current['specification'])) != specification):
        raise ValueError('An existing staging pair must not be replaced by registration')
    job_path = Path('/var/lib/cloudpanel-companion-operations/jobs') / (args.site + '.json')
    if job_path.exists() and private_json(job_path).get('returncode') is None:
        raise ValueError('Finish or recover the active workflow before updating its service')
    auth = directory / (target.user + '.htpasswd')
    if auth.is_symlink() or auth.stat().st_uid != 0 or auth.stat().st_mode & 0o077:
        raise ValueError('Initial provisioner must create private root-owned staging authentication')
    run(['systemctl', 'is-active', 'companion-isolation-' + target.user + '.service'])
    native = Path('/etc/nginx/sites-enabled') / (target.host + '.conf')
    include = directory / 'sites' / (target.user + '-access.conf')
    if native.is_symlink() or native.read_text().count('include ' + str(include) + ';') != 2:
        raise ValueError('The native staging template must retain both dynamic access includes')
    registered = current or {'user': target.user, 'host': target.host, 'source_host': source.host,
                             'specification': str(args.specification), 'protected_hosts': [source.host, target.host]}
    health = registered.get('health_file') or 'companion-health-' + secrets.token_hex(16) + '.php'
    if not re.fullmatch(r'companion-health-[a-f0-9]{32}[.]php', health):
        raise ValueError('Invalid private application check identity')
    root = Path(__file__).resolve().parent
    run(['runuser', '-u', target.user, '--', 'python3', '-c',
         'from pathlib import Path;import sys;p=Path(sys.argv[1]);assert not p.is_symlink();p.write_bytes(sys.stdin.buffer.read());p.chmod(0o644)',
         str(target.root / health)], input=(root / 'assets/application-health.php').read_bytes())
    write_private(include, render_access(target.user, {'protected': True, 'paused': False}, health), 0o644)
    run(['nginx', '-t'])
    registered['health_file'] = health
    origin = registered.get('source_health_file') or 'companion-origin-' + secrets.token_hex(16) + '.php'
    if not re.fullmatch(r'companion-origin-[a-f0-9]{32}[.]php', origin):
        raise ValueError('Invalid private source health identity')
    run(['runuser', '-u', source.user, '--', 'python3', '-c',
         'from pathlib import Path;import sys;p=Path(sys.argv[1]);assert not p.is_symlink();p.write_bytes(sys.stdin.buffer.read());p.chmod(0o644)',
         str(source.root / origin)], input=(root / 'assets/application-health.php').read_bytes())
    registered['source_health_file'] = origin
    registry['sites'][args.site] = registered
    write_private(registry_path, json.dumps(registry))
    web.update(operations_site=args.site, operations_socket='/run/cloudpanel-companion-operations/control.sock')
    write_private(web_path, json.dumps(web))
    for folder in ('/var/lib/cloudpanel-companion-jobs', '/var/lib/cloudpanel-companion-jobs/locks'):
        path = Path(folder)
        if path.is_symlink():
            raise ValueError('Private job directory cannot be a link')
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
    for name in ('companion-operations.service', 'companion-retention.service', 'companion-retention.timer'):
        write_private(Path('/etc/systemd/system') / name, (root / 'assets' / name).read_text(), 0o644)
    run(['systemd-analyze', 'verify', '/etc/systemd/system/companion-operations.service', '/etc/systemd/system/companion-retention.timer'])
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'reload', 'nginx'])
    run(['systemctl', 'enable', '--now', 'companion-operations.service'])
    # Old staging copies are recovery points, so removing them is the operator's
    # choice: manual by default, scheduled only when explicitly requested.
    run(['systemctl', 'enable' if args.automatic_cleanup else 'disable', '--now', 'companion-retention.timer'])
    run(['systemctl', 'restart', 'companion-operations.service', 'companion-web.service'])
    print('Registered staging controls installed. Existing passwords, protection choices, external policy and operators were retained.')


if __name__ == '__main__':
    main()
