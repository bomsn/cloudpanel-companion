"""Install the isolated transport for an existing registered staging copy."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
from companion.clone_worker import STAGING_MU_PLUGINS
from companion.monitor import private_json
from companion.operations import write_private
from companion.provision import write_site_file
from companion.relay import default_policy, destination, load_policy, socket_path
from companion.staging import Site, validate_pair


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, capture_output=True, timeout=120, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--site', required=True)
    parser.add_argument('--protect-host', action='append', default=[])
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    from companion.maintenance import component_install
    with component_install(Path(__file__).resolve().parent):
        install(arguments)


def install(arguments):
    os.umask(0o077)
    registry = private_json(arguments.registry)
    registered = registry['sites'][arguments.site]
    spec = private_json(Path(registered['specification']))
    source, target = Site(**spec['source']), Site(**spec['target'])
    validate_pair(source, target)
    if registered['user'] != target.user or registered['host'] != target.host or registered['source_host'] != source.host:
        raise ValueError('Staging registry does not match its specification')
    lock = os.open(Path('/var/lib/cloudpanel-companion-jobs/locks') / (target.user + '.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    root = Path(__file__).resolve().parent
    try:
        account = pwd.getpwnam('companion-relay')
        if account.pw_shell not in ('/usr/sbin/nologin', '/bin/false'):
            raise ValueError('Relay identity must not have an interactive shell')
    except KeyError:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'companion-relay'])
    stage = pwd.getpwnam(target.user)
    run(['systemctl', 'is-active', 'companion-isolation-' + target.user + '.service'])
    forbidden = sorted(set(registered.get('protected_hosts', []) + arguments.protect_host + [source.host, target.host]))
    for host in forbidden:
        if destination('https://' + host + '/').hostname != host:
            raise ValueError('Use explicit lowercase protected hostnames')
    policy_path = Path('/etc/cloudpanel-companion/sites') / (target.user + '.json')
    if policy_path.exists():
        load_policy(policy_path, set(forbidden))
    else:
        write_private(policy_path, json.dumps(default_policy()), 0o640)
    os.chown(policy_path, 0, stage.pw_gid)
    policy_path.chmod(0o640)
    relay_socket = socket_path(target.user)
    configuration = {'staging_uid': stage.pw_uid, 'policy_path': str(policy_path), 'forbidden_hosts': forbidden}
    write_private(Path('/etc/cloudpanel-companion') / ('relay-' + target.user + '.json'), json.dumps(configuration))
    registered.update(relay_socket=relay_socket, protected_hosts=forbidden)
    write_private(arguments.registry, json.dumps(registry))
    for name, asset in STAGING_MU_PLUGINS.items():
        write_site_file(target.user, target.root / 'wp-content/mu-plugins' / name, (root / 'assets' / asset).read_bytes())
    wp = ['/usr/sbin/runuser', '-u', target.user, '--', '/usr/bin/php' + target.php_version, '/usr/bin/wp', '--path=' + str(target.root), 'config', 'set']
    for name, value in [('CLOUDPANEL_COMPANION_STAGING_POLICY', str(policy_path)), ('CLOUDPANEL_COMPANION_STAGING_RELAY', relay_socket)]:
        run(wp + [name, value, '--type=constant', '--quiet', "--anchor=require_once ABSPATH . 'wp-settings.php';"], cwd=str(target.root))
    unit = 'companion-relay@' + target.user + '.service'
    shutil.copyfile(root / 'assets/companion-relay@.service', '/etc/systemd/system/companion-relay@.service')
    run(['systemd-analyze', 'verify', '/etc/systemd/system/companion-relay@.service'])
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', unit])
    run(['systemctl', 'restart', unit])
    run(['systemctl', 'restart', 'companion-operations.service', 'companion-web.service'])
    print('Staging email capture and test request controls installed. Existing operator credentials were kept.')
    os.close(lock)


if __name__ == '__main__':
    main()
