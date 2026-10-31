"""Install the isolated transport for an existing registered staging copy."""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
from companion.monitor import private_json
from companion.operations import write_private
from companion.relay import default_policy, destination, load_policy
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
    socket_path = '/run/cloudpanel-companion-relay/' + target.user + '/transport.sock'
    configuration = {'staging_uid': stage.pw_uid, 'policy_path': str(policy_path), 'forbidden_hosts': forbidden}
    write_private(Path('/etc/cloudpanel-companion') / ('relay-' + target.user + '.json'), json.dumps(configuration))
    registered.update(relay_socket=socket_path, protected_hosts=forbidden)
    write_private(arguments.registry, json.dumps(registry))
    files = {'000-companion-staging.php': 'staging-guard.php', 'staging-policy.php': 'staging-policy.php', 'staging-relay.php': 'staging-relay.php'}
    payload = {name: base64.b64encode((root / 'assets' / asset).read_bytes()).decode() for name, asset in files.items()}
    worker = '''from pathlib import Path
import base64,json,sys
directory=Path(sys.argv[1])/'wp-content/mu-plugins'
for name,encoded in json.load(sys.stdin).items():
    target=directory/name
    if target.is_symlink():raise ValueError('Guard cannot be a symlink')
    temporary=directory/('.'+name+'.install')
    with temporary.open('xb') as stream:stream.write(base64.b64decode(encoded))
    temporary.chmod(0o644);temporary.replace(target)
'''
    run(['/usr/sbin/runuser', '-u', target.user, '--', '/usr/bin/python3', '-c', worker, str(target.root)], input=json.dumps(payload).encode())
    wp = ['/usr/sbin/runuser', '-u', target.user, '--', '/usr/bin/php' + target.php_version, '/usr/bin/wp', '--path=' + str(target.root), 'config', 'set']
    for name, value in [('CLOUDPANEL_COMPANION_STAGING_POLICY', str(policy_path)), ('CLOUDPANEL_COMPANION_STAGING_RELAY', socket_path)]:
        run(wp + [name, value, '--type=constant', '--quiet', "--anchor=require_once ABSPATH . 'wp-settings.php';"], cwd=str(target.root))
    unit = 'companion-relay@' + target.user + '.service'
    shutil.copyfile(root / 'assets/companion-relay@.service', '/etc/systemd/system/companion-relay@.service')
    run(['systemd-analyze', 'verify', '/etc/systemd/system/companion-relay@.service'])
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', unit])
    run(['systemctl', 'restart', unit])
    run(['systemctl', 'restart', 'companion-operations.service', 'companion-web.service'])
    print('Isolated staging transport and external-test controls installed. Existing operator credentials were preserved.')
    os.close(lock)


if __name__ == '__main__':
    main()
