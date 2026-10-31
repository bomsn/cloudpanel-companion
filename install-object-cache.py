"""Provision a private Redis service and use WordPress's maintained provider.

Never replaces a foreign/existing object-cache drop-in. Provider controls remain
in Redis Object Cache, avoiding a second implementation of its file lifecycle.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import subprocess
import time
from companion.monitor import private_json
from companion.operations import write_private


def run(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=90, **kwargs)
    if result.returncode:
        raise RuntimeError(Path(arguments[0]).name + ' failed: ' + result.stderr.decode()[-1000:])
    return result.stdout.decode().strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--php', required=True, choices=['8.2', '8.3', '8.4'])
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r'[a-z][a-z0-9-]{1,30}', args.user) or not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', args.host):
        raise ValueError('Root invocation and explicit site identity required')
    from companion.maintenance import component_install
    with component_install(Path(__file__).resolve().parent):
        install(args)


def install(args):
    account = pwd.getpwnam(args.user)
    if account.pw_uid < 1000:
        raise ValueError('WordPress must run as a non-system website identity')
    root = Path(account.pw_dir) / 'htdocs' / args.host
    if root.resolve() != root or root.is_symlink():
        raise ValueError('Use a native CloudPanel website root')
    wp = ['/usr/sbin/runuser', '-u', args.user, '--', '/usr/bin/php' + args.php, '/usr/bin/wp', '--path=' + str(root)]
    if run(wp + ['option', 'get', 'home']) != 'https://' + args.host:
        raise ValueError('WordPress identity mismatch')
    provider = root / 'wp-content/plugins/redis-cache/includes/object-cache.php'
    if not provider.is_file() or provider.is_symlink():
        raise ValueError('Install the maintained Redis Object Cache plugin before provisioning')
    run(wp + ['plugin', 'is-active', 'redis-cache'])
    run(['/usr/bin/php' + args.php, '-r', 'if(!class_exists("Redis"))exit(1);'])
    os.umask(0o077)
    directory = Path('/etc/cloudpanel-companion')
    directory.mkdir(mode=0o711, exist_ok=True)
    receipt = directory / ('object-cache-' + args.user + '.json')
    dropin = root / 'wp-content/object-cache.php'
    if dropin.exists() or dropin.is_symlink():
        if not receipt.exists():
            print('Existing object-cache provider retained. No automatic replacement or service change.')
            return
        previous = private_json(receipt)
        if previous.get('host') != args.host or previous.get('user') != args.user or dropin.is_symlink() or dropin.read_bytes() != provider.read_bytes():
            raise ValueError('Existing object cache does not match this owned provider; nothing replaced')
        print('Owned Redis Object Cache is already installed; no live cache flush or namespace change.')
        return
    service = 'companion-redis-' + args.user
    socket = '/run/' + service + '/cache.sock'
    config = directory / (service + '.conf')
    # One daemon/socket per site means the provider's flush cannot clear another
    # website or Companion authentication state. Cache data is disposable.
    write_private(config, 'port 0\nbind 127.0.0.1\nprotected-mode yes\ndaemonize no\nsupervised no\n'
        + 'unixsocket ' + socket + '\nunixsocketperm 770\nsave ""\nappendonly no\n'
        + 'maxmemory 128mb\nmaxmemory-policy allkeys-lru\nlogfile ""\n', 0o644)
    unit = Path('/etc/systemd/system') / (service + '.service')
    write_private(unit, '''[Unit]
Description=Private WordPress object cache for ''' + args.user + '''
After=network.target
[Service]
User=redis
Group=''' + args.user + '''
RuntimeDirectory=''' + service + '''
RuntimeDirectoryMode=0750
ExecStart=/usr/bin/redis-server ''' + str(config) + '''
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
MemoryMax=256M
TasksMax=16
UMask=0007
[Install]
WantedBy=multi-user.target
''', 0o644)
    run(['systemd-analyze', 'verify', str(unit)])
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', service + '.service'])
    deadline = time.monotonic() + 10
    while not Path(socket).exists() and time.monotonic() < deadline:
        time.sleep(.1)
    run(['/usr/sbin/runuser', '-u', args.user, '--', 'redis-cli', '-s', socket, 'PING'])
    values = {'WP_REDIS_SCHEME': 'unix', 'WP_REDIS_PATH': socket,
              'WP_REDIS_PREFIX': args.user + ':' + secrets.token_hex(16) + ':',
              'WP_REDIS_CLIENT': 'phpredis'}
    for name, value in values.items():
        run(wp + ['config', 'set', name, value, '--quiet', "--anchor=require_once ABSPATH . 'wp-settings.php';"])
    for name, value in [('WP_REDIS_DATABASE', '0'), ('WP_REDIS_TIMEOUT', '0.2'), ('WP_REDIS_READ_TIMEOUT', '0.2'),
                        ('CACHE_MANAGER_FOR_CLOUDPANEL_OBJECT_CACHE', 'true')]:
        run(wp + ['config', 'set', name, value, '--raw', '--quiet', "--anchor=require_once ABSPATH . 'wp-settings.php';"])
    # A namespace is fresh on each explicit re-enable. Old in-flight PHP cannot
    # repopulate keys that this new generation will read.
    run(wp + ['redis', 'enable'])
    run(wp + ['eval', 'if(!wp_using_ext_object_cache() || !wp_cache_set("companion_probe","ready","companion_probe",30))exit(1);'])
    run(wp + ['eval', 'if(wp_cache_get("companion_probe","companion_probe")!=="ready")exit(1); wp_cache_delete("companion_probe","companion_probe");'])
    write_private(receipt, json.dumps({'host': args.host, 'user': args.user, 'provider': 'redis-cache',
                                      'socket': socket, 'service': service + '.service'}))
    print('Dedicated Redis object cache connected; cross-request persistence verified. Provider controls remain in Redis Object Cache.')


if __name__ == '__main__':
    main()
