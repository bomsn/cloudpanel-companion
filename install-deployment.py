"""Register maintenance routing and an uncached rendered-page release check."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
from companion.monitor import private_json
from companion.operations import write_private
from companion.staging import Site, validate_pair


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, capture_output=True, timeout=90, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--site', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Run the registered-site installer as root')
    from companion.maintenance import component_install
    with component_install(Path(__file__).resolve().parent):
        install(args)


def install(args):
    registry = private_json(args.registry)
    registered = registry['sites'][args.site]
    spec = private_json(Path(registered['specification']))
    live, stage = Site(**spec['source']), Site(**spec['target'])
    validate_pair(live, stage)
    if live.host != registered['source_host'] or stage.host != registered['host']:
        raise ValueError('Registered deployment pair changed')
    root = Path(__file__).resolve().parent
    health = registered.get('deploy_health_file') or 'companion-release-' + secrets.token_hex(16) + '.php'
    import re
    if not re.fullmatch(r'companion-release-[a-f0-9]{32}[.]php', health):
        raise ValueError('Invalid release check identity')
    content = '''<?php
header('Cache-Control: private, no-store');
if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'HEAD'], true) ||
    !empty($_SERVER['QUERY_STRING']) || $_COOKIE !== ['companion_release_check' => '1'] ||
    !empty($_SERVER['HTTP_AUTHORIZATION'])) {
    http_response_code(404);
    exit;
}
define('DONOTCACHEPAGE', true);
header('Cache-Control: private, no-store');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('X-Companion-OPcache-Validate: ' . (int) (bool) ini_get('opcache.validate_timestamps'));
header('X-Companion-OPcache-Revalidate: ' . (int) ini_get('opcache.revalidate_freq'));
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['SCRIPT_NAME'] = '/index.php';
$_SERVER['PHP_SELF'] = '/index.php';
require __DIR__ . '/index.php';
'''
    worker = '''import os,sys
from pathlib import Path
path=Path(sys.argv[1])
if path.is_symlink():raise ValueError('Health check cannot be a symlink')
with path.open('w') as stream:stream.write(sys.stdin.read())
path.chmod(0o644)
'''
    run(['/usr/sbin/runuser', '-u', live.user, '--', '/usr/bin/python3', '-c', worker,
         str(live.root / health)], input=content.encode())
    directory = Path('/etc/cloudpanel-companion/sites')
    include = directory / (live.user + '-deployment.conf')
    marker = directory / (live.user + '-deployment-paused')
    vhost = Path('/etc/nginx/sites-enabled') / (live.host + '.conf')
    original = vhost.read_text()
    from companion.nginx_templates import require_fresh_file_checks
    require_fresh_file_checks(run(['nginx', '-T']).stdout.decode(errors='replace'))
    write_private(include, 'set $companion_release_paused 0;\n'
        + 'if (-f ' + str(marker) + ') { set $companion_release_paused 1; }\n'
        + 'if ($uri = "/' + health + '") { set $companion_release_paused 0; }\n'
        + 'if ($companion_release_paused = 1) { return 503; }\n', 0o644)
    directive = 'include ' + str(include) + ';'
    if directive not in original:
        needle = '  server_name ' + live.host + ';'
        if original.count(needle) != 2:
            raise ValueError('Unexpected native routing; no change made')
        backup = Path('/etc/cloudpanel-companion') / ('vhost-before-deployment-' + live.host + '.conf')
        if not backup.exists():
            write_private(backup, original)
        candidate = original.replace(needle, needle + '\n  ' + directive, 1)
        write_private(vhost, candidate, 0o644)
        try:
            run(['nginx', '-t'])
        except Exception:
            write_private(vhost, original, 0o644)
            raise
        run(['systemctl', 'reload', 'nginx'])
    registered['deploy_health_file'] = health
    write_private(args.registry, json.dumps(registry))
    from companion.registered_deployment import Releases
    if not Releases(args.registry, args.site).observe():
        raise ValueError('Rendered uncached website check failed; release controls remain unqualified')
    print('Registered selected-code maintenance routing and real rendered-page checks installed. Deployment acceptance remains required.')


if __name__ == '__main__':
    main()
