"""Install endpoint checks and optional private server history.

Use install-web.py first. Include the printed telemetry file in the native
public vhost template. CloudPanel core and generated vhosts are not rewritten.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
from companion.client_address import LOG_DIRECTORY
from companion.maintenance import component_install
from companion.monitor import private_json
from companion.operations import write_private
from companion.monitor_setup import certificate_hosts, endpoint_configuration, service_configuration, service_profile, site_label
from companion.php_pool import pool
from companion.site_trust import site_ca_file

# The website's request-timing log, read by companion.telemetry.
REQUEST_LOG = LOG_DIRECTORY / 'requests.jsonl'


def run(*arguments):
    subprocess.run(arguments, check=True)


def database_observer():
    """One unprivileged local SQL account, with no access to customer tables.

    Native master credentials exist only in a root-private temporary option
    file during initial provisioning. They never enter argv or service state.
    """
    configuration = Path('/etc/cloudpanel-companion/telemetry-mysql.cnf')
    existing = configuration.exists()
    if existing:
        info = configuration.lstat()
        if configuration.is_symlink() or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Database observer credentials must be root-private')
        result = subprocess.run(['/usr/bin/mysql', '--defaults-file=' + str(configuration), '--batch',
                                 '-e', "SHOW GLOBAL STATUS LIKE 'Threads_connected'"], capture_output=True, timeout=5)
        if result.returncode == 0:
            return
    raw = subprocess.run(['clpctl', 'db:show:master-credentials', '--no-ansi'], capture_output=True, check=True, timeout=15).stdout.decode()
    lines = [line for line in raw.splitlines() if line.startswith('Connect Command: ')]
    if len(lines) != 1:
        raise ValueError('Native database credential format changed')
    arguments = shlex.split(lines[0].removeprefix('Connect Command: '))
    credentials = {name: next((value[2:] for value in arguments if value.startswith('-' + flag)), None)
                   for name, flag in (('host', 'h'), ('user', 'u'), ('password', 'p'), ('port', 'P'))}
    if not all(credentials.values()) or credentials['host'] not in ('localhost', '127.0.0.1'):
        raise ValueError('Only a local native database server is supported')
    def options(values):
        return '[client]\n' + ''.join(key + '="' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r') + '"\n' for key, value in values.items())
    password = secrets.token_hex(32) if not existing else None
    if not existing:
        # Persist the intended credentials before creating the account. Replay
        # after interruption can finish the same account without resetting it.
        write_private(configuration, options({'user': 'companion_observe', 'password': password, 'host': 'localhost'}))
    else:
        match = re.search(r'^password="([a-f0-9]{64})"$', configuration.read_text(), re.M)
        if not match:
            raise ValueError('Observer credential format changed; review before provisioning')
        password = match[1]
    with tempfile.TemporaryDirectory(prefix='companion-db-observer-', dir='/run') as directory:
        temporary = Path(directory) / 'master.cnf'
        write_private(temporary, options(credentials))
        # CREATE refuses a pre-existing unrelated account rather than resetting
        # its password. USAGE permits these global counters without table access.
        query = "CREATE USER IF NOT EXISTS 'companion_observe'@'localhost' IDENTIFIED BY '" + password + "';"
        subprocess.run(['/usr/bin/mysql', '--defaults-file=' + str(temporary)],
                       input=query.encode(), check=True, capture_output=True, timeout=10)
    subprocess.run(['/usr/bin/mysql', '--defaults-file=' + str(configuration), '--batch',
                    '-e', "SHOW GLOBAL STATUS LIKE 'Threads_connected'"], check=True, capture_output=True, timeout=5)


def install(args):
    source = Path(__file__).resolve().parent
    registered = None
    if args.site_host:
        if not re.fullmatch(r'[a-z0-9.-]+', args.site_host) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', args.site_user or ''):
            raise ValueError('Use the registered native website identity')
        identity = pwd.getpwnam(args.site_user)
        if identity.pw_uid < 1000 or Path(identity.pw_dir) != Path('/home') / args.site_user:
            raise ValueError('Website needs its independent native home and identity')
        # Server history reads this pool's status; refuse one that is not the site's own.
        pool(args.site_user, args.site_host, args.php)
        registry_path = Path('/etc/cloudpanel-companion/operations.json')
        if registry_path.exists():
            matches = [item for item in private_json(registry_path)['sites'].values() if item['source_host'] == args.site_host]
            if len(matches) > 1:
                raise ValueError('Multiple registered copies belong to this website; review the registry')
            if matches:
                registered = matches[0]
                from companion.staging import Site
                selected = Site(**private_json(Path(registered['specification']))['source'])
                selected.validate()
                if (selected.host, selected.user, selected.php_version) != (args.site_host, args.site_user, args.php):
                    raise ValueError('Monitoring website differs from the registered source')
    monitor_path = Path('/etc/cloudpanel-companion/monitor.json')
    existing = private_json(monitor_path) if monitor_path.exists() else None
    desired = existing
    if existing is None or args.configure_targets:
        if not args.site_host:
            raise ValueError('Initial origin checks require --site-host and --site-user')
        web = Path('/etc/cloudpanel-companion/web.json')
        desired = endpoint_configuration(existing, args.site_host,
                    registered['source_health_file'] if registered else None,
                    selected.database if registered else None, site_ca_file(args.site_host) is not None,
                    certificate_hosts(private_json(web)) if web.exists() else ())
        from companion.health import Target, probe
        previous = {item['name']: item for item in (existing or {}).get('targets', [])}
        # A certificate check only reports: an untrusted panel certificate shows on
        # the Overview instead of stopping the installation.
        for item in desired['targets']:
            if previous.get(item['name']) != item and not item.get('certificate_only') and not probe(Target(**item)).healthy:
                raise ValueError('An origin/application check failed before configuration was saved. Verify its native HTTPS certificate and database.')
    # Configure only known installed units. Replays preserve labels and deliberate
    # recovery-off choices; adding a new component never rewrites other services.
    # Labels name alerts, so they keep the website's name; the interface groups and
    # describes each unit from the catalog in companion.monitor_setup.
    prefix = site_label(args.site_host) if args.site_host else 'Server'
    candidates = ['nginx.service', 'clp-php-fpm.service', 'companion-web.service', 'companion-operations.service',
                  'varnish.service', 'cache-manager-control.service', 'companion-security-cache.service', 'fail2ban.service']
    if args.site_host:
        candidates += ['php' + args.php + '-fpm.service', 'companion-redis-' + args.site_user + '.service']
    if registered:
        candidates.append('companion-relay@' + registered['user'] + '.service')
    def installed(name):
        result = subprocess.run(['systemctl', 'show', name, '--property=LoadState', '--value'],
                                capture_output=True, timeout=5)
        return result.returncode == 0 and result.stdout.strip() == b'loaded'
    for name in ('mariadb.service', 'mysql.service'):
        if installed(name):
            candidates.append(name)
            break
    candidates = [(name, prefix + ': ' + service_profile(name)[1]) for name in candidates if installed(name)]
    watch_path = Path('/etc/cloudpanel-companion/system-watch.json')
    watch_existing = private_json(watch_path) if watch_path.exists() else None
    watch = service_configuration(watch_existing, candidates, args.enable_recovery)
    for path, mode in [(Path('/var/lib/cloudpanel-companion-system'), 0o700),
                       (Path('/var/lib/cloudpanel-companion-system-observations'), 0o750)]:
        if path.is_symlink() or path.resolve() != path:
            raise ValueError('Service observation storage cannot be a link')
        if path.exists() and (path.stat().st_uid != 0 or path.stat().st_mode & 0o022):
            raise ValueError('Service observation storage must be operator-owned')
        path.mkdir(mode=mode, exist_ok=True)
        path.chmod(mode)
        if mode == 0o750:
            os.chown(path, 0, __import__('grp').getgrnam('companion-web').gr_gid)
    if desired != existing:
        write_private(monitor_path, json.dumps(desired))
    if watch != watch_existing:
        write_private(watch_path, json.dumps(watch))
    from companion.installation import monitor_export
    monitor_export(source)
    units = ['companion-monitor.service', 'companion-monitor.timer', 'companion-delivery.service', 'companion-delivery.timer',
             'companion-system-watch.service', 'companion-system-watch.timer',
             'companion-system-delivery.service', 'companion-system-delivery.timer']
    if args.site_host:
        config = Path('/etc/cloudpanel-companion/telemetry.json')
        if config.exists():
            current = private_json(config)
            if current['host'] != args.site_host or current['user'] != args.site_user or current['php'] != args.php:
                raise ValueError('Existing history belongs to a different native website')
        # Operator-owned diagnostics the site's own PHP pool runs; see companion.telemetry.
        diagnostic = Path(identity.pw_dir) / '.companion-diagnostics.php'
        wordpress = Path(identity.pw_dir) / '.companion-wordpress-health.php'
        for path, asset in ((diagnostic, 'php-diagnostics.php'), (wordpress, 'wordpress-health.php')):
            if path.is_symlink():
                raise ValueError('Diagnostic cannot replace a link')
            write_private(path, (source / 'assets' / asset).read_text(), 0o644)
        config_data = {'host': args.site_host, 'user': args.site_user, 'php': args.php, 'probe': str(diagnostic),
                       'wordpress_probe': str(wordpress),
                       'access_log': str(REQUEST_LOG),
                       'error_logs': {'nginx': str(Path(identity.pw_dir) / 'logs/nginx/error.log'),
                                      'php': str(Path(identity.pw_dir) / 'logs/php/error.log')}}
        write_private(config, json.dumps(config_data))
        database_observer()
        for directory, mode in [('/var/lib/cloudpanel-companion-telemetry', 0o700),
                                ('/var/lib/cloudpanel-companion-telemetry-observations', 0o750),
                                (str(LOG_DIRECTORY), 0o750)]:
            path = Path(directory)
            if path.is_symlink():
                raise ValueError('Monitoring directories cannot be links')
            path.mkdir(mode=mode, exist_ok=True)
            os.chown(path, 0, __import__('grp').getgrnam('companion-web').gr_gid if 'observations' in directory else 0)
            os.chmod(path, mode)
        units += ['companion-telemetry.service', 'companion-telemetry.timer']
        # Coarse groups omit raw URLs, arguments, IPs and identifiers.
        nginx = r'''map $uri $companion_route_path {
    default other;
    / home;
    ~^/(product-category|shop)/ catalog;
    ~^/product/ product;
    ~^/cart/?$ cart;
    ~^/checkout/ checkout;
    ~^/my-account/ account;
    ~^/wp-admin/admin-ajax\.php$ api;
    ~^/wp-admin/ admin;
    ~^/wp-json/ api;
}
map $args $companion_route {
    default $companion_route_path;
    ~(^|&)(wc-ajax|rest_route)= api;
}
map $uri $companion_observe_route {
    default 1;
    ~^/companion-(origin|release|health)- 0;
    ~^/(favicon.ico|robots.txt)$ 0;
    ~*\.(css|js|png|jpg|jpeg|gif|webp|svg|ico|woff2?|pdf|mp4|webm)$ 0;
}
map "$companion_observe_route:$http_user_agent" $companion_observe {
    default 1;
    ~^0: 0;
    ~*:CloudPanel-Companion-Health/ 0;
}
log_format companion_private escape=json '{"route":"$companion_route","status":$status,"cache":"$upstream_http_x_cache_manager_for_cloudpanel","upstream":"$upstream_header_time"}';
'''
        # CloudPanel loads sites-enabled at HTTP scope, not conf.d. The owned
        # filename sorts before site templates that reference this log format.
        destination = Path('/etc/nginx/sites-enabled/000-companion-observations.conf')
        before = destination.read_bytes() if destination.exists() else None
        write_private(destination, nginx, 0o644)
        try:
            run('nginx', '-t')
        except BaseException:
            if before is None:
                destination.unlink()
            else:
                write_private(destination, before.decode(), 0o644)
            raise
        write_private(Path('/etc/cloudpanel-companion/telemetry-public.conf'),
                      f'access_log {REQUEST_LOG} companion_private buffer=32k flush=5s if=$companion_observe;\n', 0o644)
        write_private(Path('/etc/logrotate.d/cloudpanel-companion'), str(LOG_DIRECTORY) + '''/*.jsonl {
    daily
    maxsize 10M
    rotate 3
    missingok
    notifempty
    nocompress
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/sbin/nginx -s reopen
    endscript
}
''', 0o644)
        run('systemctl', 'reload', 'nginx')
        print("Include for the website's vhost in CloudPanel: /etc/cloudpanel-companion/telemetry-public.conf")
    for unit in units:
        shutil.copyfile(source / 'assets' / unit, Path('/etc/systemd/system') / unit)
    run('systemd-analyze', 'verify', *('/etc/systemd/system/' + unit for unit in units))
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'companion-system-watch.service')
    run('systemctl', 'start', 'companion-monitor.service')
    run('systemctl', 'enable', '--now', *(unit for unit in units if unit.endswith('.timer')))
    if args.site_host:
        run('systemctl', 'start', 'companion-telemetry.service')
    print('Monitoring installed. Your existing checks, alert settings and operators were kept.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site-host')
    parser.add_argument('--site-user')
    parser.add_argument('--php', choices=('8.2', '8.3', '8.4'), default='8.3')
    parser.add_argument('--configure-targets', action='store_true', help='Merge and verify local-origin and registered database checks and the website\'s certificate trust; retain other targets')
    parser.add_argument('--enable-recovery', action='store_true', help='Enable bounded failed-service recovery for newly registered services only; preserve existing choices')
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as the server operator')
    with component_install(Path(__file__).resolve().parent):
        install(arguments)
