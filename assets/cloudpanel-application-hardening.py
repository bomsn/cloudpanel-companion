#!/usr/bin/env python3
"""Operator-owned CloudPanel application safeguards, separate from vendor files.

Audit is the default. Applying changes never changes management firewall rules,
SSH ports or passwords. Web attack filtering remains a separate Cloudflare WAF
responsibility; these controls are not advertised as a complete WAF/sandbox.
"""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess

HEADER = '# Managed by CloudPanel Companion application hardening.\n'
# Private rollback records an operator recovers from; tests use their own directory.
RECOVERY_DIRECTORY = Path('/var/lib/cloudpanel-companion-hardening')


def managed_header(path):
    # FPM's INI parser rejects shell/Nginx-style hash comments.
    return ';' + HEADER[1:] if path.as_posix().startswith('/etc/php/') else HEADER


def run(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=60, **kwargs)
    if result.returncode:
        raise RuntimeError(Path(arguments[0]).name + ' failed: ' + result.stderr.decode(errors='replace')[-1500:])
    return result.stdout


def secure_path(path, leaf=True):
    """Reject operator configuration under writable or substituted ancestors."""
    for current in [*reversed(path.parents), path] if leaf else reversed(path.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Configuration path is not controlled by root: ' + str(current))
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError('Configuration ancestor is not a directory')
        if current == path and not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('Configuration is not a regular file/directory')


def atomic(path, content, mode):
    secure_path(path)
    path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    secure_path(path.parent)
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def owned(path, content, mode=0o644):
    secure_path(path)
    marker = managed_header(path)
    if path.exists() and not path.read_text().startswith(marker):
        raise ValueError('Existing configuration has another owner: ' + str(path))
    atomic(path, marker + content, mode)


def website(value):
    fields = value.split(':')
    if len(fields) != 4:
        raise ValueError('Use host:unix-user:php-version:max-children')
    host, user, php, children = fields
    if (not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', host) or
            not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', user) or php not in ('8.2', '8.3', '8.4') or
            not children.isdecimal() or not 1 <= int(children) <= 128):
        raise ValueError('Invalid explicit website identity or process limit')
    account = pwd.getpwnam(user)
    if account.pw_uid < 1000:
        raise ValueError('Website identity must be a non-system user')
    pool = Path('/etc/php') / php / 'fpm/pool.d' / (host + '.conf')
    if pool.is_symlink() or pool.stat().st_uid != 0 or pool.stat().st_mode & 0o022:
        raise ValueError('Native PHP pool must be operator-owned')
    text = pool.read_text()
    if re.findall(r'^user\s*=\s*(\S+)\s*$', text, re.M) != [user]:
        raise ValueError('Native PHP pool identity mismatch')
    return {'host': host, 'user': user, 'php': php, 'children': int(children), 'uid': account.pw_uid}


def php_runtime(php):
    """Server-wide PHP drop-ins for one PHP version, kept apart from CloudPanel's php.ini.

    These are PHP_INI_SYSTEM settings, so neither CloudPanel's per-site PHP settings nor
    a pool can set them. Everything else stays at CloudPanel's defaults, which already
    meet the tested configuration: 768 MB OPcache, 1,000,000 files, timestamp validation
    every 2 s, 4 MB realpath cache, no open_basedir.
    """
    conf = Path('/etc/php') / php / 'fpm/conf.d'
    return {
        conf / '99-companion-security.ini': ('opcache.validate_permission=1\n', 0o644),
        # CloudPanel's default 8 MB interned-string buffer is full after one
        # WooCommerce/Elementor page load (about 28 MB measured after three pages);
        # a full buffer stores duplicate strings in every worker instead.
        # file_exists()/is_file()/is_readable() on cached scripts answer from OPcache:
        # part of the configuration the lab benchmarks used. Timestamp validation stays
        # on, so a deleted or changed file is noticed within opcache.revalidate_freq.
        conf / '99-companion-performance.ini': ('opcache.interned_strings_buffer=64\n'
                                                'opcache.enable_file_override=1\n', 0o644),
    }


def sensitive_routes():
    return '''disable_symlinks if_not_owner from=$document_root;
location = /wp-config.php { deny all; }
location = /wp-content/debug.log { deny all; }
location ~* ^/wp-content/(updraft|ai1wm-backups|backups?|wflogs)(/|$) { deny all; }
location ~* (^|/)\\.(?!well-known/) { deny all; }
location ~* ^/wp-content/(uploads|cache|upgrade|backups?)/.*[.](php[0-9]?|phtml|phar)(/|$) { deny all; }
location ~* [.](sql|sqlite3?|bak|old|orig|save|swp|env|ini|log)$ { deny all; }
'''


def egress_policy(uid, resolvers):
    """Private-address egress limits for one website identity.

    The owner test is a positive match: packets the kernel sends for sockets no process
    holds (the ACK or RST of an already closed connection) carry no owner, match neither
    `skuid UID` nor `skuid != UID`, and an exclusion would let them reach the loopback
    reject below for every user, stalling local connections (see companion/network.py).
    """
    if type(uid) is not int or not 1000 <= uid <= 2147483647:
        raise ValueError('Explicit website UID required')
    dns = ''
    for address in sorted(set(resolvers)):
        parsed = ipaddress.ip_address(address)
        family = 'ip' if parsed.version == 4 else 'ip6'
        dns += f'    {family} daddr {parsed} udp dport 53 return\n    {family} daddr {parsed} tcp dport 53 return\n'
    return f'''table inet companion_web_{uid} {{
 chain output {{
    type filter hook output priority 20; policy accept;
    meta skuid {uid} jump website
 }}
 chain website {{
    ct direction reply return
{dns}    ip daddr 127.0.0.1 tcp dport {{ 443, 6083 }} return
    ip6 daddr ::1 tcp dport 443 return
    ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }} reject
    ip6 daddr {{ ::/128, ::1/128, ::ffff:0:0/96, fc00::/7, fe80::/10, ff00::/8 }} reject
 }}
}}
'''


def apply_egress(user):
    account = pwd.getpwnam(user)
    if account.pw_uid < 1000 or not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', user):
        raise ValueError('Explicit non-system website identity required')
    resolvers = []
    for line in Path('/etc/resolv.conf').read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'nameserver':
            resolvers.append(str(ipaddress.ip_address(fields[1])))
    name = 'companion_web_' + str(account.pw_uid)
    present = subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', name], capture_output=True).returncode == 0
    policy = ('delete table inet ' + name + '\n' if present else '') + egress_policy(account.pw_uid, resolvers)
    run(['/usr/sbin/nft', '--check', '-f', '-'], input=policy.encode())
    run(['/usr/sbin/nft', '-f', '-'], input=policy.encode())


def effective_pools(version, sites):
    result = subprocess.run(['/usr/sbin/php-fpm' + version, '-tt'], capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('PHP configuration validation failed: ' + result.stderr.decode(errors='replace')[-1200:])
    sections, current = {}, None
    for line in (result.stdout + result.stderr).decode(errors='replace').splitlines():
        section = re.search(r'NOTICE: \[([^]]+)\]$', line)
        if section:
            current = section.group(1)
        count = re.search(r'NOTICE:\s+pm.max_children\s*=\s*(\d+)\s*$', line)
        if count and current:
            sections[current] = int(count.group(1))
    for site in sites:
        if site['php'] == version and sections.get(site['host']) != site['children']:
            raise ValueError('Effective PHP worker limit differs from the requested limit')


def service_state(name):
    return {'active': subprocess.run(['systemctl', 'is-active', '--quiet', name]).returncode == 0,
            'enabled': subprocess.run(['systemctl', 'is-enabled', '--quiet', name], capture_output=True).returncode == 0}


def configure(candidates, versions, sites, egress_users):
    """Persist rollback evidence before writes; restore only this utility's scope.

    No vendor file, management firewall or unrelated nftables table is changed.
    PHP process namespaces require a planned restart, which is explicit in CLI.
    """
    previous = {}
    for path in candidates:
        secure_path(path)
        if path.exists() and not path.read_text().startswith(managed_header(path)):
            raise ValueError('Existing configuration has another owner: ' + str(path))
        previous[str(path)] = {'content': path.read_text() if path.exists() else None,
                               'mode': stat.S_IMODE(path.stat().st_mode) if path.exists() else None}
    php_units = ['php' + version + '-fpm.service' for version in versions]
    egress_units = ['companion-web-egress-' + user + '.service' for user in egress_users]
    states = {name: service_state(name) for name in php_units + egress_units}
    tables = {}
    for user in egress_users:
        name = 'companion_web_' + str(pwd.getpwnam(user).pw_uid)
        result = subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', name], capture_output=True, timeout=10)
        tables[name] = result.stdout.decode() if result.returncode == 0 else None
    backup = RECOVERY_DIRECTORY
    secure_path(backup)
    backup.mkdir(mode=0o700, exist_ok=True)
    backup.chmod(0o700)
    receipt = backup / ('before-' + secrets.token_hex(12) + '.json')
    record = {'phase': 'prepared', 'files': previous, 'services': states, 'nftables': tables}
    atomic(receipt, json.dumps(record, indent=2), 0o600)
    try:
        for path, (content, mode) in candidates.items():
            owned(path, content, mode)
        run(['/usr/sbin/visudo', '-cf', '/etc/sudoers'])
        for version in versions:
            effective_pools(version, sites)
        run(['systemctl', 'daemon-reload'])
        for name in egress_units:
            run(['systemctl', 'enable', name])
            run(['systemctl', 'restart', name])
        for name in php_units:
            if states[name]['active']:
                run(['systemctl', 'restart', name])
        record['phase'] = 'configured'
        atomic(receipt, json.dumps(record, indent=2), 0o600)
    except Exception as error:
        failures = []
        def restore(action):
            try:
                action()
            except Exception as rollback_error:
                failures.append(str(rollback_error))
        for name in egress_units:
            restore(lambda name=name: run(['systemctl', 'stop', name]))
            if not states[name]['enabled']:
                restore(lambda name=name: run(['systemctl', 'disable', name]))
        for name, entry in previous.items():
            path = Path(name)
            def restore_file(path=path, entry=entry):
                secure_path(path)
                if entry['content'] is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic(path, entry['content'], entry['mode'])
            restore(restore_file)
        for name, content in tables.items():
            exists = subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', name], capture_output=True, timeout=10).returncode == 0
            policy = ('delete table inet ' + name + '\n' if exists else '') + (content or '')
            if policy:
                restore(lambda policy=policy: run(['/usr/sbin/nft', '-f', '-'], input=policy.encode()))
        restore(lambda: run(['systemctl', 'daemon-reload']))
        for name, state in states.items():
            if state['active']:
                restore(lambda name=name: run(['systemctl', 'restart', name]))
        record['phase'] = 'rollback-needs-review' if failures else 'rolled-back'
        record['rollback_errors'] = failures
        atomic(receipt, json.dumps(record, indent=2), 0o600)
        raise RuntimeError('Hardening failed; ' + record['phase'] + '. Private recovery record: ' + str(receipt)) from error
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', action='append', default=[])
    parser.add_argument('--deny-user', action='append', default=[])
    parser.add_argument('--production-egress-user', action='append', default=[])
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--restart-php-confirmed', action='store_true')
    parser.add_argument('--egress-worker')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Run as the server operator/root')
    if args.egress_worker:
        if not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', args.egress_worker):
            raise ValueError('Invalid website user')
        apply_egress(args.egress_worker)
        return
    sites = [website(value) for value in args.site]
    if not sites or len({site['host'] for site in sites}) != len(sites):
        raise ValueError('Register explicit distinct native PHP websites')
    users = set(args.deny_user) | {site['user'] for site in sites}
    for user in users:
        if not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', user) or pwd.getpwnam(user).pw_uid == 0 or user == 'clp':
            raise ValueError('Only non-operator application identities may be denied sudo')
    if set(args.production_egress_user) - {site['user'] for site in sites}:
        raise ValueError('Production egress applies only to explicitly registered websites')
    print(json.dumps({'mode': 'apply' if args.apply else 'audit', 'sites': sites,
                      'sudo_denied_users': sorted(users), 'production_egress_users': args.production_egress_user,
                      'management_firewall_unchanged': True}, indent=2))
    if not args.apply:
        return
    if not args.restart_php_confirmed:
        raise ValueError('Applying requires --restart-php-confirmed during a planned maintenance window')
    os.umask(0o077)
    lock_path = Path('/run/cloudpanel-companion-hardening.lock')
    secure_path(lock_path)
    lock = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    candidates = {}
    sudoers = Path('/etc/sudoers.d/zz-cloudpanel-companion-sites')
    candidates[sudoers] = ('\n'.join(user + ' ALL=(ALL:ALL) !ALL' for user in sorted(users)) + '\n', 0o440)
    versions = sorted({site['php'] for site in sites})
    for php in versions:
        candidates.update(php_runtime(php))
        # CloudPanel's ondemand pools stop idle workers after 10 s and recycle them
        # every 100 requests, so quiet sites pay a cold worker start on most visits.
        resource = ''.join('[' + site['host'] + ']\npm.max_children=' + str(site['children']) +
                           '\npm.process_idle_timeout=300s\npm.max_requests=1000\n'
                           for site in sites if site['php'] == php)
        candidates[Path('/etc/php') / php / 'fpm/pool.d/zz-companion-resource-limits.conf'] = (resource, 0o644)
        dropin = Path('/etc/systemd/system') / ('php' + php + '-fpm.service.d')
        egress_units = ['companion-web-egress-' + site['user'] + '.service' for site in sites
                        if site['php'] == php and site['user'] in args.production_egress_user]
        dependency = ('[Unit]\nRequires=' + ' '.join(egress_units) + '\nAfter=' + ' '.join(egress_units) + '\n') if egress_units else ''
        candidates[dropin / 'companion-proc.conf'] = (dependency + '[Service]\nProtectProc=invisible\n', 0o644)
    for site in sites:
        candidates[Path('/etc/cloudpanel-companion/sites') / (site['user'] + '-security.conf')] = (sensitive_routes(), 0o644)
    destination = Path('/opt/cloudpanel-companion-security.py')
    source = Path(__file__).read_text()
    candidates[destination] = (source.removeprefix(HEADER), 0o644)
    for user in args.production_egress_user:
        unit = Path('/etc/systemd/system') / ('companion-web-egress-' + user + '.service')
        candidates[unit] = ('[Unit]\nDescription=Private-address protection for ' + user + '\nAfter=ufw.service network-online.target\nWants=network-online.target\n'
              '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 /opt/cloudpanel-companion-security.py --egress-worker ' + user + '\n'
              '[Install]\nWantedBy=multi-user.target\n', 0o644)
    receipt = configure(candidates, versions, sites, args.production_egress_user)
    print(json.dumps({'configured': True, 'rollback_record': str(receipt),
                      'native_vhost_action_required': 'Persist the owned per-site security include in the native Vhost template.'}))


if __name__ == '__main__':
    main()
