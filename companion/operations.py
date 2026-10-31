"""Narrow local operations boundary for registered staging sites.

Only the companion web identity and root can connect. Requests contain a site
ID and a small fixed action set; they cannot supply paths or commands. Registry
and access snippets belong to root outside website directories.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import time
from .monitor import private_json


def write_private(path, data, mode=0o600):
    if path.is_symlink():
        raise ValueError('Managed path cannot be a symlink')
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(12) + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        # Explicit managed permissions must survive the service's private umask;
        # policy readers need their intentional group-read bit, secrets do not.
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class Operations:
    def __init__(self, registry, registry_path=None):
        self.sites = registry['sites']
        for name, site in self.sites.items():
            if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', name):
                raise ValueError('Invalid registered site ID')
            for key in ('host', 'source_host'):
                if not re.fullmatch(r'[a-z0-9.-]{1,253}', site[key]) or '..' in site[key]:
                    raise ValueError('Invalid registered hostname')
            if not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', site['user']):
                raise ValueError('Invalid staging identity')
        self.jobs = None
        if registry_path is not None:
            from .jobs import RegisteredJobs
            self.jobs = RegisteredJobs(registry, registry_path)

    def action(self, request, internal=False):
        site_id = request['site']
        site = self.sites[site_id]
        user, host = site['user'], site['host']
        directory = Path('/etc/cloudpanel-companion/sites')
        policy = directory / (user + '-access.json')
        snippet = directory / (user + '-access.conf')
        include = 'include ' + str(snippet) + ';'
        vhost = Path('/etc/nginx/sites-enabled') / (host + '.conf')
        if vhost.read_text().count(include) != 2:
            raise ValueError('Staging routing changed; inspect its access integration before operating it')
        current = {'protected': not (directory / (user + '-public')).exists(),
                   'paused': (directory / (user + '-paused')).exists()}
        from .relay import default_policy, load_policy, normalize_policy, operator_inbox
        external_path = directory / (user + '.json')
        forbidden = set(site.get('protected_hosts', [])) | {site['source_host'], site['host']}
        operation = request['operation']
        if operation == 'status':
            result = {'host': host, 'source_host': site['source_host'], **current}
            result['external'] = default_policy()
            result['external_error'] = False
            result['protected_hosts'] = sorted(forbidden)
            result['relay_configured'] = site.get('relay_socket') == '/run/cloudpanel-companion-relay/' + user + '/transport.sock'
            if external_path.exists():
                try:
                    result['external'] = load_policy(external_path, forbidden)
                except (ValueError, OSError):
                    result['external_error'] = True
            if self.jobs:
                result['job'] = self.jobs.status(site_id)
            return result
        actor = request.get('actor', '')
        if not isinstance(actor, str) or not 1 <= len(actor) <= 150:
            raise ValueError('Operator identity required')
        if operation in ('mail_list', 'mail_read'):
            relay = '/run/cloudpanel-companion-relay/' + user + '/transport.sock'
            if site.get('relay_socket') != relay:
                raise ValueError('Test inbox is not configured')
            return operator_inbox(relay, operation, request.get('id'))
        if operation == 'refresh' and self.jobs:
            return self.jobs.refresh(site_id, actor, request.get('confirmed'))
        if operation == 'release_status' and self.jobs:
            from .registered_deployment import Releases
            releases = Releases(self.jobs.registry_path, site_id)
            return {'releases': releases.listing(), 'folders': releases.worker(releases.stage, 'choices', {}), 'job': self.jobs.status(site_id)}
        if operation == 'release_detail' and self.jobs:
            from .registered_deployment import Releases
            releases = Releases(self.jobs.registry_path, site_id)
            return releases.public(releases.load(request['token']))
        if operation in ('comparison_status', 'comparison_detail') and self.jobs:
            from .registered_compare import Comparison
            comparison = Comparison(self.jobs.registry_path, site_id)
            if operation == 'comparison_detail':
                return comparison.detail(request['folder'], request.get('page', 1), request.get('generation'))
            return {'comparison': comparison.snapshot(), 'job': self.jobs.status(site_id)}
        if self.jobs and not internal:
            job = self.jobs.status(site_id)
            if job and (job['running'] or (job['blocked'] and operation != 'release_recover')):
                raise ValueError('Staging controls are locked until the active job finishes or is recovered')
        if operation in ('release_preview', 'release_apply', 'release_recover', 'release_discard') and self.jobs:
            from .registered_deployment import Releases
            releases = Releases(self.jobs.registry_path, site_id)
            if operation == 'release_preview':
                return releases.preview(request['files'], actor)
            if operation == 'release_discard':
                return releases.discard(request['token'], actor)
            if request.get('confirmed') is not True:
                raise ValueError('Explicit selected-code release confirmation required')
            return self.jobs.deploy(site_id, actor, request['token'], operation == 'release_recover')
        if operation == 'compare' and self.jobs:
            return self.jobs.compare(site_id, actor)
        if operation in ('external', 'external_stop'):
            if site.get('relay_socket') != '/run/cloudpanel-companion-relay/' + user + '/transport.sock':
                raise ValueError('Staging transport is not configured')
            normalized = normalize_policy(request['policy'], forbidden) if operation == 'external' else default_policy()
            write_private(external_path, json.dumps(normalized), 0o640)
            os.chown(external_path, 0, pwd.getpwnam(user).pw_gid)
        elif operation in ('protection', 'pause'):
            value = request['enabled']
            if type(value) is not bool:
                raise ValueError('Explicit boolean required')
            marker = directory / (user + ('-public' if operation == 'protection' else '-paused'))
            enabled = not value if operation == 'protection' else value
            if enabled:
                write_private(marker, 'enabled\n', 0o644)
            else:
                if marker.is_symlink():
                    raise ValueError('Access marker cannot be a symlink')
                marker.unlink(missing_ok=True)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        elif operation == 'password':
            password = request['password']
            if (not isinstance(password, str) or not 14 <= len(password) <= 72 or
                    len(password.encode('utf-8')) > 72 or any(ord(c) < 32 for c in password)):
                raise ValueError('Use at least 14 characters and at most 72 UTF-8 bytes, without control characters')
            hashed = subprocess.run(['/usr/bin/htpasswd', '-niB', 'staging'], input=(password + '\n').encode(),
                                    check=True, capture_output=True, timeout=10).stdout.decode()
            write_private(Path('/etc/cloudpanel-companion') / (user + '.htpasswd'), hashed)
        else:
            raise ValueError('Unsupported operation')
        # Audit only the operation, never credentials or request payloads.
        with Path('/var/lib/cloudpanel-companion-operations/audit.jsonl').open('a') as stream:
            stream.write(json.dumps({'at': int(time.time()), 'actor': actor, 'site': site_id, 'operation': operation}) + '\n')
        return {'saved': True}


def render_access(user, policy, health_file=None):
    if not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', user) or set(policy) != {'protected', 'paused'}:
        raise ValueError('Invalid access policy')
    if any(type(value) is not bool for value in policy.values()):
        raise ValueError('Invalid policy values')
    directory = '/etc/cloudpanel-companion/sites/' + user
    result = ('open_file_cache off;\nset $companion_staging_realm "Private staging";\n'
              'if (-f ' + directory + '-public) { set $companion_staging_realm off; }\n'
              'auth_basic $companion_staging_realm;\n')
    result += 'auth_basic_user_file /etc/cloudpanel-companion/' + user + '.htpasswd;\n'
    result += ('set $companion_staging_paused 0;\n'
               'if (-f ' + directory + '-paused) { set $companion_staging_paused 1; }\n'
               'if ($uri ~ "^/\\.well-known/acme-challenge/[A-Za-z0-9_-]+$") { set $companion_staging_paused 0; }\n'
               '')
    if health_file is not None:
        if not re.fullmatch(r'companion-health-[a-f0-9]{32}\.php', health_file):
            raise ValueError('Invalid private health endpoint')
        result += ('if ($uri = "/' + health_file + '") { set $companion_staging_paused 0; set $companion_staging_realm off; }\n')
    result += 'if ($companion_staging_paused = 1) { return 503; }\n'
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Operations boundary runs as root')
    operations = Operations(private_json(args.registry), args.registry)
    permitted_uid = pwd.getpwnam('companion-web').pw_uid

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(30)
            _, uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid not in (0, permitted_uid):
                return
            try:
                raw = self.rfile.readline(65537)
                if len(raw) > 65536 or not raw.endswith(b'\n'):
                    raise ValueError('Invalid request size')
                from .maintenance import admissions
                with admissions():
                    result = {'ok': True, 'result': operations.action(json.loads(raw), internal=uid == 0)}
            except ValueError as error:
                result = {'ok': False, 'error': str(error)}
            except Exception:
                result = {'ok': False, 'error': 'Operation failed. Inspect the server state before retrying.'}
            self.wfile.write(json.dumps(result).encode() + b'\n')

    if args.socket.exists():
        if not args.socket.is_socket():
            raise ValueError('Operations socket path is occupied')
        args.socket.unlink()
    with socketserver.UnixStreamServer(str(args.socket), Handler) as server:
        os.chown(args.socket, 0, grp.getgrnam('companion-web').gr_gid)
        os.chmod(args.socket, 0o660)
        server.serve_forever()


if __name__ == '__main__':
    main()
