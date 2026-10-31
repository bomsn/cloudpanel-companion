"""Registered staging-to-website releases with explicit reviewed code selection.

The root coordinator owns approvals, maintenance routing and HTTP observation.
Website owners own payload transport, PHP execution and conflict-safe recovery.
Neither browser callers nor website files supply privileged command paths.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from .monitor import private_json
from .operations import write_private
from .provision import command, site_wp
from .site_trust import curl_trust
from .staging import Site, validate_pair
from .drain import drain


def release_check(host, health_file):
    """The uncached rendered-page check releases rely on: real HTML with fresh OPcache."""
    raw = command(['/usr/bin/curl', '--silent', '--show-error', '--max-time', '12',
                   '--connect-timeout', '3', '--max-filesize', '2097152', '--dump-header', '-',
                   '--resolve', host + ':443:127.0.0.1', *curl_trust(host),
                   '--header', 'Cookie: companion_release_check=1',
                   '--write-out', '\n%{http_code}',
                   'https://' + host + '/' + health_file], timeout=15)
    headers, _, body = raw.partition(b'\r\n\r\n')
    if not body:
        headers, _, body = raw.partition(b'\n\n')
    values = {}
    for line in headers.decode(errors='replace').splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            values[key.lower()] = value.strip()
    return (body.endswith(b'\n200') and b'</html>' in body.lower() and
            values.get('x-companion-opcache-validate') == '1' and
            values.get('x-companion-opcache-revalidate') in ('0', '1', '2', '3', '4', '5') and
            'no-store' in values.get('cache-control', ''))


class Releases:
    def __init__(self, registry_path, site_id):
        self.registry_path, self.site_id = registry_path, site_id
        registry = private_json(registry_path)
        self.registered = registry['sites'][site_id]
        spec = private_json(Path(self.registered['specification']))
        self.live, self.stage = Site(**spec['source']), Site(**spec['target'])
        validate_pair(self.live, self.stage)
        if (self.live.host != self.registered['source_host'] or self.stage.host != self.registered['host'] or
                self.stage.user != self.registered['user']):
            raise ValueError('Deployment pair does not match the registry')
        self.base = Path('/var/lib/cloudpanel-companion-operations/plans') / site_id
        self.base.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.marker = Path('/etc/cloudpanel-companion/sites') / (self.live.user + '-deployment-paused')
        health = self.registered.get('deploy_health_file', '')
        if not re.fullmatch(r'companion-release-[a-f0-9]{32}[.]php', health):
            raise ValueError('Registered deployment checks are not installed')
        self.health_file = health
        include = '/etc/cloudpanel-companion/sites/' + self.live.user + '-deployment.conf'
        vhost = Path('/etc/nginx/sites-enabled') / (self.live.host + '.conf')
        if vhost.read_text().count('include ' + include + ';') != 1:
            raise ValueError('Deployment maintenance routing changed; inspect it before releasing files')

    def worker(self, site, operation, request, check=False):
        arguments = ['/usr/sbin/runuser', '-u', site.user, '--', '/usr/bin/python3',
                     '-m', 'companion.deployment_transfer', operation]
        request = {'root': str(site.root), **request}
        environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                       'PYTHONPATH': '/opt/cloudpanel-companion'}
        if not check:
            process = subprocess.run(arguments, input=json.dumps(request).encode() + b'\n',
                                     capture_output=True, timeout=60, cwd='/opt/cloudpanel-companion', env=environment)
            if process.returncode:
                raise ValueError('Selected-file transport failed; inspect its registered source and target')
            raw = process.stdout
            if len(raw) > 48 * 1024 * 1024:
                raise ValueError('Deployment transport exceeded its limit')
            return json.loads(raw)
        with subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd='/opt/cloudpanel-companion', env=environment, text=True) as process:
            process.stdin.write(json.dumps(request) + '\n')
            process.stdin.flush()
            # At most one post-write and one rollback observation are expected.
            result = None
            for _ in range(3):
                line = process.stdout.readline(4 * 1024 * 1024 + 1)
                if not line or len(line) > 4 * 1024 * 1024 or not line.endswith('\n'):
                    break
                response = json.loads(line)
                if response == {'check': True}:
                    try:
                        self.invalidate()
                        time.sleep(3)
                        healthy = self.observe()
                    except Exception:
                        healthy = False
                    process.stdin.write(json.dumps({'healthy': healthy}) + '\n')
                    process.stdin.flush()
                else:
                    result = response
                    break
            process.stdin.close()
            process.wait(timeout=30)
            process.stderr.read(16384)
            if process.returncode or result is None:
                raise ValueError('Website release worker failed; its private recovery state requires inspection')
            return result

    def observe(self):
        return release_check(self.live.host, self.health_file)

    def invalidate(self):
        cache = Path('/etc/cloudpanel-companion/cache-sites.json')
        if cache.exists() and any(site['host'] == self.live.host for site in private_json(cache)['sites']):
            command(site_wp(self.live) + ['cloudpanel-cache', 'purge'], timeout=20)
        object_cache = Path('/etc/cloudpanel-companion') / ('object-cache-' + self.live.user + '.json')
        if object_cache.exists():
            receipt = private_json(object_cache)
            if receipt['host'] != self.live.host or receipt['user'] != self.live.user or receipt['socket'] != '/run/companion-redis-' + self.live.user + '/cache.sock':
                raise ValueError('Object cache ownership changed')
            command(site_wp(self.live) + ['cache', 'flush'], timeout=20)

    def load(self, token):
        if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{32}', token):
            raise ValueError('Invalid release identity')
        record = private_json(self.base / (token + '.json'), max_bytes=32 * 1024 * 1024)
        if record['site'] != self.site_id or record['token'] != token:
            raise ValueError('Release belongs to another site')
        return record

    def save(self, record):
        record['updated_ns'] = time.time_ns()
        write_private(self.base / (record['token'] + '.json'), json.dumps(record))

    def preview(self, files, actor):
        self.retire()
        records = list(self.base.glob('*.json'))
        if len(records) >= 10:
            raise ValueError('Ten release snapshots are retained. Retire reviewed old snapshots before preparing another.')
        hashes = self.worker(self.stage, 'hashes', {'files': files})
        targets = self.worker(self.live, 'target_hashes', {'files': [row['file'] for row in hashes]})
        target = {row['file']: row['sha256'] for row in targets}
        changed = [row['file'] for row in hashes if row['sha256'] != target[row['file']]]
        if not changed:
            raise ValueError('The selected code already matches the website. Check changes again after editing staging.')
        rows = self.worker(self.stage, 'read', {'files': changed})
        source = {row['file']: row['sha256'] for row in hashes}
        if any(row['sha256'] != source[row['file']] for row in rows):
            raise ValueError('Staging changed while the preview was prepared; prepare it again')
        token = secrets.token_hex(16)
        try:
            plan = self.worker(self.live, 'prepare', {'token': token, 'rows': rows})
            if any(row['live_sha256'] != target[row['file']] for row in plan['changes']):
                raise ValueError('The website changed while preparing the preview; prepare it again')
        except Exception:
            self.worker(self.live, 'cleanup', {'token': token})
            raise
        record = {'token': token, 'site': self.site_id, 'actor': actor, 'created_at': int(time.time()),
                  'expires_at': int(time.time()) + 600, 'phase': 'preview', 'plan': plan,
                  'selection': files,
                  'source_hashes': hashes, 'target_fingerprint': self.fingerprint(targets)}
        self.save(record)
        return self.public(record)

    @staticmethod
    def fingerprint(rows):
        return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def public(self, record, details=True):
        result = {key: record[key] for key in ('token', 'actor', 'created_at', 'expires_at', 'phase')} | {
            'source_host': self.stage.host, 'target_host': self.live.host,
            'file_count': len(record['plan']['changes']),
            'changed_count': sum(row['action'] != 'unchanged' for row in record['plan']['changes'])}
        if details:
            result['changes'] = record['plan']['changes']
        return result

    def listing(self):
        return [self.public(private_json(path, max_bytes=32 * 1024 * 1024), details=False) for path in sorted(self.base.glob('*.json'),
                key=lambda path: path.stat().st_mtime, reverse=True)[:10]]

    def retire(self):
        """Bound private release storage without removing active recovery copies."""
        active = None
        job_file = Path('/var/lib/cloudpanel-companion-operations/jobs') / (self.site_id + '.json')
        if job_file.exists():
            job = private_json(job_file)
            if job.get('operation') == 'deploy' and (job.get('returncode') is None or job.get('blocked')):
                active = job.get('token')
        records = sorted((private_json(path, max_bytes=32 * 1024 * 1024) for path in self.base.glob('*.json')),
                         key=lambda record: record.get('updated_ns', record['created_at'] * 1000000000), reverse=True)
        protected = set()
        for phase in ('completed', 'rolled-back'):
            protected.update(record['token'] for record in [item for item in records if item['phase'] == phase][:2])
        for record in records:
            phase, token = record['phase'], record['token']
            if token == active or token in protected or phase in ('applying', 'recovery-needs-review'):
                continue
            if phase == 'preview' and record['expires_at'] >= int(time.time()):
                continue
            if phase not in ('preview', 'completed', 'rolled-back', 'not-applied', 'rejected-php-syntax'):
                continue
            self.worker(self.live, 'cleanup', {'token': token})
            (self.base / (token + '.json')).unlink()

    def discard(self, token, actor):
        record = self.load(token)
        if record['actor'] != actor or record['phase'] != 'preview':
            raise ValueError('Only your unapplied preview can be discarded')
        self.worker(self.live, 'cleanup', {'token': token})
        (self.base / (token + '.json')).unlink()
        return {'removed': True}

    def execute(self, token, actor, state, recovery=False):
        record = self.load(token)
        if not recovery:
            if self.marker.exists():
                raise ValueError('A previous release still has the website paused; recover it before starting another')
            if record['phase'] != 'preview' or record['actor'] != actor or record['expires_at'] < int(time.time()):
                raise ValueError('Approval expired, changed operator or was already used; prepare a fresh preview')
            current = self.worker(self.stage, 'hashes', {'files': record.get('selection', [row['file'] for row in record['source_hashes']])})
            if current != record['source_hashes']:
                raise ValueError('Staging files changed after the preview; prepare a fresh preview')
            if record.get('target_fingerprint'):
                target = self.worker(self.live, 'target_hashes', {'files': [row['file'] for row in record['source_hashes']]})
                if self.fingerprint(target) != record['target_fingerprint']:
                    raise ValueError('Website code changed after the preview; prepare a fresh preview')
            if not self.observe():
                raise ValueError('The current uncached website check failed; no code was changed')
        elif record['phase'] not in ('applying', 'completed', 'recovery-needs-review', 'rolled-back'):
            raise ValueError('This release has no write intent to recover')
        record['phase'] = 'applying' if not recovery else 'recovery-needs-review'
        self.save(record)
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_private(state / 'receipt.json', json.dumps({'phase': 'deployment-switch', 'token': token}))
        write_private(self.marker, 'maintenance\n', 0o644)
        safe_resume = False
        try:
            drain(self.live.user, self.live.host, self.live.php_version)
            result = self.worker(self.live, 'recover' if recovery else 'apply',
                                 {'token': token, 'plan': record['plan'], 'php': self.live.php_version}, check=True)
            record['phase'] = result['status']
            safe_resume = result['status'] == 'completed' or (
                result['status'] in ('rolled-back', 'no-write-intent') and result.get('restored_check_passed') is True)
            if result['status'] == 'rejected-php-syntax':
                safe_resume = self.observe()
            if not safe_resume:
                record['phase'] = 'recovery-needs-review'
            self.save(record)
            write_private(state / 'receipt.json', json.dumps({'phase': 'completed' if safe_resume else 'recovery-needs-review',
                          'result': record['phase'], 'token': token}))
            if not safe_resume:
                raise ValueError('Release recovery requires review; the website remains paused')
        except Exception:
            if not safe_resume:
                try:
                    inspection = self.worker(self.live, 'inspect', {'token': token})
                    if inspection is None or inspection['status'] == 'rejected-php-syntax':
                        safe_resume = self.observe()
                        if safe_resume:
                            record['phase'] = 'not-applied'
                            self.save(record)
                            write_private(state / 'receipt.json', json.dumps({'phase': 'completed', 'result': 'not-applied', 'token': token}))
                except Exception:
                    pass
            raise
        finally:
            if safe_resume:
                self.marker.unlink(missing_ok=True)


def recover_interrupted(registry_path, site_id, state, token, actor):
    release = Releases(registry_path, site_id)
    record = release.load(token)
    inspection = release.worker(release.live, 'inspect', {'token': token})
    if record['phase'] in ('not-applied', 'rejected-php-syntax') and (inspection is None or inspection['status'] == 'rejected-php-syntax'):
        if release.observe():
            release.marker.unlink(missing_ok=True)
            write_private(state / 'receipt.json', json.dumps({'phase': 'completed', 'result': 'not-applied', 'token': token}))
            return
    if record['phase'] == 'completed' and inspection and inspection['status'] == 'completed':
        current = release.worker(release.live, 'hashes', {'files': [row['file'] for row in record['plan']['changes']]})
        expected = [{'file': row['file'], 'sha256': row['staging_sha256']} for row in record['plan']['changes']]
        if current == expected:
            release.invalidate()
            time.sleep(3)
            if release.observe():
                release.marker.unlink(missing_ok=True)
                write_private(state / 'receipt.json', json.dumps({'phase': 'completed', 'result': 'completed', 'token': token}))
                return
    release.execute(token, actor, state, recovery=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--site', required=True)
    parser.add_argument('--token', required=True)
    parser.add_argument('--actor', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--recover', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Registered release coordinator requires root')
    registry = private_json(args.registry)
    spec = private_json(Path(registry['sites'][args.site]['specification']))
    user = spec['target']['user']
    lock_path = Path('/var/lib/cloudpanel-companion-jobs/locks') / (user + '.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        Releases(args.registry, args.site).execute(args.token, args.actor, args.state, args.recover)
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
