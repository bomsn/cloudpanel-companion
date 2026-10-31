"""Launch fixed registered workflows; web requests never supply command paths."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from .monitor import private_json


class RegisteredJobs:
    def __init__(self, registry, registry_path):
        from .operations import write_private
        self.registry, self.registry_path = registry, registry_path
        self.directory = Path('/var/lib/cloudpanel-companion-operations/jobs')
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.processes = {}
        # systemd stops the service's complete cgroup before restarting it. A
        # saved unfinished job is consequently an interruption, not a live PID
        # to trust or kill after possible PID reuse.
        for site_id in registry['sites']:
            path = self.directory / (site_id + '.json')
            if not path.exists():
                continue
            metadata = private_json(path)
            if metadata.get('returncode') is not None:
                continue
            try:
                state = Path(metadata['state'])
                if metadata.get('operation') == 'compare':
                    metadata.update(returncode=-1, interrupted=True)
                    write_private(path, json.dumps(metadata))
                    continue
                if (state / 'receipt.json').exists():
                    receipt = private_json(state / 'receipt.json')
                    if metadata.get('operation') == 'deploy':
                        from .registered_deployment import recover_interrupted
                        recover_interrupted(registry_path, site_id, state, metadata['token'], metadata['actor'])
                        metadata.update(returncode=0, interrupted=True)
                        write_private(path, json.dumps(metadata))
                        continue
                    if receipt.get('phase') == 'completed':
                        metadata['returncode'] = 0
                        write_private(path, json.dumps(metadata))
                        continue
                    from .refresh import recover_interrupted
                    recover_interrupted(registry_path, site_id, state)
                metadata.update(returncode=-1, interrupted=True)
            except Exception:
                metadata.update(returncode=-1, interrupted=True, blocked=True)
            write_private(path, json.dumps(metadata))

    def status(self, site_id):
        from .operations import write_private
        path = self.directory / (site_id + '.json')
        if not path.exists():
            return None
        metadata = private_json(path)
        process = self.processes.get(site_id)
        running = process is not None and process.poll() is None
        if process is not None and not running and metadata.get('returncode') is None:
            metadata['returncode'] = process.returncode
            write_private(path, json.dumps(metadata))
        receipt_path = Path(metadata['state']) / 'receipt.json'
        receipt = private_json(receipt_path) if receipt_path.exists() else {}
        phase = receipt.get('phase', 'queued')
        return {'operation': metadata['operation'], 'phase': phase, 'running': running,
                'failed': metadata.get('returncode') not in (None, 0),
                'blocked': metadata.get('blocked', False) or phase == 'recovery-needs-review', 'started_at': metadata['started_at'],
                'result': receipt.get('result'), 'token': metadata.get('token')}

    def deploy(self, site_id, actor, token, recovery=False):
        from .operations import write_private
        from .registered_deployment import Releases
        existing = self.status(site_id)
        if existing and (existing['running'] or (existing['blocked'] and not recovery)):
            raise ValueError('A workflow is running or requires operator recovery')
        if existing and existing['blocked'] and recovery:
            metadata = private_json(self.directory / (site_id + '.json'))
            if metadata.get('operation') != 'deploy' or metadata.get('token') != token:
                raise ValueError('Recover the blocked release before starting another workflow')
        for other in self.registry['sites']:
            if other != site_id and (self.status(other) or {}).get('running'):
                raise ValueError('Another workflow is already running on this server')
        release = Releases(self.registry_path, site_id).load(token)
        if not recovery and (release['actor'] != actor or release['phase'] != 'preview' or release['expires_at'] < int(time.time())):
            raise ValueError('Prepare a fresh preview before applying these files')
        if recovery and release['phase'] not in ('completed', 'applying', 'rolled-back', 'recovery-needs-review'):
            raise ValueError('This release has no deployment to recover')
        from .registered_compare import Comparison
        Comparison(self.registry_path, site_id).invalidate()
        parent = Path('/var/lib/cloudpanel-companion-jobs/gui-deploy') / site_id
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        state = parent / (str(time.time_ns()) + '-' + secrets.token_hex(8))
        metadata = {'operation': 'deploy', 'state': str(state), 'token': token, 'actor': actor,
                    'started_at': int(time.time()), 'returncode': None}
        path = self.directory / (site_id + '.json')
        write_private(path, json.dumps(metadata))
        fd = os.open(parent / (state.name + '.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            arguments = ['/usr/bin/python3', '-m', 'companion.registered_deployment', '--registry', str(self.registry_path),
                         '--site', site_id, '--token', token, '--actor', actor, '--state', str(state)]
            if recovery:
                arguments.append('--recover')
            process = subprocess.Popen(arguments, cwd='/opt/cloudpanel-companion', stdout=fd, stderr=fd,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
        except Exception:
            metadata['returncode'] = -1
            write_private(path, json.dumps(metadata))
            raise
        finally:
            os.close(fd)
        self.processes[site_id] = process
        return {'started': True}

    def refresh(self, site_id, actor, confirmed):
        from .operations import write_private
        if confirmed is not True:
            raise ValueError('Explicit staging refresh confirmation required')
        existing = self.status(site_id)
        if existing and (existing['running'] or existing['blocked']):
            raise ValueError('A registered job is running or requires recovery')
        for other in self.registry['sites']:
            if other != site_id:
                status = self.status(other)
                if status and status['running']:
                    raise ValueError('Another workflow is already running on this server')
        site = self.registry['sites'][site_id]
        specification = Path(site['specification'])
        spec = private_json(specification)
        if spec['target']['host'] != site['host'] or spec['target']['user'] != site['user'] or spec['source']['host'] != site['source_host']:
            raise ValueError('Staging specification does not match the registered site')
        from .registered_compare import Comparison
        Comparison(self.registry_path, site_id).invalidate()
        parent = Path('/var/lib/cloudpanel-companion-jobs/gui') / site_id
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        state = parent / (str(time.time_ns()) + '-' + secrets.token_hex(8))
        metadata = {'operation': 'refresh', 'state': str(state), 'actor': actor,
                    'started_at': int(time.time()), 'returncode': None}
        path = self.directory / (site_id + '.json')
        write_private(path, json.dumps(metadata))
        log = parent / (state.name + '.log')
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            process = subprocess.Popen(['/usr/bin/python3', '-m', 'companion.refresh',
                '--specification', str(specification), '--registry', str(self.registry_path),
                '--site', site_id, '--state', str(state), '--confirm-staging-refresh'],
                cwd='/opt/cloudpanel-companion', stdout=fd, stderr=fd,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C.UTF-8'})
        except Exception:
            metadata['returncode'] = -1
            write_private(path, json.dumps(metadata))
            raise
        finally:
            os.close(fd)
        self.processes[site_id] = process
        return {'started': True}

    def compare(self, site_id, actor):
        from .operations import write_private
        from .registered_compare import Comparison
        for other in self.registry['sites']:
            status = self.status(other)
            if status and (status['running'] or status['blocked']):
                raise ValueError('Finish the current website workflow before checking code changes')
        comparison = Comparison(self.registry_path, site_id)
        state = comparison.parent / (str(time.time_ns()) + '-' + secrets.token_hex(8))
        metadata = {'operation': 'compare', 'state': str(state), 'actor': actor,
                    'started_at': int(time.time()), 'returncode': None}
        path = self.directory / (site_id + '.json')
        write_private(path, json.dumps(metadata))
        fd = os.open(comparison.parent / (state.name + '.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            process = subprocess.Popen(['/usr/bin/python3', '-m', 'companion.registered_compare', '--registry', str(self.registry_path),
                                        '--site', site_id, '--state', str(state)], cwd='/opt/cloudpanel-companion', stdout=fd, stderr=fd,
                                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
        except Exception:
            metadata['returncode'] = -1
            write_private(path, json.dumps(metadata))
            raise
        finally:
            os.close(fd)
        self.processes[site_id] = process
        return {'started': True}
