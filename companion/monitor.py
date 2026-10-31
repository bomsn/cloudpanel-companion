"""Single-run monitoring command; a systemd timer supplies the schedule."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from .health import Observation, Target, probe
from .incidents import IncidentStore


def private_json(path: Path, *, max_bytes: int = 65536):
    if type(max_bytes) is not int or not 1 <= max_bytes <= 32 * 1024 * 1024:
        raise ValueError('Explicit bounded private JSON size required')
    # O_NOFOLLOW prevents a replaced symlink from changing which secret is read.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r', encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        private_owned = info.st_uid == os.geteuid() and not info.st_mode & 0o077
        # systemd LoadCredential supplies a read-only, root-owned 0440 file in
        # a per-service mount. Accept that contract without loosening ordinary
        # configuration ownership or accepting a writable group-shared secret.
        credential_dir = os.environ.get('CREDENTIALS_DIRECTORY', '')
        systemd_credential = (
            credential_dir.startswith('/run/credentials/') and
            path.parent == Path(credential_dir) and path.resolve() == path and
            info.st_uid == 0 and not info.st_mode & 0o227 and
            bool(os.fstatvfs(stream.fileno()).f_flag & os.ST_RDONLY)
        )
        if not stat.S_ISREG(info.st_mode) or not (private_owned or systemd_credential):
            raise ValueError('Configuration must be a private regular file owned by the monitoring user')
        if info.st_size > max_bytes:
            raise ValueError('Configuration exceeds the supported size')
        return json.load(stream)


def bounded_probe(target: Target) -> Observation:
    """A child deadline bounds DNS and slow-header peers, not just socket waits."""
    environment = dict(os.environ)
    environment.pop('SSLKEYLOGFILE', None)
    started = time.monotonic()
    try:
        result = subprocess.run([sys.executable, '-m', 'companion.monitor', '--probe-worker'],
                                input=json.dumps(target.__dict__), capture_output=True, text=True,
                                timeout=target.timeout + 2, env=environment)
        if result.returncode == 0:
            return Observation(**json.loads(result.stdout))
    except subprocess.TimeoutExpired:
        return Observation(target.name, False, 'probe-deadline', None,
                           round((time.monotonic() - started) * 1000))
    except (OSError, ValueError, TypeError):
        pass
    return Observation(target.name, False, 'probe-unavailable', None,
                       round((time.monotonic() - started) * 1000))


def run(config_path: Path, state_dir: Path):
    import fcntl
    config = private_json(config_path)
    if set(config) - {'targets', 'failure_threshold'}:
        raise ValueError('Unknown monitor configuration field')
    if not isinstance(config.get('targets'), list) or not 1 <= len(config['targets']) <= 50:
        raise ValueError('Configure between 1 and 50 explicit targets')
    targets = [Target(**item) for item in config['targets']]
    for target in targets:
        target.validate()
    if len({target.name for target in targets}) != len(targets):
        raise ValueError('Target names must be unique')
    threshold = config.get('failure_threshold', 2)
    if not isinstance(threshold, int) or not 1 <= threshold <= 10:
        raise ValueError('Invalid failure threshold')
    # Operator/service manager creates this directory. Do not follow a supplied
    # symlink or silently repair permissions on an unrelated existing directory.
    info = state_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise ValueError('State directory must be private and owned by the monitoring user')
    os.umask(0o077)
    lock_fd = os.open(state_dir / 'monitor.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Previous monitor run is still active')
        database = state_dir / 'monitor.sqlite3'
        if database.is_symlink():
            raise ValueError('State database cannot be a symlink')
        store = IncidentStore(database)
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                observations = list(pool.map(bounded_probe, targets))
            for result in observations:
                store.observe(result, threshold=threshold)
            # Freshness is recorded only after all configured targets were observed.
            # An outside observer must check this; a dead server cannot alert itself.
            marker = state_dir / 'last-completed.json'
            temporary = state_dir / 'last-completed.new'
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump({'completed_at': int(time.time()), 'target_count': len(targets),
                           'target_names': [target.name for target in targets]}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, marker)
            return {'observations': [result.to_dict() for result in observations],
                    'pending_notifications': len(store.pending())}
        finally:
            store.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path)
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--probe-worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.probe_worker:
            print(json.dumps(probe(Target(**json.load(sys.stdin))).to_dict()))
        else:
            if args.config is None or args.state_dir is None:
                parser.error('--config and --state-dir are required')
            print(json.dumps(run(args.config, args.state_dir)))
    except (ValueError, TypeError, KeyError, OSError, RuntimeError):
        # Do not print raw exceptions containing paths, URLs or secret values.
        print('Monitoring run failed; check configuration, ownership and service logs.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
