"""Replace the shared runtime once, with stopped consumers and rollback data.

Website PHP and Nginx remain running. Stopping the cache controller removes its
readiness marker, so public requests fall back to private uncached PHP. Operator
accounts are backed up only after the interface stops accepting writes.
"""
import compileall
import ctypes
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import time
from .operations import write_private
from .monitor import private_json

TIMERS = ('companion-monitor.timer', 'companion-delivery.timer', 'companion-system-watch.timer',
          'companion-system-delivery.timer', 'companion-retention.timer', 'companion-telemetry.timer')
CONSUMERS = ('companion-web.service', 'companion-operations.service', 'companion-system-watch.service',
             'companion-monitor.service', 'companion-delivery.service', 'companion-system-delivery.service',
             'cache-manager-control.service', 'companion-telemetry.service')
UPDATES = Path('/var/lib/cloudpanel-companion-updates')
SYSTEMD = Path('/etc/systemd/system')
MANAGED = tuple(map(Path, (
    '/etc/cloudpanel-companion/web.json', '/etc/cloudpanel-companion/companion-web-proxy.conf',
    '/etc/cloudpanel-companion/security-cache.conf', '/etc/systemd/system/companion-web.service',
    '/etc/systemd/system/companion-security-cache.service',
    '/etc/systemd/system/companion-monitor.service.d/web-export.conf',
    '/var/lib/cloudpanel-companion-web/static/staticfiles.json',
)))


def identity(path):
    if not path.exists():
        return None
    if path.is_symlink() or path.resolve() != path or path.stat().st_uid != 0:
        raise ValueError('Package directories must remain operator-owned and resolved')
    info = path.stat()
    return [info.st_dev, info.st_ino]


def restore_file(path, data, owner):
    if path.is_symlink():
        raise ValueError('A managed configuration changed into a link')
    if data is None:
        path.unlink(missing_ok=True)
        return
    temporary = path.with_name('.companion-restore-' + secrets.token_hex(12))
    with temporary.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chown(temporary, owner[0], owner[1])
    temporary.chmod(owner[2])
    temporary.replace(path)


def recover(directory, base=UPDATES):
    """Recover an interrupted package swap from its root-only write intent."""
    if directory.parent != base or directory.resolve() != directory or directory.is_symlink():
        raise ValueError('Choose an explicit package recovery record')
    record = private_json(directory / 'receipt.json')
    if record['phase'] in ('completed', 'rolled-back', 'prepared-failed'):
        raise ValueError('Only an interrupted update can be automatically recovered; completed installations require a new planned upgrade')
    if record.get('artifacts_pruned'):
        raise ValueError('This older update no longer retains rollback artifacts')
    destination, candidate = Path(record['installed_package']), Path(record['old_package'])
    import re
    if (not re.fullmatch(r'\.companion-package-[a-f0-9]{24}', candidate.name) or
            candidate.parent != destination.parent or directory.stat().st_uid != 0):
        raise ValueError('Invalid package recovery identity')
    services = record['services']
    stopped = record.get('stop_services', services)
    if any(unit not in TIMERS + CONSUMERS and not re.fullmatch(r'companion-relay@[a-z][a-z0-9-]{2,30}\.service', unit) for unit in set(services + stopped)):
        raise ValueError('Recovery contains an unregistered service')
    if stopped:
        subprocess.run(['systemctl', 'stop', *stopped], check=True, capture_output=True)
    current = identity(destination)
    if current == record['candidate_identity']:
        if record['old_identity'] is not None:
            if identity(candidate) != record['old_identity']:
                raise ValueError('The previous runtime identity changed; automatic recovery refused')
            exchange(destination, candidate)
        else:
            destination.rename(candidate)
    elif current != record['old_identity']:
        raise ValueError('Installed runtime changed after the interrupted update')
    for number, item in enumerate(record.get('files', [])):
        path = Path(item['path'])
        if item['owner'] is None:
            restore_file(path, None, None)
        else:
            restore_file(path, (directory / ('file-' + str(number))).read_bytes(), item['owner'])
    if record.get('database_owner'):
        accounts = Path(record['accounts'])
        for suffix in ('-wal', '-shm'):
            path = accounts.with_name(accounts.name + suffix)
            if path.is_symlink():
                raise ValueError('Operator database sidecar cannot be a link')
            path.unlink(missing_ok=True)
        restore_file(accounts, (directory / 'accounts.sqlite3').read_bytes(), record['database_owner'])
    if services or record.get('units'):
        subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
    failures = []
    for unit in sorted(services, key=lambda value: value.endswith('.timer')):
        if subprocess.run(['systemctl', 'start', unit], capture_output=True).returncode:
            failures.append(unit)
    record['phase'] = 'recovery-needs-review' if failures else 'rolled-back'
    write_private(directory / 'receipt.json', json.dumps(record))
    if failures:
        raise ValueError('Previous services require review: ' + ', '.join(failures))


def exchange(left, right):
    operation = ctypes.CDLL(None, use_errno=True).renameat2
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    if operation(-100, os.fsencode(left), -100, os.fsencode(right), 2):
        raise OSError(ctypes.get_errno(), 'Atomic package exchange failed')
    descriptor = os.open(left.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_package(source, destination=Path('/opt/cloudpanel-companion')):
    """Component installers cannot independently replace the shared runtime."""
    for package in ('companion', 'companion_web', 'assets'):
        for path in (source / package).rglob('*'):
            if path.is_symlink():
                raise ValueError('Release source must not contain links')
            if not path.is_file() or '__pycache__' in path.parts:
                continue
            installed = destination / path.relative_to(source)
            if not installed.is_file() or installed.is_symlink() or installed.read_bytes() != path.read_bytes():
                raise ValueError('Install this release with install-web.py before installing its components')


def installed_units(source, systemd=SYSTEMD):
    """Unit files of this package that a component installer has installed.

    Every component installer copies its units verbatim from assets/, so an update
    (`git pull` and `install.sh`) refreshes exactly the ones already present and
    never installs a component the operator has not chosen.
    """
    return [systemd / path.name for path in sorted((source / 'assets').iterdir())
            if path.suffix in ('.service', '.timer') and path.is_file() and not path.is_symlink()
            and (systemd / path.name).is_file()]


def prune_updates(base, keep=2):
    """Retain two completed rollback sets; never remove unresolved updates."""
    records = []
    for receipt in base.glob('*/receipt.json'):
        record = private_json(receipt)
        if record['phase'] in ('completed', 'rolled-back') and not record.get('artifacts_pruned'):
            records.append((receipt.parent, record))
    for directory, record in sorted(records, key=lambda item: item[0].name, reverse=True)[keep:]:
        old = Path(record['old_package'])
        expected = record['old_identity'] if record['phase'] == 'completed' else record['candidate_identity']
        import re
        if (old.parent != Path(record['installed_package']).parent or
                not re.fullmatch(r'\.companion-package-[a-f0-9]{24}', old.name)):
            raise ValueError('Invalid old package retention identity')
        if old.exists():
            if identity(old) != expected:
                raise ValueError('An older runtime changed identity; retention refused')
            shutil.rmtree(old)
        for item in directory.iterdir():
            if item.name == 'receipt.json':
                continue
            if item.is_symlink() or not item.is_file():
                raise ValueError('Unexpected artifact in update recovery storage')
            item.unlink()
        record['artifacts_pruned'] = True
        write_private(directory / 'receipt.json', json.dumps(record))


class PackageTransaction:
    def __init__(self, source, destination=Path('/opt/cloudpanel-companion'),
                 state=Path('/var/lib/cloudpanel-companion-updates'),
                 accounts=Path('/var/lib/cloudpanel-companion-web/accounts.sqlite3'), services=None, managed=MANAGED,
                 systemd=SYSTEMD):
        self.source, self.destination, self.accounts = source, destination, accounts
        self.systemd = systemd
        self.units = []
        self.state = state / (str(time.time_ns()) + '-' + secrets.token_hex(8))
        self.candidate = destination.parent / ('.companion-package-' + secrets.token_hex(12))
        self.services = services
        self.active = []
        self.switched = False
        self.preexisting = destination.exists()
        self.database_owner = None
        self.activate = []
        self.managed = managed
        self.files = []
        self.old_identity = None
        self.candidate_identity = None

    def receipt(self, phase):
        write_private(self.state / 'receipt.json', json.dumps({'phase': phase, 'old_package': str(self.candidate),
                      'installed_package': str(self.destination), 'services': self.active,
                      'stop_services': list(dict.fromkeys(self.active + self.activate)),
                      'old_identity': self.old_identity, 'candidate_identity': self.candidate_identity,
                      'accounts': str(self.accounts), 'database_owner': self.database_owner, 'files': self.files,
                      'units': [str(path) for path in self.units]}))

    def __enter__(self):
        if os.geteuid() != 0:
            raise ValueError('Package installation requires the server operator')
        for path in (self.source, self.destination, self.state.parent, self.accounts.parent):
            if path.resolve() != path or path.is_symlink():
                raise ValueError('Installation and private state must use resolved directories')
        self.state.parent.mkdir(mode=0o700, exist_ok=True)
        if self.state.parent.stat().st_uid != 0 or self.state.parent.stat().st_mode & 0o077:
            raise ValueError('Package recovery state must be private and operator owned')
        for previous in self.state.parent.glob('*/receipt.json'):
            if private_json(previous)['phase'] not in ('completed', 'rolled-back', 'prepared-failed'):
                raise ValueError('Recover the interrupted package update before trying another installation: ' + str(previous.parent))
        self.state.mkdir(mode=0o700)
        self.candidate.mkdir(mode=0o755)
        try:
            for package in ('companion', 'companion_web', 'assets'):
                for path in (self.source / package).rglob('*'):
                    if path.is_symlink():
                        raise ValueError('Release source must not contain links')
                shutil.copytree(self.source / package, self.candidate / package,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            # This policy is installed by the cache component, not generated by
            # the runtime package. Retain it while the component is upgraded.
            policy = self.destination / 'assets/cache-policy.vcl'
            if policy.is_file() and not policy.is_symlink():
                shutil.copyfile(policy, self.candidate / 'assets/cache-policy.vcl')
            if not compileall.compile_dir(str(self.candidate), quiet=2):
                raise ValueError('Release Python syntax validation failed before stopping services')
            self.old_identity, self.candidate_identity = identity(self.destination), identity(self.candidate)
            units = list(TIMERS + CONSUMERS)
            if self.services is not None:
                units = list(self.services)
            else:
                result = subprocess.run(['systemctl', 'list-units', '--all', '--plain', '--no-legend',
                                         'companion-relay@*.service'], capture_output=True, check=True)
                units += [line.split()[0] for line in result.stdout.decode().splitlines() if line.split()]
            self.active = []
            for unit in units:
                status = subprocess.run(['systemctl', 'show', unit, '--property=ActiveState', '--value'],
                                        capture_output=True, check=True).stdout.decode().strip()
                # Oneshoot jobs are "activating" while their process runs.
                # They must finish stopping before any shared code is exchanged.
                if status in ('active', 'activating', 'reloading'):
                    self.active.append(unit)
            # Installed units are refreshed from the new package and backed up like
            # the managed files, so a failed update restores them too.
            self.units = [path for path in installed_units(self.source, self.systemd) if path not in self.managed]
            self.receipt('prepared')
            if self.active:
                subprocess.run(['systemctl', 'stop', *self.active], check=True)
            for number, path in enumerate(tuple(self.managed) + tuple(self.units)):
                if path.is_symlink():
                    raise ValueError('Managed installation files must not be links')
                item = {'path': str(path), 'owner': None}
                if path.exists():
                    info = path.stat()
                    item['owner'] = [info.st_uid, info.st_gid, info.st_mode & 0o777]
                    backup = self.state / ('file-' + str(number))
                    backup.write_bytes(path.read_bytes())
                    backup.chmod(0o600)
                self.files.append(item)
            if self.accounts.exists():
                if self.accounts.is_symlink():
                    raise ValueError('Operator database cannot be a link')
                info = self.accounts.stat()
                self.database_owner = (info.st_uid, info.st_gid, info.st_mode & 0o777)
                with sqlite3.connect(self.accounts) as current, sqlite3.connect(self.state / 'accounts.sqlite3') as backup:
                    current.backup(backup)
                (self.state / 'accounts.sqlite3').chmod(0o600)
            self.receipt('switch-intent')
            if self.preexisting:
                exchange(self.destination, self.candidate)
            else:
                self.candidate.rename(self.destination)
            self.switched = True
            self.receipt('switched')
            changed = False
            for unit in self.units:
                content = (self.destination / 'assets' / unit.name).read_bytes()
                if unit.read_bytes() != content:
                    info = unit.stat()
                    restore_file(unit, content, (info.st_uid, info.st_gid, info.st_mode & 0o777))
                    changed = True
            if changed:
                subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
            return self
        except BaseException:
            self.__exit__(*__import__('sys').exc_info())
            raise

    def __exit__(self, kind, error, traceback):
        # A caller may have enabled new units during setup. Stop the interface
        # before restoring its account database on any failed activation.
        if kind is not None:
            if self.switched:
                self.receipt('recovery-needs-review')
                recover(self.state, self.state.parent)
            else:
                for unit in sorted(self.active, key=lambda value: value.endswith('.timer')):
                    subprocess.run(['systemctl', 'start', unit], check=True)
                if self.candidate.exists():
                    identity(self.candidate)
                    shutil.rmtree(self.candidate)
                self.receipt('prepared-failed')
            return False
        failures = []
        # Start long-lived services before timers, so observations do not race
        # deliberate maintenance. Service dependencies retain their native order.
        requested = self.active if kind else list(dict.fromkeys(self.active + self.activate))
        self.receipt('activation-intent')
        for unit in sorted(requested, key=lambda value: value.endswith('.timer')):
            if subprocess.run(['systemctl', 'start', unit], capture_output=True).returncode:
                failures.append(unit)
        self.receipt('recovery-needs-review' if failures else 'rolled-back' if kind else 'completed')
        if failures:
            subprocess.run(['systemctl', 'stop', *requested], capture_output=True)
            recover(self.state, self.state.parent)
            raise ValueError('Package services require operator review: ' + ', '.join(failures))
        prune_updates(self.state.parent)
        return False


if __name__ == '__main__':
    import argparse
    from .maintenance import admissions, require_idle
    parser = argparse.ArgumentParser(description='Restore the previous runtime after an interrupted package update.')
    parser.add_argument('--recover', type=Path, required=True)
    parser.add_argument('--confirm', action='store_true', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as the server operator')
    with admissions(exclusive=True):
        require_idle()
        recover(args.recover)
