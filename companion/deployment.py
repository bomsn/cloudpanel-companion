"""Deploy reviewed code as the target site identity, never as root.

An operator-owned job runner must supply the registered roots and private state
directory. Website requests must not call this module with arbitrary paths.
Selected files are replaced atomically; this is not a site-wide atomic release.
The caller must quiesce other code writers and handle page/object/OPcache purge.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import time

from .promotion import selected_file, verify_preview

LIMIT = 64 * 1024 * 1024


def save_record(transaction, record):
    temporary = transaction / 'receipt.new'
    temporary.write_text(json.dumps(record, indent=2))
    temporary.chmod(0o600)
    with temporary.open('rb') as stream:
        os.fsync(stream.fileno())
    os.replace(temporary, transaction / 'receipt.json')
    fd = os.open(transaction, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Deployment requires regular files')
        data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError('Deployment file exceeds size limit')
        return data


def replace(root, relative, data, expected):
    """Walk directory descriptors to prevent a substituted parent symlink."""
    selected_file(root, relative)
    parts = relative.split('/')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.companion-' + secrets.token_hex(16)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        except FileNotFoundError:
            current, mode = None, 0o644
        else:
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('Target is not a regular file')
                mode = stat.S_IMODE(info.st_mode) & 0o666
                current = stream.read(LIMIT + 1)
        if (sha(current) if current is not None else None) != expected:
            raise ValueError('Target changed; no overwrite was performed')
        if data is None:
            os.unlink(parts[-1], dir_fd=directory)
        else:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         mode, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, parts[-1], src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def prepare_parents(root, relative, created, save):
    """Record directory intent before creation so interrupted additions recover.

    Only empty directories created by this release may be removed on recovery;
    a later file or edit is never deleted to make the rollback look complete.
    """
    selected_file(root, relative)
    parts = relative.split('/')[:-1]
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(parts):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                if index < 2:
                    raise ValueError('The destination theme/plugin base must already exist')
                name = '/'.join(parts[:index + 1])
                created.append(name)
                save()
                try:
                    os.mkdir(part, mode=0o755, dir_fd=directory)
                except FileExistsError:
                    created.remove(name)
                    save()
                else:
                    os.fsync(directory)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                if name in created:
                    os.fchmod(child, 0o755)
                    os.fsync(child)
            os.close(directory)
            directory = child
    finally:
        os.close(directory)


def recover_directories(root, created):
    """Remove only attested empty code directories using no-follow descriptors."""
    for relative in reversed(created):
        selected_file(root, relative, folder=True)
        parts = relative.split('/')
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            try:
                os.rmdir(parts[-1], dir_fd=directory)
                os.fsync(directory)
            except OSError as error:
                import errno
                if error.errno not in (errno.ENOENT, errno.ENOTEMPTY, errno.EEXIST):
                    raise
        except FileNotFoundError:
            pass
        finally:
            os.close(directory)


def apply(staging_root, live_root, approved, state, php_binary, check):
    """Apply approved code and recover on error without overwriting newer edits.

    The post-write check must include the site's cache invalidation contract.
    Failed checks trigger recovery and another check of the restored version.
    A recovery conflict is retained for the operator rather than guessed away.
    """
    if os.geteuid() == 0:
        raise ValueError('Run deployment as the target site user, never root')
    for path in (live_root, state):
        info = path.lstat()
        if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError('Target and recovery directory must belong to the executing site user')
    if state.is_relative_to(live_root) or state.is_relative_to(staging_root) or state.stat().st_mode & 0o077:
        raise ValueError('Recovery state must be private and outside both webroots')
    binary = Path(php_binary)
    if not binary.is_absolute() or binary.stat().st_uid != 0 or binary.stat().st_mode & 0o022:
        raise ValueError('Use a root-owned PHP binary that website users cannot modify')
    lock = os.open(state / 'deployment.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verify_preview(staging_root, live_root, approved)
        changes, total = [], 0
        for row in approved['changes']:
            if row['action'] == 'unchanged':
                continue
            source = read_file(selected_file(staging_root, row['file']))
            before = read_file(selected_file(live_root, row['file']))
            if source is None or sha(source) != row['staging_sha256'] or (sha(before) if before is not None else None) != row['live_sha256']:
                raise ValueError('Files changed after review')
            total += len(source) + len(before or b'')
            if total > LIMIT:
                raise ValueError('Selected deployment exceeds size limit')
            changes.append((row, source, before))
        transaction = state / (str(time.time_ns()) + '-' + secrets.token_hex(8))
        transaction.mkdir(mode=0o700)
        state_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(state_fd)
        finally:
            os.close(state_fd)
        record = {'plan': approved, 'status': 'prepared', 'applied': [], 'created_directories': [], 'recovery_conflicts': []}

        def save():
            save_record(transaction, record)

        for index, (row, source, before) in enumerate(changes):
            if before is not None:
                recovery = transaction / f'{index}.before'
                recovery.write_bytes(before)
                recovery.chmod(0o600)
                with recovery.open('rb') as stream:
                    os.fsync(stream.fileno())
            if row['file'].lower().endswith('.php'):
                result = subprocess.run([str(binary), '-n', '-l'], input=source,
                                        capture_output=True, timeout=15)
                if result.returncode:
                    record['status'] = 'rejected-php-syntax'
                    save()
                    raise ValueError('Selected PHP failed syntax validation')
        save()
        try:
            for row, source, before in changes:
                # Write intent before replacement so a killed process leaves a
                # complete recovery manifest even between rename and receipt.
                record['status'] = 'applying'
                record['applied'].append(row['file'])
                save()
                prepare_parents(live_root, row['file'], record['created_directories'], save)
                replace(live_root, row['file'], source, row['live_sha256'])
            if check() is not True:
                raise ValueError('Post-deployment check failed')
            record['status'] = 'completed'
            save()
        except Exception:
            for row, source, before in reversed(changes):
                if row['file'] not in record['applied']:
                    continue
                try:
                    current = read_file(selected_file(live_root, row['file']))
                    if current == before:
                        continue
                    replace(live_root, row['file'], before, row['staging_sha256'])
                except (OSError, ValueError):
                    record['recovery_conflicts'].append(row['file'])
            try:
                recover_directories(live_root, record['created_directories'])
            except (OSError, ValueError):
                record['recovery_conflicts'].append('Created code directories require inspection')
            record['status'] = 'recovery-needs-review' if record['recovery_conflicts'] else 'rolled-back'
            try:
                record['restored_check_passed'] = check() is True
            except Exception:
                record['restored_check_passed'] = False
            save()
            raise
        return transaction / 'receipt.json'
    finally:
        os.close(lock)


def recover(live_root, state, transaction_id, check):
    """Recover a recorded write intent after interruption, preserving later edits."""
    import re
    if not re.fullmatch(r'[0-9]{10,30}-[a-f0-9]{16}', transaction_id):
        raise ValueError('Invalid transaction identity')
    if os.geteuid() == 0:
        raise ValueError('Run recovery as the target site user, never root')
    for path in (live_root, state):
        info = path.lstat()
        if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError('Recovery roots must belong to the executing site user')
    if state.is_relative_to(live_root) or state.stat().st_mode & 0o077:
        raise ValueError('Recovery state must be private and outside the webroot')
    lock = os.open(state / 'deployment.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        transaction = state / transaction_id
        if transaction.resolve() != transaction or transaction.stat().st_uid != os.geteuid():
            raise ValueError('Invalid recovery directory')
        raw = read_file(transaction / 'receipt.json')
        if raw is None or len(raw) > 4 * 1024 * 1024:
            raise ValueError('Invalid recovery receipt')
        record = json.loads(raw)
        if record['plan']['target_root'] != str(live_root):
            raise ValueError('Recovery receipt belongs to another site')
        if record['status'] not in ('applying', 'recovery-needs-review', 'completed', 'rolled-back'):
            raise ValueError('Transaction has no recorded write intent')
        changes = [row for row in record['plan']['changes'] if row['action'] != 'unchanged']
        backups = []
        # Validate every recovery artifact before changing any target file.
        for index, row in enumerate(changes):
            before = read_file(transaction / f'{index}.before')
            if (sha(before) if before is not None else None) != row['live_sha256']:
                raise ValueError('Recovery copy is missing or altered')
            selected_file(live_root, row['file'])
            backups.append((row, before))
        conflicts = []
        for row, before in reversed(backups):
            if row['file'] not in record['applied']:
                continue
            try:
                if read_file(selected_file(live_root, row['file'])) != before:
                    replace(live_root, row['file'], before, row['staging_sha256'])
            except (OSError, ValueError):
                conflicts.append(row['file'])
        record['recovery_conflicts'] = conflicts
        try:
            recover_directories(live_root, record.get('created_directories', []))
        except (OSError, ValueError):
            conflicts.append('Created code directories require inspection')
        record['status'] = 'recovery-needs-review' if conflicts else 'rolled-back'
        try:
            record['restored_check_passed'] = check() is True
        except Exception:
            record['restored_check_passed'] = False
        save_record(transaction, record)
        return record
    finally:
        os.close(lock)
