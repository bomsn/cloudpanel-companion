"""Non-root selected-file transport and release executor.

The privileged coordinator supplies registered paths through stdin. File reads,
writes, PHP and WordPress always run as the corresponding website owner.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import stat
from .deployment import apply, read_file, recover
from .promotion import preview, selected_file, expand_selection, folder_choices

LIMIT = 32 * 1024 * 1024


def validate_selection(files, limit=5000):
    if not isinstance(files, list) or not 1 <= len(files) <= limit or len(set(files)) != len(files):
        raise ValueError('Select a bounded group of distinct code files')
    for relative in files:
        if not isinstance(relative, str) or len(relative) > 300:
            raise ValueError('Invalid code selection')
        if relative.startswith(('wp-content/plugins/cache-manager-for-cloudpanel/', 'wp-content/plugins/redis-cache/')):
            raise ValueError('Cache infrastructure uses its own update procedure')


def source_files(root, files, content=True):
    files = expand_selection(root, files, max_files=5000 if content else 50000)
    validate_selection(files, limit=5000 if content else 50000)
    result, total = [], 0
    for relative in files:
        if not content:
            result.append({'file': relative, 'sha256': file_hash(root, relative)})
            continue
        data = read_file(selected_file(root, relative))
        if data is None:
            raise ValueError('A selected source file is missing')
        total += len(data)
        if len(data) > 8 * 1024 * 1024 or total > LIMIT:
            raise ValueError('Selection exceeds the 8 MB/file or 32 MB/release limit')
        row = {'file': relative, 'sha256': hashlib.sha256(data).hexdigest()}
        if content:
            row['content'] = base64.b64encode(data).decode()
        result.append(row)
    return result


def file_hash(root, relative, missing=False):
    path = selected_file(root, relative)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing:
            return None
        raise ValueError('A selected code file is missing')
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 128 * 1024 * 1024:
            raise ValueError('A code fingerprint requires a bounded regular file')
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('A code file changed while preparing the preview')
        return value


def local_paths(request):
    home = Path.home().resolve()
    token = request['token']
    if not re.fullmatch(r'[a-f0-9]{32}', token):
        raise ValueError('Invalid release identity')
    directory = home / '.companion-deployment'
    if directory.is_symlink():
        raise ValueError('Release storage cannot be a link')
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.stat().st_uid != os.geteuid() or directory.stat().st_mode & 0o077:
        raise ValueError('Release storage must be private and owner-controlled')
    release = directory / token
    return release, release / 'source', release / 'recovery'


def check_request():
    # The site UID cannot reach the lab network directly. The coordinator makes
    # the real uncached HTTP observation and returns only its boolean result.
    print(json.dumps({'check': True}), flush=True)
    reply = sys.stdin.readline(256)
    return json.loads(reply) == {'healthy': True}


def main():
    if os.geteuid() == 0:
        raise ValueError('Website transfer/execution must not run as root')
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['read', 'hashes', 'target_hashes', 'choices', 'prepare', 'apply', 'recover', 'inspect', 'cleanup'])
    args = parser.parse_args()
    raw = sys.stdin.buffer.readline(48 * 1024 * 1024 + 1)
    if not raw.endswith(b'\n') or len(raw) > 48 * 1024 * 1024:
        raise ValueError('Invalid release payload size')
    request = json.loads(raw)
    root = Path(request['root'])
    if root.resolve() != root or root.is_symlink() or root.stat().st_uid != os.geteuid():
        raise ValueError('Registered site root must belong to executing owner')
    if args.operation == 'choices':
        print(json.dumps(folder_choices(root)))
        return
    if args.operation == 'target_hashes':
        validate_selection(request['files'], limit=50000)
        print(json.dumps([{'file': relative, 'sha256': file_hash(root, relative, missing=True)} for relative in request['files']]))
        return
    if args.operation in ('read', 'hashes'):
        print(json.dumps(source_files(root, request['files'], args.operation == 'read')))
        return
    release, source, state = local_paths(request)
    if args.operation == 'prepare':
        release.mkdir(mode=0o700)
        source.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        rows = request['rows']
        validate_selection([row['file'] for row in rows])
        total = 0
        for row in rows:
            data = base64.b64decode(row['content'], validate=True)
            total += len(data)
            if len(data) > 8 * 1024 * 1024 or total > LIMIT or hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('Release snapshot is invalid or too large')
            path = selected_file(source, row['file'])
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with path.open('xb') as output:
                output.write(data)
            path.chmod(0o600)
        print(json.dumps(preview(source, root, [row['file'] for row in rows])))
        return
    if args.operation == 'cleanup' and not release.exists() and not release.is_symlink():
        print(json.dumps({'removed': True}))
        return
    if release.is_symlink() or release.resolve() != release or release.stat().st_uid != os.geteuid():
        raise ValueError('Invalid owned release snapshot')
    transactions = sorted(path for path in state.iterdir() if path.is_dir() and re.fullmatch(r'[0-9]{10,30}-[a-f0-9]{16}', path.name))
    if len(transactions) > 1:
        raise ValueError('Ambiguous recovery state')
    if args.operation == 'inspect':
        print(json.dumps(json.loads(read_file(transactions[0] / 'receipt.json')) if transactions else None))
        return
    if args.operation == 'cleanup':
        import shutil
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('Descriptor-based directory removal is required')
        shutil.rmtree(release)
        print(json.dumps({'removed': True}))
        return
    if args.operation == 'recover':
        if not transactions:
            print(json.dumps({'status': 'no-write-intent', 'restored_check_passed': check_request()}))
        else:
            print(json.dumps(recover(root, state, transactions[0].name, check_request)))
        return
    if transactions:
        raise ValueError('This snapshot already has a deployment transaction')
    try:
        receipt = apply(source, root, request['plan'], state, '/usr/bin/php' + request['php'], check_request)
    except Exception:
        transactions = [path for path in state.iterdir() if path.is_dir() and (path / 'receipt.json').is_file()]
        if len(transactions) == 1:
            print(json.dumps(json.loads(read_file(transactions[0] / 'receipt.json'))))
            return
        raise
    print(json.dumps(json.loads(read_file(receipt))))


if __name__ == '__main__':
    main()
