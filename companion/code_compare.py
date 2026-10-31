"""Bounded non-root code inventories; only names, hashes and sizes leave a site.

Comparison never executes website code or follows filesystem links. Unsupported
or private artifacts are reported as exclusions, not silently called identical.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from .promotion import selected_file

MAX_FILES = 50000
MAX_BYTES = 2 * 1024 * 1024 * 1024
MANAGED = {'cache-manager-for-cloudpanel', 'redis-cache'}


def folder_label(folder, kind):
    candidates = [folder / 'style.css'] if kind == 'themes' else [folder / (folder.name + '.php'), *sorted(folder.glob('*.php'))[:10]]
    field = 'Theme' if kind == 'themes' else 'Plugin'
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as stream:
            header = stream.read(8192).decode(errors='replace')
        match = re.search(r'(?im)^\s*(?:/\*+|\*|//|#)?\s*' + field + r' Name:\s*([^\r\n]+)', header)
        if match:
            return match.group(1).strip().removesuffix('*/').strip()[:120]
    return folder.name


def inventory(root):
    root = Path(root)
    if root.resolve() != root or root.is_symlink():
        raise ValueError('Code inventory requires a resolved registered root')
    folders, total_files, total_bytes = {}, 0, 0
    started = time.monotonic()
    for kind in ('themes', 'plugins'):
        base = root / 'wp-content' / kind
        if base.is_symlink() or not base.is_dir():
            raise ValueError('A registered theme/plugin directory is unavailable')
        for folder in sorted(base.iterdir()):
            if time.monotonic() - started > 80 or len(folders) >= 512:
                raise ValueError('Code check reached its folder/time limit; no complete result was saved')
            if folder.name.startswith('.') or folder.name in MANAGED:
                continue
            if not folder.is_dir() and not folder.is_symlink():
                continue
            relative_folder = folder.relative_to(root).as_posix()
            record = {'name': folder.name, 'label': folder.name if folder.is_symlink() else folder_label(folder, kind), 'kind': kind, 'files': {}, 'excluded': []}
            folders[relative_folder] = record
            if folder.is_symlink():
                record['excluded'].append({'file': relative_folder, 'reason': 'Symbolic link'})
                continue
            for directory, names, leaves in os.walk(folder, followlinks=False):
                if time.monotonic() - started > 80:
                    raise ValueError('Code check reached its time limit; no complete result was saved')
                for name in list(names):
                    path = Path(directory) / name
                    relative = path.relative_to(root).as_posix()
                    if name.startswith('.') or path.is_symlink():
                        record['excluded'].append({'file': relative, 'reason': 'Private directory or symbolic link'})
                        names.remove(name)
                for name in leaves:
                    path = Path(directory) / name
                    relative = path.relative_to(root).as_posix()
                    total_files += 1
                    if total_files > MAX_FILES:
                        raise ValueError('Code check exceeds 50000 files; no complete result was saved')
                    try:
                        selected_file(root, relative)
                    except ValueError:
                        record['excluded'].append({'file': relative, 'reason': 'Private/configuration artifact'})
                        continue
                    try:
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(fd, 'rb') as stream:
                            before = os.fstat(stream.fileno())
                            if not stat.S_ISREG(before.st_mode):
                                record['excluded'].append({'file': relative, 'reason': 'Not a regular file'})
                                continue
                            total_bytes += before.st_size
                            if total_bytes > MAX_BYTES:
                                raise ValueError('Code check exceeds 2 GB; no complete result was saved')
                            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                            after = os.fstat(stream.fileno())
                            if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                                    after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                                raise ValueError('A code file changed during checking; check again')
                        record['files'][relative] = {'sha256': digest, 'bytes': before.st_size}
                    except (FileNotFoundError, PermissionError):
                        raise ValueError('A code file disappeared or could not be read; check again')
    return {'folders': folders, 'file_count': total_files, 'bytes_read': total_bytes}


def differences(website, staging):
    folders, details = [], {}
    for path in sorted(set(website['folders']) | set(staging['folders'])):
        live = website['folders'].get(path, {'files': {}, 'excluded': []})
        stage = staging['folders'].get(path, {'files': {}, 'excluded': []})
        info = staging['folders'].get(path) or website['folders'][path]
        rows, unchanged = [], 0
        for file in sorted(set(live['files']) | set(stage['files'])):
            before, after = live['files'].get(file), stage['files'].get(file)
            if before == after:
                unchanged += 1
                continue
            status = 'website-only' if after is None else 'added' if before is None else 'modified'
            rows.append({'file': file, 'status': status, 'bytes': (after or before)['bytes'],
                         'releasable': after is not None and after['bytes'] <= 8 * 1024 * 1024 and len(file) <= 300})
        identity = hashlib.sha256(path.encode()).hexdigest()
        excluded = [{'side': side, **item} for side, record in [('website', live), ('staging', stage)] for item in record['excluded']]
        files = list(stage['files'])
        changes = [row for row in rows if row['status'] != 'website-only']
        folders.append({'id': identity, 'path': path, 'name': info['name'], 'label': info.get('label', info['name']), 'kind': info['kind'],
                        'changed': sum(row['status'] != 'website-only' for row in rows),
                        'website_only': sum(row['status'] == 'website-only' for row in rows),
                        'unchanged': unchanged, 'excluded': len(excluded), 'staging_files': len(files),
                        'whole_folder': bool(changes) and not excluded and len(changes) <= 5000 and
                                        sum(row['bytes'] for row in changes) <= 32 * 1024 * 1024 and
                                        all(row['releasable'] for row in changes) and
                                        all(item['bytes'] <= 128 * 1024 * 1024 and len(file) <= 300 for file, item in stage['files'].items())})
        details[identity] = {'rows': rows, 'excluded': excluded}
    return folders, details


def main():
    if os.geteuid() == 0:
        raise ValueError('Code inventory must run as the corresponding website owner')
    request = json.loads(sys.stdin.buffer.readline(4096))
    root = Path(request['root'])
    if root.stat().st_uid != os.geteuid():
        raise ValueError('Code inventory root belongs to another identity')
    print(json.dumps(inventory(root)))


if __name__ == '__main__':
    main()
