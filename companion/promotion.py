"""Preview explicitly selected code files. This module never writes to a site.

Database merging and media-to-content relationships are separate operations.
They cannot safely be represented by a generic copy-staging-to-live switch.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat


def digest(path: Path):
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError('Selection is not a regular file')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def selected_file(root: Path, relative: str, folder=False) -> Path:
    part = PurePosixPath(relative)
    if (not relative or '\\' in relative or part.is_absolute() or
            any(piece in ('', '.', '..') for piece in relative.split('/'))):
        raise ValueError('Select a relative code file')
    pieces = part.parts
    if len(pieces) < (3 if folder else 4) or pieces[0] != 'wp-content' or pieces[1] not in ('themes', 'plugins'):
        raise ValueError('Only explicitly selected theme/plugin files are supported initially')
    if any(piece.startswith('.') for piece in pieces) or part.suffix.lower() in ('.sql', '.env', '.log', '.pem', '.key'):
        raise ValueError('Private/configuration artifacts cannot be promoted')
    if root.is_symlink() or root.resolve() != root:
        raise ValueError('Site root must be an explicit resolved directory')
    current = root
    for piece in pieces:
        current = current / piece
        if current.is_symlink():
            raise ValueError('Symlink selections require a separate reviewed deployment strategy')
    if not current.resolve().is_relative_to(root):
        raise ValueError('Selection leaves the site root')
    return current


def expand_selection(root: Path, selections: list[str], max_files=5000) -> list[str]:
    """Freeze explicit folders into files without following links or hiding omissions.

    A whole folder remains a reviewed copy, not a destination mirror: files found
    only on the destination are retained. Private artifacts reject the selection
    rather than silently producing an incomplete plugin or theme release.
    """
    if (not isinstance(selections, list) or not 1 <= len(selections) <= 5000 or
            any(not isinstance(value, str) or len(value) > 300 for value in selections)):
        raise ValueError('Choose code files or folders, up to 5000 paths')
    files = set()
    for selection in selections:
        relative = selection[:-1] if selection.endswith('/') else selection
        path = selected_file(root, relative, folder=True)
        if path.is_dir():
            found = False
            for directory, names, leaves in os.walk(path, followlinks=False):
                for name in names + leaves:
                    entry = Path(directory) / name
                    child = entry.relative_to(root).as_posix()
                    selected_file(root, child, folder=True)
                    if entry.is_symlink() or not (entry.is_dir() or stat.S_ISREG(entry.lstat().st_mode)):
                        raise ValueError('Folders containing links or special files cannot be released')
                for name in leaves:
                    files.add((Path(directory) / name).relative_to(root).as_posix())
                    found = True
                    if len(files) > max_files:
                        raise ValueError('Folder selection exceeds its bounded file limit')
            if not found:
                raise ValueError('An empty folder has no releasable files')
        else:
            selected_file(root, relative)
            if not path.is_file():
                raise ValueError('A selected code file or folder is missing')
            files.add(relative)
    if not files or len(files) > max_files:
        raise ValueError('Select a bounded group of distinct code files')
    return sorted(files)


def folder_choices(root: Path) -> list[dict]:
    """List only safe top-level theme/plugin folders for the operator's picker."""
    choices = []
    for kind in ('themes', 'plugins'):
        base = root / 'wp-content' / kind
        if base.is_symlink() or not base.is_dir():
            raise ValueError('The registered code directory is unavailable')
        for path in base.iterdir():
            if path.name.startswith('.') or path.is_symlink() or not path.is_dir():
                continue
            if kind == 'plugins' and path.name in ('cache-manager-for-cloudpanel', 'redis-cache'):
                continue
            relative = path.relative_to(root).as_posix()
            selected_file(root, relative, folder=True)
            choices.append({'path': relative, 'name': path.name, 'kind': kind})
            if len(choices) > 5000:
                raise ValueError('Too many code folders to list safely')
    return sorted(choices, key=lambda row: (row['kind'], row['name']))


def preview(staging_root: Path, live_root: Path, files: list[str]) -> dict:
    if staging_root == live_root or staging_root.is_relative_to(live_root) or live_root.is_relative_to(staging_root):
        raise ValueError('Source and target must be separate site roots')
    if not files or len(files) > 5000 or len(set(files)) != len(files):
        raise ValueError('Select 1–5000 distinct files')
    changes = []
    for relative in sorted(files):
        source = selected_file(staging_root, relative)
        target = selected_file(live_root, relative)
        source_hash, target_hash = digest(source), digest(target)
        if source_hash is None:
            raise ValueError('Missing staging files are not interpreted as deletion requests')
        changes.append({'file': relative, 'action': 'unchanged' if source_hash == target_hash else
                        ('add' if target_hash is None else 'replace'),
                        'staging_sha256': source_hash, 'live_sha256': target_hash})
    # Bind approval to both site roots, even when another site has identical
    # files. Matching content alone must never authorize a different target.
    return {'version': 1, 'source_root': str(staging_root), 'target_root': str(live_root),
            'scope': 'selected-code-files', 'database': 'excluded',
            'uploads': 'excluded', 'deletions': 'excluded', 'changes': changes}


def verify_preview(staging_root: Path, live_root: Path, approved: dict):
    current = preview(staging_root, live_root, [row['file'] for row in approved['changes']])
    if current != approved:
        raise ValueError('The source or target changed after the preview. Review a fresh plan.')
    # This is a preflight, not a write transaction. An eventual executor must
    # establish its deployment lock, recovery snapshot and quiescent file writes.
