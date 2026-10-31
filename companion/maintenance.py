"""Keep application upgrades and registered workflows mutually exclusive.

An asynchronous job outlives its initiating request. Installation takes the
exclusive admissions lock before checking durable job state, so no new job can
start between that check and replacing its executing Python code.
"""
import contextlib
import fcntl
import os
from pathlib import Path
import stat
from .monitor import private_json

LOCK = Path('/run/cloudpanel-companion-update.lock')


@contextlib.contextmanager
def admissions(exclusive=False, path=LOCK):
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('The update lock must be a private operator-owned file')
        try:
            fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Server tools are being updated. Try again shortly.')
        yield
    finally:
        os.close(descriptor)


def require_idle(directory=Path('/var/lib/cloudpanel-companion-operations/jobs')):
    if directory.is_symlink():
        raise ValueError('Registered job storage must not be a link')
    for path in directory.glob('*.json'):
        record = private_json(path)
        if record.get('returncode') is None or record.get('blocked'):
            raise ValueError('Finish or recover the current workflow before upgrading the server tools')
        receipt_path = Path(record['state']) / 'receipt.json'
        if receipt_path.exists():
            receipt = private_json(receipt_path)
            if receipt.get('phase') == 'recovery-needs-review' or receipt.get('result') == 'recovery-needs-review':
                raise ValueError('Resolve the pending recovery before upgrading the server tools')


@contextlib.contextmanager
def component_install(source):
    from .package_install import require_package
    with admissions(exclusive=True):
        require_idle()
        require_package(source)
        yield
