"""Atomic directory exchange: staging generations and the installed runtime package."""
import argparse
import ctypes
import os
from pathlib import Path
import pwd
import re

RENAME_EXCHANGE = 2
AT_FDCWD = -100


def rename_exchange(left: Path, right: Path):
    """Swap two directories in one step, so no reader ever finds either path missing."""
    operation = ctypes.CDLL(None, use_errno=True).renameat2
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    if operation(AT_FDCWD, os.fsencode(left), AT_FDCWD, os.fsencode(right), RENAME_EXCHANGE) != 0:
        raise OSError(ctypes.get_errno(), 'Atomic directory exchange failed')
    for directory in dict.fromkeys((left.parent, right.parent)):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def exchange(user, host, generation):
    """Exchange an isolated staging generation with its webroot as the site user."""
    if os.geteuid() == 0 or pwd.getpwuid(os.geteuid()).pw_name != user:
        raise ValueError('Exchange must run as the staging identity')
    if not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', user) or not re.fullmatch(r'[a-z0-9.-]{1,253}', host):
        raise ValueError('Invalid staging identity')
    root = Path('/home') / user / 'htdocs' / host
    parent = Path('/home') / user / '.companion-generations'
    if generation.parent != parent or not re.fullmatch(r'\.companion-clone-[a-f0-9]{24}', generation.name):
        raise ValueError('Unregistered generation path')
    for path in (root, generation):
        if path.resolve() != path or not path.is_dir() or path.stat().st_uid != os.geteuid():
            raise ValueError('Both generation roots must belong to this staging identity')
    rename_exchange(root, generation)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--generation', type=Path, required=True)
    args = parser.parse_args()
    exchange(args.user, args.host, args.generation)
