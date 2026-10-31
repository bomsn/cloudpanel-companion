"""Export only monitoring observations, never credentials or delivery secrets."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import shutil


def host_resources():
    """Read OS counters without granting the web worker server access.

    Load is a task count, not CPU usage. Available memory includes reclaimable
    caches, so normal Linux caching is not described as memory exhaustion.
    """
    try:
        memory = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, value = line.split(':', 1)
            if key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'):
                memory[key] = int(value.split()[0]) * 1024
        disk = shutil.disk_usage('/')
        return {'cpus': os.cpu_count(), 'load': list(os.getloadavg()),
                'memory_total': memory['MemTotal'], 'memory_available': memory['MemAvailable'],
                'swap_used': memory['SwapTotal'] - memory['SwapFree'],
                'disk_total': disk.total, 'disk_free': disk.free}
    except (OSError, ValueError, KeyError):
        return None


def export(state: Path, destination: Path):
    marker = json.loads((state / 'last-completed.json').read_text())
    names = marker['target_names']
    if not isinstance(names, list) or not 1 <= len(names) <= 50 or len(set(names)) != len(names):
        raise ValueError('Invalid completed inventory')
    with sqlite3.connect(f'file:{state / "monitor.sqlite3"}?mode=ro', uri=True) as db:
        rows = db.execute('SELECT name,observation,observed_at FROM target_state WHERE name IN (' +
                          ','.join('?' for _ in names) + ') ORDER BY name', names).fetchall()
    if len(rows) != len(names) or any(row[2] < marker['completed_at'] - 60 for row in rows):
        raise ValueError('Incomplete observations')
    result = {'observed_at': marker['completed_at'], 'checks': [json.loads(row[1]) for row in rows],
              'resources': host_resources()}
    temporary = destination.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    os.fchmod(fd, 0o640)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    export(args.state, args.output)
