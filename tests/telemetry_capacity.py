"""Isolated seven-day capacity fixture. Never writes dashboard history."""
import json
from pathlib import Path
import resource
import sqlite3
import tempfile
import time
from companion.telemetry import GROUPS, export


def main():
    sample = {'cpu': 30, 'memory': 40, 'php_active': 2, 'php_queue': 0, 'log_gaps': 0,
              'services': [{'unit': f'fixture-{index}.service', 'name': f'Fixture {index}', 'state': 'active',
                            'recovery_enabled': True, 'attempted_recovery': False} for index in range(14)],
              'errors': {'PHP warning in plugin fixture': 2}, 'requests': []}
    for route in GROUPS:
        for cache in ('HIT', 'MISS', 'BYPASS', 'OTHER'):
            sample['requests'].append({'route': route, 'cache': cache, 'count': 1000, 'errors': 1,
                                       'timed': 1000, 'milliseconds': 300000, 'bins': {'60': 1000}})
    now = 2000000000
    with tempfile.TemporaryDirectory(prefix='companion-history-capacity-') as directory:
        with sqlite3.connect(Path(directory) / 'fixture.sqlite3') as db:
            db.execute('CREATE TABLE samples(at INTEGER PRIMARY KEY,payload TEXT NOT NULL)')
            payload = json.dumps(sample)
            db.executemany('INSERT INTO samples VALUES(?,?)', ((now - index * 60, payload) for index in range(10081)))
            db.commit()
            started, cpu = time.monotonic(), time.process_time()
            result = export(db, now)
            elapsed, cpu = time.monotonic() - started, time.process_time() - cpu
            assert result['windows']['7d']['sample_count'] == 10081
            assert sum(row['count'] for row in result['windows']['7d']['routes']) == 10081 * 36000
            assert len(result['windows']['7d']['points']) <= 337
            size = len(json.dumps(result))
            assert size < 2 * 1024 * 1024
            print(json.dumps({'fixture': 'Synthetic isolated seven-day capacity test, not visitor history',
                              'samples': 10081, 'export_wall_seconds': round(elapsed, 3),
                              'export_cpu_seconds': round(cpu, 3), 'peak_memory_mb': round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2),
                              'export_bytes': size}))


if __name__ == '__main__':
    main()
