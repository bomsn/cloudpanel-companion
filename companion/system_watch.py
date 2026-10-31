"""Observe registered systemd units and bound recovery of failed units.

Intentional inactive/stopped units are never started automatically. Recovery
requires two failed observations and is limited to two attempts per unit/hour,
with a five-minute cooldown. HTTP errors never trigger a database/server restart.
Scheduled backups are observed too (companion.backups); they are never run here.
"""
import argparse
import fcntl
import grp
import json
import os
from pathlib import Path
import re
import subprocess
import time
from . import backups
from .health import Observation
from .incidents import IncidentStore
from .monitor import private_json
from .operations import write_private


def unit_state(unit):
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState', '--value'],
                                capture_output=True, timeout=5, check=True)
        value = result.stdout.decode().strip()
        return value if value in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading') else 'unknown'
    except (OSError, subprocess.SubprocessError):
        return 'unknown'


def run(configuration, state, output, backup_cron_files=backups.CRON_FILES):
    if os.geteuid() != 0:
        raise ValueError('System service recovery requires root')
    settings = private_json(configuration)
    units = settings['units']
    if not isinstance(units, list) or not 1 <= len(units) <= 20:
        raise ValueError('Register 1–20 service units')
    names, labels = set(), set()
    for unit in units:
        if (set(unit) != {'name', 'label', 'recover'} or
                not re.fullmatch(r'[a-zA-Z0-9@_.-]{1,100}\.service', unit['name']) or
                unit['name'] in names or not isinstance(unit['label'], str) or unit['label'] in labels or
                not 1 <= len(unit['label']) <= 150 or type(unit['recover']) is not bool):
            raise ValueError('Invalid service registry')
        names.add(unit['name'])
        labels.add(unit['label'])
    for directory in (state, output.parent):
        info = directory.lstat()
        if directory.resolve() != directory or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('System state/export directories must be operator-owned')
    if state.stat().st_mode & 0o077:
        raise ValueError('Recovery state must be private')
    lock = os.open(state / 'watch.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = IncidentStore(state / 'monitor.sqlite3')
        try:
            store.db.execute('CREATE TABLE IF NOT EXISTS recovery_attempts(unit TEXT NOT NULL, at INTEGER NOT NULL)')
            store.db.execute('CREATE TABLE IF NOT EXISTS unit_failures(unit TEXT PRIMARY KEY, count INTEGER NOT NULL)')
            observations = []
            now = int(time.time())
            for unit in units:
                actual = unit_state(unit['name'])
                # Inactive is explicitly reported, not labelled healthy. Alerting
                # does not imply permission to undo an operator's deliberate stop.
                store.observe(Observation(unit['label'], actual == 'active', 'service-' + actual, None, 0))
                previous = store.db.execute('SELECT count FROM unit_failures WHERE unit=?', (unit['name'],)).fetchone()
                failures = min(2, (previous[0] if previous else 0) + 1) if actual == 'failed' else 0
                with store.db:
                    store.db.execute('INSERT INTO unit_failures VALUES(?,?) ON CONFLICT(unit) DO UPDATE SET count=excluded.count',
                                     (unit['name'], failures))
                attempts = store.db.execute('SELECT at FROM recovery_attempts WHERE unit=? AND at>=? ORDER BY at',
                                            (unit['name'], now - 3600)).fetchall()
                attempted = False
                if actual == 'failed' and unit['recover'] and failures >= 2 and len(attempts) < 2 and (not attempts or now - attempts[-1][0] >= 300):
                    with store.db:
                        store.db.execute('INSERT INTO recovery_attempts VALUES(?,?)', (unit['name'], now))
                    attempted = True
                    try:
                        subprocess.run(['/usr/bin/systemctl', 'restart', unit['name']],
                                       check=True, capture_output=True, timeout=30)
                    except (OSError, subprocess.SubprocessError):
                        pass
                    actual = unit_state(unit['name'])
                    if actual == 'active':
                        store.observe(Observation(unit['label'], True, 'service-active', None, 0), threshold=1)
                observations.append({'unit': unit['name'], 'name': unit['label'], 'state': actual,
                                     'recovery_enabled': unit['recover'], 'attempted_recovery': attempted})
            with store.db:
                store.db.execute('DELETE FROM recovery_attempts WHERE at<?', (now - 86400,))
            # Scheduled backups are observed like services: a missed one becomes an
            # incident through the same store and delivery, and is listed on the Overview.
            jobs = backups.observe(now, backup_cron_files)
            for job in jobs:
                store.observe(Observation(job['name'], job['healthy'], 'backup-' + job['state'], None, 0))
            write_private(output, json.dumps({'observed_at': now, 'services': observations, 'backups': jobs,
                                              'backup_grace': backups.GRACE}), 0o640)
            os.chown(output, 0, grp.getgrnam('companion-web').gr_gid)
            return observations
        finally:
            store.close()
    finally:
        os.close(lock)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.config, args.state, args.output)))
