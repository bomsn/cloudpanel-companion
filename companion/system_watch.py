"""Observe registered systemd units and bound recovery of failed units.

Intentional inactive/stopped units are never started automatically. Recovery
requires two failed observations and is limited to two attempts per unit/hour,
with a five-minute cooldown. HTTP errors never trigger a database/server restart.
Scheduled backups are observed too (companion.backups); they are never run here.
So are the package's timer-driven jobs and the outgoing mail queue.
"""
import argparse
import fcntl
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
from .monitor_setup import TIMERS, validate_units
from .operations import write_export
from .telemetry import json_lines

PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'Result', 'UnitFileState', 'ActiveEnterTimestamp', 'StateChangeTimestamp',
              'ExecMainStartTimestamp', 'ConditionResult', 'ConditionTimestamp')
ACTIVE_STATES = ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading')
POSTQUEUE = Path('/usr/sbin/postqueue')
# A message still queued after an hour is not a retry in progress: delivery is failing.
MAIL_STUCK_AFTER = 3600
MAIL_LIMIT = 100000
MAIL_TIMEOUT = 10
# One entry lists every recipient of a message; a longer entry is skipped, and the count marked incomplete.
MAIL_LINE_BYTES = 1024 * 1024


def unit_properties(names):
    """systemd's view of each unit, read in one call and in argument order.

    Order, not the reported Id, identifies a unit: an alias such as mysql.service
    reports the unit it points to. A unit systemd cannot load reports not-found.
    """
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'show', '--timestamp=unix', '--property=' + ','.join(PROPERTIES),
                                 '--', *names], capture_output=True, timeout=15, check=True)
        blocks = [dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
                  for block in result.stdout.decode(errors='replace').strip().split('\n\n')]
    except (OSError, subprocess.SubprocessError):
        blocks = []
    if len(blocks) != len(names):
        return {name: {} for name in names}
    return dict(zip(names, blocks))


def moment(value):
    """Epoch seconds of a `--timestamp=unix` value; empty means it never happened."""
    return int(value[1:]) if re.fullmatch(r'@[0-9]+', value or '') else None


def service_state(properties):
    """One plain state per unit, so a missing unit is not reported as merely inactive."""
    load = properties.get('LoadState')
    if load in ('not-found', 'masked'):
        return 'not-installed' if load == 'not-found' else 'masked'
    state = properties.get('ActiveState')
    return state if load == 'loaded' and state in ACTIVE_STATES else 'unknown'


def next_runs():
    """When each timer next elapses. Timers relative to their job's last run have none while it runs."""
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'list-timers', '--all', '--output=json', '--no-pager'],
                                capture_output=True, timeout=15, check=True)
        return {item['unit']: item['next'] // 1000000 for item in json.loads(result.stdout)
                if type(item.get('next')) is int and item['next'] > 0}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return {}


def scheduled_job(timer, service, next_run):
    """A timer and the oneshot it starts: on or off, its last run and result, and its next run."""
    if timer.get('LoadState') != 'loaded':
        return None
    enabled, scheduled = timer.get('UnitFileState') == 'enabled', timer.get('ActiveState') == 'active'
    running = service.get('ActiveState') in ('activating', 'deactivating')
    # A unit that never started also reports ConditionResult=no, but without a time.
    if service.get('ConditionResult') == 'no' and moment(service.get('ConditionTimestamp')):
        # The job's own condition (for example, Slack not set up) skipped the run.
        last, result = moment(service.get('ConditionTimestamp')), 'skipped'
    else:
        last = moment(service.get('ExecMainStartTimestamp'))
        result = None if running or last is None else service.get('Result') or None
    healthy = result in (None, 'success', 'skipped') and (scheduled or not enabled)
    return {'enabled': enabled, 'scheduled': scheduled, 'running': running, 'last_run': last,
            'result': result, 'next_run': next_run if scheduled else None, 'healthy': healthy}


def mail_queue(now, postqueue=POSTQUEUE):
    """Postfix's queue as a count and the oldest arrival; None without Postfix.

    Only each entry's arrival time is read. Recipients, senders and contents never
    leave this function. Reading is bounded in time and in the number of entries.
    """
    if not postqueue.exists():
        return None
    try:
        arrivals, complete, returncode = json_lines([str(postqueue), '-j'], MAIL_TIMEOUT, MAIL_LIMIT,
                                                    lambda item: item['arrival_time'], MAIL_LINE_BYTES)
        if any(type(arrival) is not int for arrival in arrivals):
            raise ValueError('Unexpected queue entry')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        arrivals, returncode = None, None
    # A queue that cannot be read (the mail system is down) cannot be delivering.
    if arrivals is None or returncode:
        return {'available': False, 'stuck_after': MAIL_STUCK_AFTER}
    oldest = min(arrivals, default=None)
    return {'available': True, 'count': len(arrivals), 'complete': complete, 'oldest_at': oldest,
            'stuck': oldest is not None and now - oldest > MAIL_STUCK_AFTER, 'stuck_after': MAIL_STUCK_AFTER}


def run(configuration, state, output, backup_cron_files=backups.CRON_FILES):
    if os.geteuid() != 0:
        raise ValueError('System service recovery requires root')
    settings = private_json(configuration)
    units = settings['units']
    validate_units(units)
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
            timers = list(TIMERS)
            # A timer starts the service of the same name; its oneshot run carries the result.
            oneshots = [name.removesuffix('.timer') + '.service' for name in timers]
            properties = unit_properties([unit['name'] for unit in units] + timers + oneshots)
            for unit in units:
                actual = service_state(properties[unit['name']])
                # Inactive is explicitly reported, not labelled healthy. Alerting
                # does not imply permission to undo an operator's deliberate stop.
                store.observe(Observation(unit['label'], actual in ('active', 'reloading'), 'service-' + actual, None, 0))
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
                    properties.update(unit_properties([unit['name']]))
                    actual = service_state(properties[unit['name']])
                    if actual == 'active':
                        store.observe(Observation(unit['label'], True, 'service-active', None, 0), threshold=1)
                current = properties[unit['name']]
                # The unit systemd runs names the product: mysql.service is an alias of
                # mariadb.service where MariaDB is installed. The label names alerts.
                observations.append({'unit': current.get('Id') or unit['name'], 'name': unit['label'], 'state': actual,
                                     'healthy': actual in ('active', 'reloading'),
                                     # Running since it started (a reload keeps that); otherwise since it changed.
                                     'since': moment(current.get('ActiveEnterTimestamp' if actual in ('active', 'reloading')
                                                                 else 'StateChangeTimestamp')),
                                     'recovery_enabled': unit['recover'], 'attempted_recovery': attempted})
            with store.db:
                store.db.execute('DELETE FROM recovery_attempts WHERE at<?', (now - 86400,))
            # A failed scheduled run alerts like a failed service. The timer runs it
            # again on schedule, so there is nothing to recover.
            schedule, scheduled = next_runs(), []
            for timer, service in zip(timers, oneshots):
                job = scheduled_job(properties[timer], properties[service], schedule.get(timer))
                if job:
                    job.update(unit=timer, service=service, name='Scheduled job: ' + TIMERS[timer][0])
                    store.observe(Observation(job['name'], job['healthy'], 'job-' + str(job['result']), None, 0))
                    scheduled.append(job)
            mail = mail_queue(now)
            if mail:
                category = 'mail-' + ('unavailable' if not mail['available'] else 'stuck' if mail['stuck'] else 'flowing')
                store.observe(Observation('Outgoing mail', category == 'mail-flowing', category, None, 0))
            # Scheduled backups are observed like services: a missed one becomes an
            # incident through the same store and delivery, and is listed on the Overview.
            jobs = backups.observe(now, backup_cron_files)
            for job in jobs:
                store.observe(Observation(job['name'], job['healthy'], 'backup-' + job['state'], None, 0))
            write_export(output, json.dumps({'observed_at': now, 'services': observations, 'scheduled': scheduled, 'mail': mail,
                                             'backups': jobs, 'backup_grace': backups.GRACE}))
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
