"""Missed-backup detection from Rclone Automated Backups' own schedule and success records.

The backup tool schedules every job with one line in its cron file and, after each
successful run, replaces `<state>/status/<job>.json` (next to `<state>/cron_scripts`).
A job whose latest scheduled run has not succeeded within GRACE seconds is reported
as missed. system_watch turns each job into an observation, so a missed backup
becomes an incident delivered like a failed service (Slack when configured) and is
listed on the Overview. Nothing here runs, edits or reschedules a backup.
"""
import base64
import calendar
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import re
import stat

CRON_FILES = (Path('/etc/cron.d/rclone-automated-backups'),
              Path('/etc/cron.d/rclone-automated-backups-by-alikhallad'))
# How long after its scheduled time a run may take to succeed. Runs queue behind
# each other through the tool's shared lock, and a large full backup takes a while.
GRACE = 3 * 3600
JOB_NAME = re.compile(r'[a-f0-9]{32}_(\d{2})-(\d{2})_(daily|weekly|monthly)')
MAX_JOBS = 50


def cron_values(field, low, high):
    """The values a numeric cron field matches (numbers, `*`, lists, ranges, steps)."""
    values = set()
    for part in field.split(','):
        part, _, step = part.partition('/')
        if part == '*':
            start, end = low, high
        elif re.fullmatch(r'\d+-\d+', part):
            start, end = map(int, part.split('-'))
        elif re.fullmatch(r'\d+', part):
            start = int(part)
            end = high if step else start
        else:
            raise ValueError('Unsupported cron field ' + field)
        if not re.fullmatch(r'\d*', step) or (step and int(step) < 1) or not low <= start <= end <= high:
            raise ValueError('Unsupported cron field ' + field)
        values.update(range(start, end + 1, int(step) if step else 1))
    return values


def previous_run(expression, before, last_day_only=False):
    """Local time (epoch seconds) of the latest run of a 5-field cron schedule at or before `before`.

    Cron runs in the server's local time zone, as datetime.fromtimestamp() does.
    `last_day_only` is the tool's "last day of the month" schedule: a daily cron
    line whose job only works on the month's final day.
    """
    fields = expression.split()
    if len(fields) != 5:
        raise ValueError('Expected a 5-field cron schedule')
    minutes, hours = cron_values(fields[0], 0, 59), cron_values(fields[1], 0, 23)
    days, months = cron_values(fields[2], 1, 31), cron_values(fields[3], 1, 12)
    weekdays = {value % 7 for value in cron_values(fields[4], 0, 7)}
    # Standard cron: when both day fields are restricted, either one matches.
    either = fields[2] != '*' and fields[4] != '*'
    limit = datetime.fromtimestamp(before)
    for offset in range(0, 400):
        day = limit.date() - timedelta(days=offset)
        by_date, by_weekday = day.day in days, (day.weekday() + 1) % 7 in weekdays
        if day.month not in months or not ((by_date or by_weekday) if either else (by_date and by_weekday)):
            continue
        if last_day_only and day.day != calendar.monthrange(day.year, day.month)[1]:
            continue
        for hour in sorted(hours, reverse=True):
            for minute in sorted(minutes, reverse=True):
                moment = datetime(day.year, day.month, day.day, hour, minute)
                if moment <= limit:
                    return int(moment.timestamp())
    return None


def root_file(path, limit=65536):
    """Contents of a root-owned regular file nobody else can change, or None."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > limit:
            return None
        return stream.read(limit)


def job_setting(script, name):
    """A setting the tool encodes in its job script (`<name>_b64=...`), or None."""
    values = re.findall(rb'^' + name.encode() + rb'_b64=([A-Za-z0-9+/=]*)$', script, flags=re.M)
    if len(values) != 1:
        return None
    try:
        return base64.b64decode(values[0], validate=True).decode()
    except (ValueError, UnicodeError):
        return None


def jobs(cron_files=CRON_FILES):
    """The enabled backup jobs: one per cron line that runs a generated job script."""
    found = []
    for cron_file in cron_files:
        content = root_file(cron_file)
        for line in (content or b'').decode(errors='replace').splitlines():
            parts = line.split()
            if len(parts) != 8 or line.lstrip().startswith('#') or parts[5:7] != ['root', '/bin/bash']:
                continue
            script = Path(parts[7])
            match = JOB_NAME.fullmatch(script.name)
            if not match or not script.is_absolute() or script.parent.name != 'cron_scripts':
                continue
            found.append({'expression': ' '.join(parts[:5]), 'script': script, 'name': script.name,
                          'time': match[1] + ':' + match[2],
                          # A monthly job on a daily cron line is the "last day of the month" schedule.
                          'schedule': 'monthly-last' if match[3] == 'monthly' and parts[2] == '*' else match[3]})
    return found[:MAX_JOBS]


def last_success(job):
    """Finish time of the job's latest successful run from its success record, or None."""
    raw = root_file(job['script'].parent.parent / 'status' / (job['name'] + '.json'), 4096)
    try:
        record = json.loads(raw) if raw else None
    except ValueError:
        return None
    if not isinstance(record, dict) or record.get('job') != job['name'] or type(record.get('finished_at')) is not int:
        return None
    return record['finished_at']


def observe(now, cron_files=CRON_FILES):
    """One entry per enabled backup job: whether its latest due run succeeded in time."""
    results = []
    labels = set()
    for job in jobs(cron_files):
        script = root_file(job['script'], 8 * 1024 * 1024)
        domain = job_setting(script, 'domain') if script else None
        kind = job_setting(script, 'type') if script else None
        label = 'Backup: ' + (domain or 'job ' + job['name'][:8]) + ' ' + (kind or 'backup') + ', ' + \
            {'monthly-last': 'last day of the month'}.get(job['schedule'], job['schedule']) + ' ' + job['time']
        label = label if label not in labels else label + ' (' + job['name'][:8] + ')'
        labels.add(label)
        try:
            due = previous_run(job['expression'], now - GRACE, job['schedule'] == 'monthly-last')
        except ValueError:
            due = None
        created = job['script'].stat().st_mtime if script else None
        success = last_success(job)
        if script is None:
            state, healthy = 'job-script-missing', False
        elif due is None or due < created:
            # Created after its latest scheduled run: nothing was due yet.
            state, healthy = 'not-due-yet', True
        elif success is not None and success >= due:
            state, healthy = 'succeeded', True
        else:
            state, healthy = 'missed', False
        results.append({'name': label, 'job': job['name'], 'healthy': healthy, 'state': state,
                        'last_success': success, 'due_at': due})
    return results
