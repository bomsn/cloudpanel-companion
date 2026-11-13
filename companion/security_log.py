"""Private sign-in, SSH, panel-visit and website-probe history for the Security page.

companion-security-log.timer runs this once a minute as root. It reads what only
root may read: the Companion-owned panel access logs (companion.client_address),
CloudPanel's own sign-in records (read-only), sshd's journal, the firewall and
Fail2ban state, the website probe log and the website's own access log
(companion.probe_guard). Entries are kept for 90 days in a root-only database, and one
bounded export is written for the interface, which never reads these sources.

The interface records its own sign-ins (companion_web.signins) with the rules in
this module, so a new source or a burst means the same thing on every panel.
Every successful CloudPanel and Companion sign-in alerts; an SSH sign-in alerts once
per user and address a day, since automation reconnects often. Alerts join the system
incident outbox, which companion-system-delivery sends to Slack when Slack is
configured, at most ALERT_LIMIT an hour; the interface hands its alerts over through a
small spool that is validated here before anything is sent.
"""
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import subprocess
import time
from . import client_address, probe_guard, ssh_jail
from .delivery import utc_time
from .incidents import IncidentStore
from .operations import write_export
from .telemetry import command, json_lines, tail

STATE = Path('/var/lib/cloudpanel-companion-security-log')
OUTPUT = Path('/var/lib/cloudpanel-companion-security-log-observations/security.json')
# The interface refuses a larger export, so the collector never writes one.
EXPORT_LIMIT = 1024 * 1024
# The system watch's incident store; companion-system-delivery sends its outbox to Slack.
ALERTS = Path('/var/lib/cloudpanel-companion-system')
SLACK = Path('/etc/cloudpanel-companion/slack.json')
PANEL_DATABASE = 'file:/home/clp/htdocs/app/data/db.sq3?mode=ro'
# Written by the interface (companion_web.signins), read and emptied here.
WEB_SPOOL = Path('/var/lib/cloudpanel-companion-web/security-alerts')

PANELS = {'companion': 'Companion', 'cloudpanel': 'CloudPanel', 'ssh': 'SSH'}
RETENTION = 90 * 86400
# Every table is cut back to its bound at the start of a run, before the run adds to it,
# so a database that ever fills up frees its own space on the next run.
MAX_EVENTS = 100000
# Distinct visiting addresses kept per panel and day; the rest are counted together.
MAX_DAILY_SOURCES = 1000
# Accepted CloudPanel passwords waiting for their sign-in record, and failed SSH
# connections already counted, matter for minutes; an hour of each is kept.
MATCH_WINDOW = 3600
MAX_PENDING = 10000
MAX_CONNECTIONS = 40000
# A burst is this many failed attempts within ten minutes. SSH meets constant
# internet-wide guessing that Fail2ban answers, so only an unusual wave counts.
BURST_WINDOW = 600
BURST_THRESHOLD = {'companion': 10, 'cloudpanel': 10, 'ssh': 60}
# At most one burst alert per panel in six hours; the page still lists every burst.
BURST_QUIET = 6 * 3600
# Entries older than this when first read (catching up on history) are highlighted, never alerted.
ALERT_AGE = 3600
# An SSH sign-in alerts once per user and address within this time.
SSH_ALERT_WINDOW = 86400
# Slack messages from this collector per hour. Past it, one note says alerts are held
# back; the Security page still lists every event.
ALERT_LIMIT = 20
# Distinct probe paths, probing addresses, not-found paths and their addresses kept per
# day; the rest are counted together. The page lists the top ones.
PROBE_DAILY = 200
PROBE_TOP = 15
MAX_BANS = 10000
# CloudPanel writes its sign-in record during the request; its access-log line is
# written as the response ends. Records younger than this wait for the next run.
PANEL_SETTLE = 30
PANEL_MATCH = 10
JOURNAL_LIMIT = 20000
# Leaves the rest of the run's 45 seconds (TimeoutStartSec) for the other sources and the export.
JOURNAL_TIMEOUT = 20
PANEL_RECORDS = 500
# One run adds at most JOURNAL_LIMIT sshd entries, PANEL_RECORDS CloudPanel records and
# what 3 MiB of each access log holds (tail() reads 2 MiB of it and 1 MiB of its rotated
# file; a line is at least 100 bytes, so 31,457 lines). With IPv6 addresses and the
# longest names, at the bytes per row measured:
#   events     (100,000 + 20,000 + 500 + 31,457) x 241 B   37 MB
#   visits     2 panels x 92 days x 1,001 x 156 B           29 MB
#   pending    (10,000 + 31,457) x 60 B                      2 MB
#   SSH        (40,000 + 20,000) x 109 B                     7 MB
#   probes     2 tables x 92 days x 201 x 230 B (paths)      9 MB
#              2 tables x 92 days x 201 x 110 B (addresses)  4 MB
#   bans       10,000 x 100 B                                1 MB
# about 87 MiB when written in random order (measured): two thirds of the limit, with
# room for fragmentation. tests/test_security_log.py rebuilds this worst case.
DATABASE_LIMIT = 128 * 1024 * 1024
LATEST = 25
# Failed-attempt sources listed per panel; the rest are counted in a footnote.
SOURCES = 15
SPOOL_NAME = re.compile(r'[0-9]{10}-[a-f0-9]{16}\.json')

SCHEMA = '''
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY, panel TEXT NOT NULL, outcome TEXT NOT NULL, at INTEGER NOT NULL,
    user TEXT NOT NULL, ip TEXT NOT NULL, country TEXT NOT NULL, browser TEXT NOT NULL, method TEXT NOT NULL,
    two_factor INTEGER NOT NULL, verified INTEGER NOT NULL, new_source TEXT NOT NULL, burst INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS events_panel ON events(panel, outcome, at);
CREATE TABLE IF NOT EXISTS visits(day INTEGER NOT NULL, panel TEXT NOT NULL, ip TEXT NOT NULL, country TEXT NOT NULL,
    requests INTEGER NOT NULL, PRIMARY KEY(day, panel, ip));
CREATE TABLE IF NOT EXISTS pending_logins(at REAL NOT NULL, ip TEXT NOT NULL, country TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ssh_failed_connections(connection TEXT PRIMARY KEY, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cursor(id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts_sent(at INTEGER NOT NULL, held INTEGER NOT NULL);
'''
# Requests per UTC day: probe paths and the addresses sending them (labelled with their
# country), and not-found pages that reached the website and the addresses asking for them.
PROBE_TABLES = ('probe_paths', 'probe_sources', 'missing_paths', 'missing_sources')
SCHEMA += ''.join(f'CREATE TABLE IF NOT EXISTS {table}(day INTEGER NOT NULL, key TEXT NOT NULL, label TEXT NOT NULL, '
                  f'requests INTEGER NOT NULL, PRIMARY KEY(day, key));\n' for table in PROBE_TABLES)
# Every ban the probe jail held, and the run that last saw it running.
SCHEMA += ('CREATE TABLE IF NOT EXISTS probe_bans(ip TEXT NOT NULL, start INTEGER NOT NULL, until INTEGER NOT NULL, '
           'seen INTEGER NOT NULL, PRIMARY KEY(ip, start));\n')
EVENT_FIELDS = ('at', 'user', 'ip', 'country', 'browser', 'method', 'two_factor', 'verified', 'new_source', 'burst')


# Rules shared with the interface -------------------------------------------------

def country_known(code):
    # Cloudflare sends XX when it cannot place an address.
    return bool(code) and code != 'XX'


def country_label(code):
    return {'T1': 'Tor network'}.get(code, code) if country_known(code) else 'Unknown'


def new_source(known_ips, known_countries, ip, country):
    """'country' or 'ip' when a successful sign-in comes from a source unseen in the
    previous 90 days, otherwise ''. The first recorded sign-in sets the baseline."""
    if not known_ips or not ip:
        return ''
    if country_known(country) and country not in known_countries:
        return 'country'
    return '' if ip in known_ips else 'ip'


def burst_due(failures, panel, last_burst, now):
    return failures >= BURST_THRESHOLD[panel] and (last_burst is None or now - last_burst >= BURST_QUIET)


BROWSERS = ((r'Edg(?:e|A|iOS)?/(\d+)', 'Edge'), (r'OPR/(\d+)', 'Opera'), (r'(?:Firefox|FxiOS)/(\d+)', 'Firefox'),
            (r'(?:Chrome|CriOS)/(\d+)', 'Chrome'), (r'Version/(\d+)[.\d]* (?:Mobile/\S+ )?Safari/', 'Safari'),
            (r'^curl/(\d+)', 'curl'), (r'^Wget/(\d+)', 'Wget'), (r'^python-requests/(\d+)', 'Python requests'))
SYSTEMS = (('Windows', 'Windows'), ('iPhone', 'iOS'), ('iPad', 'iPadOS'), ('Android', 'Android'),
           ('CrOS', 'ChromeOS'), ('Macintosh', 'macOS'), ('Linux', 'Linux'))


def browser(user_agent):
    """A short label such as "Firefox 133 on Windows"; the full user agent is never kept."""
    agent = (user_agent or '')[:512]
    name = next((label + ' ' + match[1] for pattern, label in BROWSERS if (match := re.search(pattern, agent))), None)
    system = next((label for token, label in SYSTEMS if token in agent), None)
    if not name:
        return 'Other client' + (' on ' + system if system else '') if agent else 'Not reported'
    return name + (' on ' + system if system else '')


def clean_user(value):
    """Attempted user names come from strangers: printable, short and inert."""
    return re.sub(r'[^\x21-\x7e]', '?', str(value or ''))[:64]


SSH_METHOD_LABELS = {'key': 'SSH key', 'password': 'Password', 'other': 'Other'}
SOURCE_LABELS = {'country': 'New country', 'ip': 'New IP address'}
# What browser() can return; the interface's spool is checked against it.
BROWSER_LABEL = re.compile(r'(?:[A-Za-z][A-Za-z ]{0,30} [0-9]{1,6}|Other client|Not reported)(?: on [A-Za-z]{2,12})?')


def signin_alert(panel, at, ip, user, *, country='', source='', first=False, method='', two_factor=False,
                 browser_label='', verified=True):
    """A successful sign-in as an alert: the event, then who signed in, from where and how."""
    where = ip + (', ' + country_label(country) if country_known(country) else '')
    marker = {'country': ' from a new country', 'ip': ' from a new IP address'}.get(source, '')
    details = [('Account', user or 'Not recorded'),
               ('Source IP', ip if verified else ip + " (CloudPanel's own record, not verified)")]
    if panel == 'ssh':
        details.append(('Method', SSH_METHOD_LABELS.get(method, 'Other')))
    else:
        details += [('Country', country_label(country)), ('Method', 'Password'),
                    ('Two-factor', 'Yes' if two_factor else 'No'), ('Browser', browser_label or 'Not reported')]
    seen = (SOURCE_LABELS.get(source) or ('Not judged: the address is not verified' if not verified else
                                          'First recorded sign-in' if first else 'Known IP address'))
    details += [('Source', seen), ('Time', utc_time(at))]
    return {'event': f'{PANELS[panel]} sign-in{marker}: {user or "unknown user"} from {where}', 'details': details}


def burst_alert(panel, at, ip, country, count):
    where = ip + (', ' + country_label(country) if country_known(country) else '')
    return {'event': f'{count} failed {PANELS[panel]} sign-in attempts within {BURST_WINDOW // 60} minutes, latest from {where}',
            'details': [('Latest attempt', utc_time(at))]}


def failed_sources(rows):
    """Failed attempts grouped by source (address and country), most recent activity first.

    One busy source is one row with its attempt count, the names it tried, the steps it
    failed and when it was active, so a guessing bot never turns the page into a log.
    `unnamed` counts attempts recorded without a name: an SSH client that sent none, or
    a Companion name that is no account's (companion_web.signins never keeps those).
    """
    groups = {}
    for row in rows:
        if row['outcome'] != 'failed':
            continue
        group = groups.setdefault((row['ip'], row['country']), {
            'ip': row['ip'], 'country': row['country'], 'attempts': 0, 'first_at': row['at'], 'last_at': row['at'],
            'names': Counter(), 'unnamed': 0, 'steps': set(), 'burst': 0})
        group['attempts'] += 1
        group['first_at'], group['last_at'] = min(group['first_at'], row['at']), max(group['last_at'], row['at'])
        if row['user']:
            group['names'][row['user']] += 1
        else:
            group['unnamed'] += 1
        if row['method']:
            group['steps'].add(row['method'])
        group['burst'] = max(group['burst'], row['burst'])
    result = []
    for group in sorted(groups.values(), key=lambda item: -item['last_at']):
        names = group.pop('names')
        # Most-tried names first; equally tried names alphabetically, whatever order the rows came in.
        tried = sorted(names.items(), key=lambda item: (-item[1], item[0]))
        result.append({**group, 'users': [name for name, _ in tried[:3]], 'more_users': max(0, len(tried) - 3),
                       'steps': sorted(group['steps'])})
    return result


def panel_summary(recent, signins, now):
    """One summary shape for every panel, from this collector or the interface's own records.

    `recent` holds the last seven days of entries and `signins` the latest successful
    ones, newest first. Rows are dicts with EVENT_FIELDS and an `outcome`.
    """
    day = now - 86400
    week = [row for row in recent if row['at'] >= now - 7 * 86400]
    sources = failed_sources(week)
    # Sign-ins and failures per UTC day, oldest first: the Security page's seven-day chart.
    today = now // 86400 * 86400
    days = {start: {'day': start, 'signins': 0, 'failed': 0} for start in range(today - 6 * 86400, today + 1, 86400)}
    for row in recent:
        bucket = days.get(row['at'] // 86400 * 86400)
        if bucket and row['outcome'] in ('signin', 'failed'):
            bucket['signins' if row['outcome'] == 'signin' else 'failed'] += 1
    return {
        'days': list(days.values()),
        'signins_24h': sum(row['outcome'] == 'signin' and row['at'] >= day for row in week),
        'signins_7d': sum(row['outcome'] == 'signin' for row in week),
        'failed_24h': sum(row['outcome'] == 'failed' and row['at'] >= day for row in week),
        'failed_7d': sum(row['outcome'] == 'failed' for row in week),
        'signins': signins[:LATEST],
        'failed_sources': sources[:SOURCES], 'source_count': len(sources), 'more_sources': max(0, len(sources) - SOURCES),
        'new_sources': [row for row in week if row['outcome'] == 'signin' and row['new_source']][:10],
        'bursts': [row for row in week if row['burst']][:10],
    }


# Sources --------------------------------------------------------------------------

def known_sources(db, panel, at):
    rows = db.execute("SELECT DISTINCT ip, country FROM events WHERE panel=? AND outcome='signin' AND verified=1 "
                      'AND at>=? AND at<=?', (panel, at - RETENTION, at)).fetchall()
    return {ip for ip, _ in rows}, {country for _, country in rows if country_known(country)}


def signin_due(db, panel, at, user, ip):
    """Every panel sign-in alerts; an SSH one only when that user did not sign in from that address in the last day."""
    return panel != 'ssh' or not db.execute(
        "SELECT 1 FROM events WHERE panel='ssh' AND outcome='signin' AND user=? AND ip=? AND at>=? AND at<=? LIMIT 1",
        (user, ip, int(at) - SSH_ALERT_WINDOW, int(at))).fetchone()


def record(db, panel, outcome, at, ip, now, alerts, *, user='', country='', browser_label='', method='',
           two_factor=False, verified=True):
    source, first = '', False
    if outcome == 'signin' and verified:
        known_ips, known_countries = known_sources(db, panel, at)
        source, first = new_source(known_ips, known_countries, ip, country), not known_ips
    if outcome == 'signin' and now - at <= ALERT_AGE and signin_due(db, panel, at, user, ip):
        alerts.append(signin_alert(panel, at, ip, user, country=country, source=source, first=first, method=method,
                                   two_factor=two_factor, browser_label=browser_label, verified=verified))
    db.execute('INSERT INTO events(panel,outcome,at,user,ip,country,browser,method,two_factor,verified,new_source) '
               'VALUES(?,?,?,?,?,?,?,?,?,?,?)', (panel, outcome, int(at), user, ip, country, browser_label, method,
                                                int(two_factor), int(verified), source))


def detect_burst(db, panel, now, alerts):
    count, latest = db.execute("SELECT COUNT(*), MAX(id) FROM events WHERE panel=? AND outcome='failed' AND at>?",
                               (panel, now - BURST_WINDOW)).fetchone()
    last = db.execute('SELECT MAX(at) FROM events WHERE panel=? AND burst>0', (panel,)).fetchone()[0]
    if burst_due(count, panel, last, now):
        db.execute('UPDATE events SET burst=? WHERE id=?', (count, latest))
        at, ip, country = db.execute('SELECT at, ip, country FROM events WHERE id=?', (latest,)).fetchone()
        alerts.append(burst_alert(panel, at, ip, country, count))


def tally(db, table, rows):
    """Add one request per (time, key, label) row to a per-day table.

    A day keeps PROBE_DAILY distinct keys; later ones share the empty key, so the day's
    total stays exact while the table stays bounded.
    """
    counts, labels = Counter(), {}
    for at, key, label in rows:
        bucket = (int(at) // 86400 * 86400, key)
        counts[bucket] += 1
        labels[bucket] = label
    for (day, key), count in counts.items():
        label = labels[(day, key)]
        if not db.execute(f'SELECT 1 FROM {table} WHERE day=? AND key=?', (day, key)).fetchone() and \
                db.execute(f'SELECT COUNT(*) FROM {table} WHERE day=?', (day,)).fetchone()[0] >= PROBE_DAILY:
            key, label = '', ''
        db.execute(f'INSERT INTO {table} VALUES(?,?,?,?) ON CONFLICT(day,key) DO UPDATE SET '
                   'requests=requests+excluded.requests, label=excluded.label', (day, key, label, count))


def record_bans(db, bans, now):
    """The probe jail's current bans, marked as seen by this run."""
    for ip, start, until in bans:
        db.execute('INSERT INTO probe_bans VALUES(?,?,?,?) ON CONFLICT(ip,start) DO UPDATE SET '
                   'until=excluded.until, seen=excluded.seen', (ip, start, until, now))


def count_visits(db, panel, entries):
    requests, countries = Counter(), {}
    for entry in entries:
        key = (int(entry['at']) // 86400 * 86400, entry['ip'])
        requests[key] += 1
        countries[key] = entry['country']
    for (day, ip), count in requests.items():
        country = countries[(day, ip)]
        if not db.execute('SELECT 1 FROM visits WHERE day=? AND panel=? AND ip=?', (day, panel, ip)).fetchone() and \
                db.execute('SELECT COUNT(*) FROM visits WHERE day=? AND panel=?', (day, panel)).fetchone()[0] >= MAX_DAILY_SOURCES:
            ip, country = '', ''
        db.execute('INSERT INTO visits VALUES(?,?,?,?,?) ON CONFLICT(day,panel,ip) DO UPDATE SET '
                   'requests=requests+excluded.requests, country=excluded.country', (day, panel, ip, country, count))


def cloudpanel_outcomes(db, entries, now, alerts):
    """CloudPanel answers every password POST with a redirect: back to /login when it
    was rejected, onwards when accepted. A rejected code re-renders its form (200)."""
    for entry in entries:
        if entry['method'] != 'POST':
            continue
        if entry['path'] == 'login' and entry['status'] in (302, 303):
            if entry['next'] == 'login':
                record(db, 'cloudpanel', 'failed', entry['at'], entry['ip'], now, alerts,
                       country=entry['country'], method='password')
            else:
                db.execute('INSERT INTO pending_logins VALUES(?,?,?)', (entry['at'], entry['ip'], entry['country']))
        elif entry['path'] == 'code' and entry['status'] == 200:
            record(db, 'cloudpanel', 'failed', entry['at'], entry['ip'], now, alerts, country=entry['country'], method='code')


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return ''


def cloudpanel_signins(db, after, now, alerts, database=PANEL_DATABASE):
    """CloudPanel's own LOGIN records name the user and browser. Behind Cloudflare its
    recorded address is an edge server (or a client-chosen X-Real-IP), so the address
    is taken from the matching line of the Companion's panel log; without one the
    record keeps CloudPanel's address, marked unverified."""
    with closing(sqlite3.connect(database, uri=True, timeout=2)) as panel:
        rows = panel.execute("SELECT event.id, event.created_at, event.user_name, event.source_ip_address, "
                             "event.user_agent, user.mfa FROM event LEFT JOIN user ON user.user_name = event.user_name "
                             "WHERE event.event_name = 'LOGIN' AND event.id > ? ORDER BY event.id LIMIT ?",
                             (after or 0, PANEL_RECORDS)).fetchall()
    last = after or 0
    for event_id, created, user, address, agent, mfa in rows:
        # CloudPanel's kernel sets PHP to UTC before it writes these records.
        at = int(datetime.strptime(str(created)[:19], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp())
        if at > now - PANEL_SETTLE:
            break
        last = event_id
        if at < now - RETENTION:
            continue
        match = db.execute('SELECT rowid, ip, country FROM pending_logins WHERE at BETWEEN ? AND ? '
                           'ORDER BY abs(at - ?) LIMIT 1', (at - PANEL_MATCH, at + PANEL_MATCH + 1, at)).fetchone()
        if match:
            db.execute('DELETE FROM pending_logins WHERE rowid=?', (match[0],))
        ip, country = (match[1], match[2]) if match else (valid_ip(address), '')
        record(db, 'cloudpanel', 'signin', at, ip, now, alerts, user=clean_user(user), country=country,
               browser_label=browser(agent), method='password', two_factor=bool(mfa), verified=bool(match))
    return last


# Only an existing account can be accepted, so its name has no spaces. A failed attempt's
# name is the client's choice and may itself contain "from 192.0.2.1 port 1": sshd writes
# the real address last, so each failure pattern is anchored at the end and its greedy
# name group leaves only that final address to the address group.
SSH_ACCEPTED = re.compile(r'Accepted (\S+) for (\S+) from (\S+) port \d+')
SSH_FAILED = (re.compile(r'Failed \S+ for (?:invalid user )?(.*) from (\S+) port \d+ ssh2(?:: .*)?$'),
              re.compile(r'Invalid user (.*) from (\S+) port \d+$'),
              re.compile(r'(?:Connection (?:closed|reset) by|Disconnected from) (?:authenticating|invalid) user (.*) (\S+) port \d+ \[preauth\]$'))
SSH_METHODS = {'publickey': 'key', 'password': 'password', 'keyboard-interactive/pam': 'password'}


def ssh_entry(entry):
    """One sshd journal entry as a sign-in or failure, keyed by its connection's process.

    A failed connection logs several lines (an invalid user, then its disconnect);
    the connection key lets the caller count it once.
    """
    message = entry.get('MESSAGE')
    if not isinstance(message, str):
        return None
    try:
        at = int(entry['__REALTIME_TIMESTAMP']) // 1000000
    except (KeyError, TypeError, ValueError):
        return None
    found = None
    match = SSH_ACCEPTED.match(message)
    if match:
        found = {'outcome': 'signin', 'method': SSH_METHODS.get(match[1], 'other'), 'user': match[2], 'ip': match[3]}
    else:
        for pattern in SSH_FAILED:
            match = pattern.match(message)
            if match:
                found = {'outcome': 'failed', 'method': '', 'user': match[1], 'ip': match[2]}
                break
    if not found or not valid_ip(found['ip']):
        return None
    return {**found, 'at': at, 'ip': valid_ip(found['ip']), 'user': clean_user(found['user']),
            'connection': str(entry.get('_BOOT_ID', '')) + ':' + str(entry.get('_PID', ''))}


def journal(cursor, since, limit=JOURNAL_LIMIT):
    """sshd's own entries: _COMM and _UID are recorded by journald, so a local user
    cannot add lines that pass for sshd's by choosing a syslog identifier."""
    arguments = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json',
                 '--after-cursor=' + cursor if cursor else '--since=@' + str(int(since)),
                 '_COMM=sshd', '_COMM=sshd-session', '_UID=0']
    entries, _, returncode = json_lines(arguments, JOURNAL_TIMEOUT, limit)
    # journalctl refuses a cursor it cannot read (exit 1, no entries); continue from the saved time.
    if returncode and cursor and not entries:
        return journal(None, since, limit)
    entries = [entry for entry in entries if isinstance(entry, dict)]
    last = next((entry['__CURSOR'] for entry in reversed(entries) if '__CURSOR' in entry), None)
    return entries, last


def ssh(db, saved, now, alerts):
    saved = saved or {}
    entries, cursor = journal(saved.get('cursor'), saved['at'] + 1 if saved.get('at') else now - RETENTION)
    latest = saved.get('at')
    for entry in entries:
        event = ssh_entry(entry)
        if not event:
            continue
        latest = max(latest or 0, event['at'])
        if event['outcome'] == 'failed' and not db.execute('INSERT OR IGNORE INTO ssh_failed_connections VALUES(?,?)',
                                                           (event['connection'], event['at'])).rowcount:
            continue
        record(db, 'ssh', event['outcome'], event['at'], event['ip'], now, alerts, user=event['user'], method=event['method'])
    return {'cursor': cursor or saved.get('cursor'), 'at': latest}


def jail_status(jail):
    """A Fail2ban jail's ban counts and banned addresses, or None while it is not running."""
    try:
        value = command([probe_guard.FAIL2BAN_CLIENT, 'status', jail])
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    current = re.search(r'Currently banned:\s*(\d+)', value)
    total = re.search(r'Total banned:\s*(\d+)', value)
    listed = re.search(r'Banned IP list:[ \t]*(.*)', value)
    if not (current and total):
        return None
    banned = [valid_ip(item) for item in (listed[1].split() if listed else [])[:200]]
    return {'current': int(current[1]), 'total': int(total[1]), 'banned': [ip for ip in banned if ip]}


def protection():
    """The firewall and ban state, as confirmed facts rather than a vulnerability scan."""
    result = {'firewall': None, 'ssh_jail': jail_status(ssh_jail.JAIL), 'ssh_ports': ssh_jail.coverage(),
              'probe_jail': jail_status(probe_guard.JAIL)}
    try:
        result['firewall'] = 'active' if 'Status: active' in command(['/usr/sbin/ufw', 'status']) else 'inactive'
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return result


def spool_alerts(spool=WEB_SPOOL, owner=None):
    """Read the interface's alert spool: each file names fields, never message text.

    The directory belongs to the interface's account, so every file is opened without
    following links, bounded and validated; the message is written here.
    """
    owner = pwd.getpwnam('companion-web').pw_uid if owner is None else owner
    try:
        directory = os.open(spool, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return [], None
    info = os.fstat(directory)
    if info.st_uid != owner or info.st_mode & 0o077:
        os.close(directory)
        raise ValueError('The interface alert spool must be private to the interface')
    names = []
    with os.scandir(directory) as listing:
        for number, item in enumerate(listing):
            if number >= 200:
                break
            # Other names are the interface's temporary files, renamed once complete.
            if SPOOL_NAME.fullmatch(item.name):
                names.append(item.name)
    alerts, processed = [], sorted(names)[:20]
    for name in processed:
        try:
            # Non-blocking, so a pipe planted in the spool cannot stall the collector before the type check.
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    continue
                item = json.loads(stream.read(2049)[:2048])
            alert = spooled_alert(item)
            if alert:
                alerts.append(alert)
        except (OSError, ValueError, TypeError, KeyError):
            continue
    return alerts, (directory, processed)


def spooled_alert(item):
    at, ip, country = int(item['at']), valid_ip(item['ip']), str(item.get('country', ''))
    if not ip or (country and not client_address.COUNTRY.fullmatch(country)) or not 0 < at < 2 ** 32:
        return None
    if (item['kind'] == 'signin' and item['source'] in ('', 'ip', 'country') and type(item['first']) is bool
            and type(item['two_factor']) is bool and isinstance(item['browser'], str) and BROWSER_LABEL.fullmatch(item['browser'])):
        return signin_alert('companion', at, ip, clean_user(item['user']), country=country, source=item['source'],
                            first=item['first'], two_factor=item['two_factor'], browser_label=item['browser'])
    if item['kind'] == 'burst' and type(item['count']) is int and 0 < item['count'] < 100000:
        return burst_alert('companion', at, ip, country, item['count'])
    return None


def clear_spool(handle):
    if handle:
        directory, names = handle
        for name in names:
            try:
                os.unlink(name, dir_fd=directory)
            except OSError:
                pass
        os.close(directory)


# Export ---------------------------------------------------------------------------

def rows(db, query, arguments):
    return [dict(zip(('outcome',) + EVENT_FIELDS, row)) for row in db.execute(
        'SELECT outcome,' + ','.join(EVENT_FIELDS) + ' FROM events WHERE ' + query, arguments)]


def visits_summary(db, panel, now):
    today = now // 86400 * 86400
    start = today - 6 * 86400
    per_day = {day: {'day': day, 'requests': requests, 'ips': ips} for day, requests, ips in db.execute(
        "SELECT day, SUM(requests), SUM(ip != '') FROM visits WHERE panel=? AND day>=? GROUP BY day", (panel, start))}
    countries = [{'country': country, 'requests': requests, 'ips': ips} for country, requests, ips in db.execute(
        "SELECT country, SUM(requests), COUNT(DISTINCT ip) FROM visits WHERE panel=? AND day>=? AND ip != '' "
        'GROUP BY country ORDER BY 2 DESC LIMIT 8', (panel, start))]
    top = [{'ip': ip, 'country': country, 'requests': requests} for ip, country, requests in db.execute(
        "SELECT ip, MAX(country), SUM(requests) FROM visits WHERE panel=? AND day>=? AND ip != '' "
        'GROUP BY ip ORDER BY 3 DESC LIMIT 10', (panel, start))]
    requests, ips, located = db.execute(
        "SELECT COALESCE(SUM(requests), 0), COUNT(DISTINCT NULLIF(ip, '')), "
        "COUNT(DISTINCT CASE WHEN ip != '' AND country NOT IN ('', 'XX') THEN country END) FROM visits "
        'WHERE panel=? AND day>=?', (panel, start)).fetchone()
    return {'days': [per_day.get(day, {'day': day, 'requests': 0, 'ips': 0}) for day in range(today, start - 1, -86400)],
            'requests': requests, 'ips': ips, 'country_count': located, 'countries': countries, 'top_ips': top}


def top_keys(db, table, since, limit=PROBE_TOP):
    """A per-day table's most requested keys since a day, with their latest label."""
    return [{'key': key, 'label': label, 'requests': requests} for key, label, requests in db.execute(
        f"SELECT key, MAX(label), SUM(requests) FROM {table} WHERE day>=? AND key!='' GROUP BY key "
        'ORDER BY 3 DESC, 1 LIMIT ?', (since, limit))]


def ban_rows(db, query, arguments):
    """Probe bans with the country their address was last seen from."""
    return [{'ip': ip, 'start': began, 'until': until, 'country': country} for ip, began, until, country in db.execute(
        "SELECT ip, start, until, COALESCE((SELECT label FROM probe_sources WHERE key=ip ORDER BY day DESC LIMIT 1), '') "
        'FROM probe_bans WHERE ' + query, arguments)]


def probes_summary(db, now):
    """The website probes of the last 7 days, the bans, the not-found pages that reached the website and edge patterns."""
    today = now // 86400 * 86400
    start = today - 6 * 86400
    per_day = dict(db.execute('SELECT day, SUM(requests) FROM probe_paths WHERE day>=? GROUP BY day', (start,)))
    missing = db.execute('SELECT COALESCE(SUM(requests), 0) FROM missing_paths WHERE day>=?', (start,)).fetchone()[0]
    return {
        'days': [{'day': day, 'requests': per_day.get(day, 0)} for day in range(start, today + 1, 86400)],
        'requests': sum(per_day.values()),
        'sources': db.execute("SELECT COUNT(DISTINCT key) FROM probe_sources WHERE day>=? AND key!=''", (start,)).fetchone()[0],
        'paths': top_keys(db, 'probe_paths', start), 'top_sources': top_keys(db, 'probe_sources', start),
        'active': ban_rows(db, 'seen=? ORDER BY until LIMIT 200', (now,)),
        'recent': ban_rows(db, 'start>=? ORDER BY start DESC LIMIT 50', (now - 7 * 86400,)),
        'recent_count': db.execute('SELECT COUNT(*) FROM probe_bans WHERE start>=?', (now - 7 * 86400,)).fetchone()[0],
        'missing': missing, 'missing_paths': top_keys(db, 'missing_paths', start),
        'missing_sources': top_keys(db, 'missing_sources', start),
        'patterns': probe_guard.edge_patterns(
            [(row['key'], row['requests']) for row in top_keys(db, 'probe_paths', start, 200)],
            [(row['key'], row['requests']) for row in top_keys(db, 'missing_paths', start, 50)]),
    }


def export(db, now, state, probes=False):
    panels = {}
    for panel in ('cloudpanel', 'ssh'):
        recent = rows(db, 'panel=? AND at>=? ORDER BY at DESC, id DESC', (panel, now - 7 * 86400))
        signins = rows(db, "panel=? AND outcome='signin' ORDER BY at DESC, id DESC LIMIT ?", (panel, LATEST))
        panels[panel] = panel_summary(recent, signins, now)
    return {'observed_at': now, 'panels': panels,
            'visits': {panel: visits_summary(db, panel, now) for panel in client_address.LOGS},
            'probes': probes_summary(db, now) if probes else None, **state}


def admit(db, alerts, now):
    """The alerts Slack receives: at most ALERT_LIMIT an hour, and past that one note that the rest are held back."""
    sent, noted = db.execute('SELECT COUNT(*), COALESCE(MAX(held), 0) FROM alerts_sent WHERE at>?', (now - 3600,)).fetchone()
    admitted = alerts[:max(0, ALERT_LIMIT - sent)]
    held = len(alerts) - len(admitted)
    db.executemany('INSERT INTO alerts_sent VALUES(?, 0)', [(now,)] * len(admitted))
    if held and not noted:
        db.execute('INSERT INTO alerts_sent VALUES(?, 1)', (now,))
        admitted.append({'event': f'More than {ALERT_LIMIT} security alerts within an hour: the rest of this hour\'s are '
                                  'not sent to Slack', 'details': [('Held back so far', str(held)),
                                                                   ('Every event', 'Listed on the Security page'),
                                                                   ('Time', utc_time(now))]})
    return admitted


def prune(db, now):
    """Delete entries past the 90-day retention and cut every table back to its bound."""
    for table in PROBE_TABLES:
        db.execute(f'DELETE FROM {table} WHERE day<?', (now - RETENTION,))
    db.execute('DELETE FROM probe_bans WHERE start<?', (now - RETENTION,))
    db.execute('DELETE FROM probe_bans WHERE rowid <= (SELECT rowid FROM probe_bans ORDER BY rowid DESC LIMIT 1 OFFSET ?)',
               (MAX_BANS,))
    db.execute('DELETE FROM alerts_sent WHERE at<?', (now - 3600,))
    db.execute('DELETE FROM events WHERE at<?', (now - RETENTION,))
    db.execute('DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)', (MAX_EVENTS,))
    db.execute('DELETE FROM visits WHERE day<?', (now - RETENTION,))
    db.execute('DELETE FROM pending_logins WHERE at<?', (now - MATCH_WINDOW,))
    db.execute('DELETE FROM pending_logins WHERE rowid <= (SELECT rowid FROM pending_logins ORDER BY rowid DESC '
               'LIMIT 1 OFFSET ?)', (MAX_PENDING,))
    # Relative to the newest counted connection, not now: while the journal is caught up
    # from older history, a connection read across two runs still counts once.
    db.execute('DELETE FROM ssh_failed_connections WHERE at < (SELECT MAX(at) FROM ssh_failed_connections) - ?',
               (MATCH_WINDOW,))
    db.execute('DELETE FROM ssh_failed_connections WHERE rowid <= (SELECT rowid FROM ssh_failed_connections '
               'ORDER BY rowid DESC LIMIT 1 OFFSET ?)', (MAX_CONNECTIONS,))


def deliver(alerts, now, store=ALERTS, slack=SLACK):
    if not alerts or not slack.exists() or not store.is_dir():
        return 0
    incidents = IncidentStore(store / 'monitor.sqlite3')
    try:
        for alert in alerts:
            incidents.notify(alert['event'], now, alert['details'])
    finally:
        incidents.close()
    return len(alerts)


def gather(db, cursor, now, alerts):
    """Read every source into the database and advance `cursor`; returns the sources that could not be read.

    The tables are pruned first, so a full database makes room before anything is added.
    """
    unavailable = []
    prune(db, now)
    for panel, path in client_address.LOGS.items():
        try:
            lines, cursor[panel], _ = tail(path, cursor.get(panel))
        except (OSError, ValueError):
            unavailable.append(PANELS[panel] + ' access log')
            continue
        entries = [entry for entry in map(client_address.access_entry, lines) if entry]
        count_visits(db, panel, entries)
        if panel == 'cloudpanel':
            cloudpanel_outcomes(db, entries, now, alerts)
    try:
        cursor['panel_event'] = cloudpanel_signins(db, cursor.get('panel_event'), now, alerts)
    except (sqlite3.Error, OSError, ValueError):
        unavailable.append('CloudPanel sign-in records')
    try:
        cursor['journal'] = ssh(db, cursor.get('journal'), now, alerts)
    except (OSError, ValueError, subprocess.SubprocessError):
        unavailable.append('SSH journal')
    for panel in ('cloudpanel', 'ssh'):
        detect_burst(db, panel, now, alerts)
    if probe_guard.CONFIG.exists():
        unavailable += gather_probes(db, cursor, now, probe_guard.settings().get('access_log'))
    return unavailable


def gather_probes(db, cursor, now, access_log):
    """The probe log, the website's not-found pages and the probe jail's bans; returns what could not be read."""
    unavailable = []
    # (cursor key, log, line parser, the tables it counts into, its name when unreadable)
    sources = [('probes', probe_guard.PROBE_LOG, probe_guard.probe_entry, 'probe', 'Website probe log')]
    if access_log:
        sources.append(('site_access', Path(access_log), probe_guard.not_found_entry, 'missing', "Website's access log"))
    for key, path, parse, tables, name in sources:
        try:
            lines, cursor[key], _ = tail(path, cursor.get(key))
        except (OSError, ValueError):
            unavailable.append(name)
            continue
        entries = [entry for entry in map(parse, lines) if entry]
        tally(db, tables + '_paths', [(entry['at'], entry['path'], '') for entry in entries])
        tally(db, tables + '_sources', [(entry['at'], entry['ip'], entry.get('country', '')) for entry in entries])
    try:
        record_bans(db, probe_guard.active_bans(), now)
    except (OSError, ValueError, subprocess.SubprocessError):
        unavailable.append('Website probe bans')
    return unavailable


def collect(state=STATE, output=OUTPUT, now=None):
    if os.geteuid() != 0:
        raise ValueError('The operator installs and runs server collectors')
    info = state.lstat()
    if state.resolve() != state or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Collector state must be root-owned and private')
    lock = os.open(state / 'collect.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for filename in ('security.sqlite3', 'security.sqlite3-journal'):
            if (state / filename).is_symlink():
                raise ValueError('Collector state cannot be a link')
        now = int(time.time()) if now is None else now
        alerts, spool = [], None
        db = sqlite3.connect(state / 'security.sqlite3')
        try:
            db.execute('PRAGMA auto_vacuum=INCREMENTAL')
            pages = DATABASE_LIMIT // db.execute('PRAGMA page_size').fetchone()[0]
            db.execute(f'PRAGMA max_page_count={pages}')
            db.executescript(SCHEMA)
            saved = db.execute('SELECT payload FROM cursor WHERE id=1').fetchone()
            cursor = json.loads(saved[0]) if saved else {}
            # Every source and its cursor commit together: a killed run cannot count an entry twice.
            with db:
                unavailable = gather(db, cursor, now, alerts)
                db.execute('INSERT INTO cursor VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
                           (json.dumps(cursor),))
            db.execute('PRAGMA incremental_vacuum(256)')
            try:
                spooled, spool = spool_alerts()
                alerts += spooled
            except (OSError, ValueError, KeyError):
                unavailable.append('Companion alert spool')
            with db:
                alerts = admit(db, alerts, now)
            exported = export(db, now, {'protection': protection(), 'panel_log': client_address.panel_log_state(),
                                        'unavailable': unavailable}, probes=probe_guard.CONFIG.exists())
        finally:
            db.close()
        payload = json.dumps(exported, separators=(',', ':'))
        if len(payload) > EXPORT_LIMIT:
            raise ValueError('The security export exceeded its bound')
        write_export(output, payload)
        delivered = deliver(alerts, now)
        clear_spool(spool)
        return {'observed_at': now, 'alerts': delivered, 'unavailable': unavailable}
    finally:
        os.close(lock)


if __name__ == '__main__':
    print(json.dumps(collect()))
