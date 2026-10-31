"""Bounded, private server history. No visitor identities or raw URLs are stored.

One minute samples and grouped request counters are retained for seven days.
The web process receives only aggregate exports; it cannot query the database,
read server logs, execute PHP or alter monitoring configuration.
"""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
import fcntl
import grp
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import time
from .monitor import private_json
from .operations import write_private

GROUPS = {'home', 'catalog', 'product', 'cart', 'checkout', 'account', 'admin', 'api', 'other'}
NUMBERS = ('cpu', 'iowait', 'memory', 'swap_bytes', 'disk', 'load', 'php_active', 'php_queue',
           'php_limit_hits', 'opcache_used', 'opcache_free', 'opcache_restarts', 'db_connections', 'db_running')
WINDOWS = {'1h': (3600, 60), '24h': (86400, 300), '7d': (604800, 1800)}
ROOT = Path('/var/lib/cloudpanel-companion-telemetry')


def command(arguments, timeout=3, environment=None):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout, env=environment, check=True)
    if len(result.stdout) > 262144:
        raise ValueError('Observation exceeds its bound')
    return result.stdout.decode('utf-8', errors='replace')


def cpu_delta(previous, current):
    """Account for idle and I/O wait separately; guest counters overlap user."""
    if not previous or len(current) < 8 or len(previous) != len(current):
        return None, None
    delta = [new - old for new, old in zip(current[:8], previous[:8])]
    total = sum(delta)
    if min(delta) < 0 or total <= 0:
        return None, None
    return round(100 * (total - delta[3] - delta[4]) / total, 2), round(100 * delta[4] / total, 2)


def resource_sample(previous):
    values = [int(item) for item in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
    cpu, iowait = cpu_delta(previous, values)
    memory = {line.split(':')[0]: int(line.split()[1]) * 1024
              for line in Path('/proc/meminfo').read_text().splitlines() if ':' in line}
    disk = shutil.disk_usage('/')
    return {'cpu': cpu, 'iowait': iowait,
            'memory': round(100 * (1 - memory['MemAvailable'] / memory['MemTotal']), 2),
            'memory_total': memory['MemTotal'], 'swap_bytes': memory['SwapTotal'] - memory['SwapFree'],
            'disk': round(100 * disk.used / disk.total, 2), 'disk_free': disk.free,
            'load': round(os.getloadavg()[0], 2), 'cpus': os.cpu_count()}, values


def fcgi(port, path, query=''):
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'SCRIPT_NAME': path,
                   'SCRIPT_FILENAME': path, 'REQUEST_URI': path + ('?' + query if query else ''),
                   'QUERY_STRING': query, 'REQUEST_METHOD': 'GET', 'SERVER_PROTOCOL': 'HTTP/1.1',
                   'GATEWAY_INTERFACE': 'CGI/1.1', 'REMOTE_ADDR': '127.0.0.1',
                   'SERVER_NAME': 'localhost', 'SERVER_PORT': '443'}
    result = command(['/usr/bin/cgi-fcgi', '-bind', '-connect', '127.0.0.1:' + str(port)], environment=environment)
    separator = '\r\n\r\n' if '\r\n\r\n' in result else '\n\n'
    return json.loads(result.split(separator, 1)[1])


def php_sample(config):
    host, version = config['host'], config['php']
    if not re.fullmatch(r'[a-z0-9.-]+', host) or version not in ('8.2', '8.3', '8.4'):
        raise ValueError('Invalid registered PHP pool')
    path = Path('/etc/php') / version / 'fpm/pool.d' / (host + '.conf')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Untrusted native PHP pool')
    pool = path.read_text()
    users = re.findall(r'^user\s*=\s*(\S+)\s*$', pool, re.M)
    ports = re.findall(r'^listen\s*=\s*127\.0\.0\.1:([0-9]+)\s*$', pool, re.M)
    if users != [config['user']] or len(ports) != 1:
        raise ValueError('Native PHP pool identity changed')
    result, errors = {}, []
    try:
        observation = fcgi(int(ports[0]), '/status', 'json')
        if observation['pool'] != host:
            raise ValueError('Wrong PHP pool responder')
        result.update(php_active=max(0, observation['active processes'] - 1),
                      php_queue=observation['listen queue'], php_limit_hits=observation['max children reached'])
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        errors.append('PHP worker status unavailable or busy')
    try:
        probe = Path(config['probe'])
        info = probe.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or probe.is_symlink():
            raise ValueError('PHP diagnostic must be operator-owned')
        observation = fcgi(int(ports[0]), str(probe))
        if observation.get('available') is not True:
            raise ValueError('Web OPcache status unavailable')
        for key in ('opcache_used', 'opcache_free', 'opcache_restarts'):
            result[key] = observation[key]
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        errors.append('Web PHP OPcache unavailable or busy')
    return result, errors


def tail(path, previous, limit=2 * 1024 * 1024, *, follow_rotation=True):
    """Follow bounded numbered/native dated rotations without following links.

    Skipped bytes and rotations that cannot be recovered are exported as gaps.
    A fresh installation starts at the current end; it never invents old data.
    CloudPanel rotates to name-YYYY-MM-DD. Check a fixed nearby-date window,
    including timezone boundaries, rather than scanning a website-owned folder.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return [], previous, 0
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Log is not a regular file')
        identity = [info.st_dev, info.st_ino]
        if not previous:
            return [], {'id': identity, 'offset': info.st_size}, 0
        rows, gap = [], 0
        offset = previous['offset'] if previous['id'] == identity else 0
        if previous['id'] != identity:
            # Only one generation can be followed. If it changes again between
            # inspection and open, mark the gap instead of following recursively.
            if not follow_rotation:
                return [], previous, 1
            today = datetime.now(timezone.utc).date()
            candidates = [Path(str(path) + '.1')] + [
                Path(str(path) + '-' + str(today + timedelta(days=days)))
                for days in (0, -1, 1, -2)]
            for rotated in candidates:
                try:
                    rotated_info = rotated.lstat()
                    if not stat.S_ISREG(rotated_info.st_mode) or [rotated_info.st_dev, rotated_info.st_ino] != previous['id']:
                        continue
                    old, _, missed = tail(rotated, previous, limit // 2, follow_rotation=False)
                    rows.extend(old)
                    gap += missed
                    break
                except OSError:
                    continue
            else:
                gap += 1
        if offset > info.st_size:
            offset, gap = 0, gap + 1
        if info.st_size - offset > limit:
            offset, gap = info.st_size - limit, gap + 1
            stream.seek(offset)
            stream.readline(limit)
        else:
            stream.seek(offset)
        data = stream.read(limit)
        end = data.rfind(b'\n')
        consumed = end + 1 if end >= 0 else 0
        if not consumed and len(data) == limit:
            consumed, gap = len(data), gap + 1
        rows.extend(data[:consumed].decode('utf-8', 'replace').splitlines())
        return rows, {'id': identity, 'offset': stream.tell() - len(data) + consumed}, gap


def histogram_bin(milliseconds):
    # Logarithmic upper bounds have at most 10% quantization error.
    return 0 if milliseconds <= 1 else int(math.ceil(math.log(milliseconds, 1.1)))


def request_groups(rows):
    groups, invalid = {}, 0
    for row in rows:
        try:
            item = json.loads(row)
            route, status = item['route'], int(item['status'])
            if route not in GROUPS or not 100 <= status <= 599:
                raise ValueError('Unknown log group')
            cache = item['cache'] if item['cache'] in ('HIT', 'MISS', 'BYPASS') else 'OTHER'
            key = route + ':' + cache
            group = groups.setdefault(key, {'route': route, 'cache': cache, 'count': 0, 'errors': 0,
                                             'milliseconds': 0, 'timed': 0, 'bins': {}})
            group['count'] += 1
            group['errors'] += status >= 500
            # Multiple upstream attempts cannot be assigned to one PHP render.
            raw = item['upstream']
            if re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', raw):
                duration = float(raw) * 1000
                if not math.isfinite(duration) or duration > 7200000:
                    raise ValueError('Invalid timing')
                group['milliseconds'] += duration
                group['timed'] += 1
                bucket = str(histogram_bin(duration))
                group['bins'][bucket] = group['bins'].get(bucket, 0) + 1
        except (ValueError, TypeError, KeyError):
            invalid += 1
    return list(groups.values()), invalid


def error_groups(rows):
    """Classify messages without persisting original text or customer data."""
    counts = Counter()
    for row in rows:
        if 'PHP Fatal error' in row or 'PHP Parse error' in row:
            label = 'PHP fatal or parse error'
        elif 'PHP Warning' in row:
            label = 'PHP warning'
        elif 'PHP Deprecated' in row:
            label = 'PHP deprecation'
        elif 'upstream timed out' in row:
            label = 'Upstream timeout'
        elif 'connect() failed' in row or 'connection refused' in row.lower():
            label = 'Upstream connection refused'
        elif 'Permission denied' in row:
            label = 'File permission denial'
        elif re.search(r'\[(?:error|crit|alert|emerg)\]', row):
            label = 'Other server error'
        else:
            continue
        match = re.search(r'/wp-content/(plugins|themes)/([a-zA-Z0-9_-]{1,80})/', row)
        if match:
            label += ' in ' + match[1][:-1] + ' ' + match[2]
        counts[label] += 1
    return dict(counts.most_common(40))


def percentile(bins, count):
    threshold, seen = math.ceil(count * .95), 0
    for bucket, total in sorted(bins.items(), key=lambda item: int(item[0])):
        seen += total
        if seen >= threshold:
            return round(1.1 ** int(bucket), 1)
    return None


def merge_group(groups, group):
    key = group['route'] + ':' + group['cache']
    target = groups.setdefault(key, {'route': group['route'], 'cache': group['cache'],
                                     'count': 0, 'errors': 0, 'timed': 0, 'milliseconds': 0, 'bins': Counter()})
    for name in ('count', 'errors', 'timed', 'milliseconds'):
        target[name] += group[name]
    target['bins'].update(group['bins'])


def finish_groups(groups):
    routes = []
    for group in groups.values():
        group = dict(group)
        bins = group.pop('bins')
        group['mean_ms'] = round(group['milliseconds'] / group['timed'], 1) if group['timed'] else None
        group['p95_ms'] = percentile(bins, group['timed']) if group['timed'] else None
        routes.append(group)
    return sorted(routes, key=lambda row: row['count'], reverse=True)


def aggregate(samples):
    groups, errors = {}, Counter()
    for sample in samples:
        errors.update(sample.get('errors', {}))
        for group in sample.get('requests', []):
            merge_group(groups, group)
    return finish_groups(groups), errors.most_common(12)


def export(db, now):
    # Stream history once. Keeping thousands of decoded service/request objects
    # in memory would make the collector grow expensive after a week of use.
    result = {'observed_at': now, 'started_at': None, 'windows': {}, 'latest': None}
    windows = {name: {'buckets': {}, 'routes': {}, 'errors': Counter(), 'samples': 0, 'gaps': 0, 'php_queue_max': None} for name in WINDOWS}
    changes, previous = deque(maxlen=20), {}
    for at, payload in db.execute('SELECT at,payload FROM samples WHERE at>=? ORDER BY at', (now - 604800,)):
        row = json.loads(payload)
        if result['started_at'] is None:
            result['started_at'] = at
        result['latest'] = row
        for name, (duration, step) in WINDOWS.items():
            if at < now - duration:
                continue
            state = windows[name]
            state['samples'] += 1
            state['gaps'] += row.get('log_gaps', 0)
            if type(row.get('php_queue')) is int:
                state['php_queue_max'] = max(state['php_queue_max'] or 0, row['php_queue'])
            state['errors'].update(row.get('errors', {}))
            if len(state['errors']) > 200:
                common = dict(state['errors'].most_common(199))
                omitted = sum(state['errors'].values()) - sum(common.values())
                common['Other error groups'] = common.get('Other error groups', 0) + omitted
                state['errors'] = Counter(common)
            point = state['buckets'].setdefault(at // step * step, {'samples': 0, 'sum': Counter(), 'count': Counter(),
                                                                   'requests': 0, 'errors': 0, 'timed': 0, 'milliseconds': 0})
            point['samples'] += 1
            for key in NUMBERS:
                if type(row.get(key)) in (int, float):
                    point['sum'][key] += row[key]
                    point['count'][key] += 1
            for group in row.get('requests', []):
                merge_group(state['routes'], group)
                point['requests'] += group['count']
                point['errors'] += group['errors']
                if group['cache'] != 'HIT':
                    point['milliseconds'] += group['milliseconds']
                    point['timed'] += group['timed']
        for item in row.get('services', []):
            if item['unit'] in previous and previous[item['unit']] != item['state']:
                changes.append({'at': at, 'name': item['name'], 'before': previous[item['unit']], 'after': item['state']})
            previous[item['unit']] = item['state']
    for name, state in windows.items():
        points = []
        for at, bucket in sorted(state['buckets'].items()):
            point = {'at': at, 'samples': bucket['samples'], 'requests': bucket['requests'], 'errors': bucket['errors'],
                     'origin_ms': round(bucket['milliseconds'] / bucket['timed'], 1) if bucket['timed'] else None}
            for key in NUMBERS:
                point[key] = round(bucket['sum'][key] / bucket['count'][key], 2) if bucket['count'][key] else None
            points.append(point)
        result['windows'][name] = {'points': points, 'routes': finish_groups(state['routes']),
                                  'errors': state['errors'].most_common(12), 'sample_count': state['samples'],
                                  'gaps': state['gaps'], 'php_queue_max': state['php_queue_max']}
    result['service_changes'] = list(reversed(changes))
    return result


def collect(configuration, state=ROOT, output=Path('/var/lib/cloudpanel-companion-telemetry-observations/history.json')):
    if os.geteuid() != 0:
        raise ValueError('The operator installs and runs server collectors')
    config = private_json(configuration)
    info = state.lstat()
    if state.resolve() != state or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Collector state must be root-owned and private')
    lock = os.open(state / 'collect.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for filename in ('history.sqlite3', 'history.sqlite3-wal', 'history.sqlite3-shm'):
            if (state / filename).is_symlink():
                raise ValueError('Collector state cannot be a link')
        database = sqlite3.connect(state / 'history.sqlite3')
        database.execute('PRAGMA auto_vacuum=INCREMENTAL')
        database.execute('PRAGMA max_page_count=65536')
        database.execute('CREATE TABLE IF NOT EXISTS samples(at INTEGER PRIMARY KEY,payload TEXT NOT NULL)')
        database.execute('CREATE TABLE IF NOT EXISTS cursor(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL)')
        record = database.execute('SELECT payload FROM cursor WHERE id=1').fetchone()
        previous = json.loads(record[0]) if record else {}
        now = int(time.time())
        sample, cpu = resource_sample(previous.get('cpu'))
        unavailable = []
        php, errors = php_sample(config)
        sample.update(php)
        unavailable.extend(errors)
        try:
            raw = command(['/usr/bin/mysql', '--defaults-file=/etc/cloudpanel-companion/telemetry-mysql.cnf', '--batch', '--skip-column-names',
                           '-e', "SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Threads_running')"])
            values = dict(line.split('\t', 1) for line in raw.splitlines())
            sample.update(db_connections=int(values['Threads_connected']), db_running=max(0, int(values['Threads_running']) - 1))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            unavailable.append('Database connection counters unavailable')
        requests, cursor, gaps = tail(Path(config['access_log']), previous.get('access'))
        groups, invalid = request_groups(requests)
        sample.update(requests=groups, log_gaps=gaps + bool(invalid))
        offsets, error_counts, unavailable_logs = {}, Counter(), []
        for name, filename in config.get('error_logs', {}).items():
            try:
                if not Path(filename).is_file():
                    unavailable_logs.append(name)
                lines, offset, gap = tail(Path(filename), previous.get('errors', {}).get(name))
                offsets[name] = offset
                sample['log_gaps'] += gap
                error_counts.update(error_groups(lines))
            except (OSError, ValueError):
                unavailable_logs.append(name)
                offsets[name] = previous.get('errors', {}).get(name)
        sample['errors'] = dict(error_counts.most_common(40))
        sample['unavailable_logs'] = unavailable_logs
        if not Path(config['access_log']).exists():
            unavailable.append('Request timing log is not connected')
        sample['unavailable'] = unavailable
        sample['security'] = security_sample()
        try:
            system = json.loads(Path('/var/lib/cloudpanel-companion-system-observations/latest.json').read_text())
            sample['services'] = system['services'] if 0 <= now - system['observed_at'] <= 180 else []
        except (OSError, ValueError, KeyError):
            sample['services'] = []
        sample['at'] = now
        try:
            db = database
            payload = json.dumps(sample, separators=(',', ':'))
            if len(payload) > 65536:
                raise ValueError('Grouped telemetry exceeded its bound')
            with db:
                db.execute('DELETE FROM samples WHERE at<?', (now - 604800,))
                db.execute('INSERT OR REPLACE INTO samples VALUES(?,?)', (now, payload))
                db.execute('DELETE FROM samples WHERE at NOT IN (SELECT at FROM samples ORDER BY at DESC LIMIT 10081)')
                # Commit the log cursor with its counters. A killed collector
                # cannot count the same request twice on its next invocation.
                db.execute('INSERT INTO cursor VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
                           (json.dumps({'cpu': cpu, 'access': cursor, 'errors': offsets}),))
            db.execute('PRAGMA incremental_vacuum(256)')
            exported = export(db, now)
        finally:
            database.close()
        write_private(output, json.dumps(exported, separators=(',', ':')), 0o640)
        os.chown(output, 0, grp.getgrnam('companion-web').gr_gid)
        return {'observed_at': now, 'samples': exported['windows']['7d']['sample_count'], 'unavailable': unavailable}
    finally:
        os.close(lock)


def security_sample():
    result = {}
    for key, args in (
        ('firewall', ['/usr/sbin/ufw', 'status']),
        ('ssh_jail', ['/usr/bin/fail2ban-client', 'status', 'sshd']),
    ):
        try:
            value = command(args)
            if key == 'firewall':
                result[key] = 'active' if 'Status: active' in value else 'inactive'
            else:
                current = re.search(r'Currently banned:\s*(\d+)', value)
                total = re.search(r'Total banned:\s*(\d+)', value)
                result[key] = {'current': int(current[1]), 'total': int(total[1])} if current and total else None
        except (OSError, ValueError, subprocess.SubprocessError):
            result[key] = None
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/etc/cloudpanel-companion/telemetry.json'))
    args = parser.parse_args()
    print(json.dumps(collect(args.config)))
