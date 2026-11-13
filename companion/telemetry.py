"""Bounded, private server history. No visitor identities or raw URLs are stored.

One minute samples and grouped request counters are retained for seven days.
The web process receives only aggregate exports; it cannot query the database,
read server logs, execute PHP or alter monitoring configuration.
"""
import argparse
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import threading
import time
from .monitor import private_json
from .operations import write_export
from .php_pool import fastcgi_json, pool

GROUPS = {'home', 'catalog', 'product', 'cart', 'checkout', 'account', 'admin', 'api', 'other'}
NUMBERS = ('cpu', 'iowait', 'memory', 'swap_bytes', 'disk', 'load', 'php_active', 'php_queue',
           'php_limit_hits', 'opcache_used', 'opcache_free', 'opcache_restarts', 'db_connections', 'db_running')
WINDOWS = {'1h': (3600, 60), '24h': (86400, 300), '7d': (604800, 1800)}
# An observation older than three collection intervals is no longer current health.
FRESH_SECONDS = 180
ROOT = Path('/var/lib/cloudpanel-companion-telemetry')
# WordPress health loads the whole site, so it is read hourly and kept between runs.
WORDPRESS_INTERVAL = 3600
# A WP-Cron event this late is not waiting for the next cron run: events are not running.
CRON_OVERDUE = 3600


def command(arguments, timeout=3):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout, check=True)
    if len(result.stdout) > 262144:
        raise ValueError('Observation exceeds its bound')
    return result.stdout.decode('utf-8', errors='replace')


def json_lines(arguments, timeout, limit, keep=lambda item: item, line_bytes=65536):
    """What `keep` takes from each JSON line a command prints, within a deadline and a count.

    Lines are read one at a time, so only what `keep` returns is held. Returns the kept
    values, whether every line was kept, and the exit status (None when reading stopped
    at `limit` lines and the command was stopped). A line longer than `line_bytes` is
    skipped; it, too, makes the result incomplete. A command still running at `timeout`
    seconds is killed and raises subprocess.TimeoutExpired, so a stuck journal or mail
    system cannot hold a collector until systemd stops it.
    """
    expired = threading.Event()
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def stop():
        expired.set()
        process.kill()
    deadline = threading.Timer(timeout, stop)
    deadline.start()
    kept, complete, skipping, stopped = [], True, False, False
    try:
        while line := process.stdout.readline(line_bytes + 1):
            ended = line.endswith(b'\n')
            if skipping or (len(line) > line_bytes and not ended):
                skipping, complete = not ended, False
                continue
            if len(kept) >= limit:
                complete, stopped = False, True
                break
            kept.append(keep(json.loads(line)))
    except ValueError:
        # The deadline cuts the last line short; that is a timeout, not malformed output.
        if not expired.is_set():
            raise
    finally:
        deadline.cancel()
        if process.poll() is None:
            process.kill()
        process.stdout.close()
        process.wait()
    if expired.is_set():
        raise subprocess.TimeoutExpired(arguments, timeout)
    return kept, complete, None if stopped else process.returncode


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


def operator_file(path):
    """A diagnostic the site's PHP pool may run: root-owned, not group- or world-writable, not a link."""
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('PHP diagnostic must be operator-owned')
    return str(path)


OPCACHE = ('opcache_used', 'opcache_free', 'opcache_wasted', 'opcache_wasted_percent', 'opcache_full', 'opcache_scripts',
           'opcache_restarts')


def opcache_sample(config, port=None):
    """The website pool's OPcache, as the operator-owned diagnostic (assets/php-diagnostics.php) reports it."""
    port = port or pool(config['user'], config['host'], config['php'])[1]
    observation = fastcgi_json(port, operator_file(config['probe']))
    if observation.get('available') is not True:
        raise ValueError('Web OPcache status unavailable')
    return {key: observation[key] for key in OPCACHE}


def php_sample(config):
    host = config['host']
    _, port = pool(config['user'], host, config['php'])
    result, errors = {}, []
    try:
        observation = fastcgi_json(port, '/status', 'json')
        if observation['pool'] != host:
            raise ValueError('Wrong PHP pool responder')
        result.update(php_active=max(0, observation['active processes'] - 1),
                      php_queue=observation['listen queue'], php_limit_hits=observation['max children reached'])
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        errors.append('PHP worker status unavailable or busy')
    try:
        result.update(opcache_sample(config, port))
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        errors.append('Web PHP OPcache unavailable or busy')
    return result, errors


def wordpress_report(raw):
    """Validate and bound what the WordPress probe reports. Names come from the site."""
    def text(value, limit=120):
        if not isinstance(value, str):
            raise ValueError('Unexpected WordPress value')
        return value[:limit]

    def updates(items):
        if not isinstance(items, list):
            raise ValueError('Unexpected WordPress updates')
        return [{'name': text(item['name']), 'version': text(item['version'], 40), 'update': text(item['update'], 40),
                 'package': item['package'] is True} for item in items[:100]]

    core, cron = raw['core'], raw['cron']
    if type(cron['overdue']) is not int or not isinstance(cron['hooks'], dict) or type(cron['oldest']) not in (int, type(None)):
        raise ValueError('Unexpected WP-Cron report')
    return {'core': {'version': text(core['version'], 40), 'update': None if core['update'] is None else text(core['update'], 40)},
            'plugins': updates(raw['plugins']), 'themes': updates(raw['themes']),
            'updates_checked': raw['updates_checked'] if type(raw['updates_checked']) is int else None,
            'cron': {'overdue': cron['overdue'], 'oldest': cron['oldest'],
                     'hooks': sorted(((text(hook), count) for hook, count in cron['hooks'].items() if type(count) is int),
                                     key=lambda item: -item[1])[:5]}}


def wordpress_sample(config, now):
    """Pending updates and overdue WP-Cron events, read through the site's own PHP pool.

    The operator-owned probe runs as the site user, like every page view. It reads
    only the update information WordPress has already cached and never contacts
    WordPress.org, so a check costs one site load. Nothing runs WordPress as root.
    """
    try:
        _, port = pool(config['user'], config['host'], config['php'])
        raw = fastcgi_json(port, operator_file(config['wordpress_probe']), 'overdue=' + str(CRON_OVERDUE),
                           config['host'], timeout=20)
        return {'checked_at': now, 'available': True, **wordpress_report(raw)}
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError, subprocess.SubprocessError):
        return {'checked_at': now, 'available': False}


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


def percentile(bins, count, share):
    threshold, seen = math.ceil(count * share), 0
    for bucket, total in sorted(bins.items(), key=lambda item: int(item[0])):
        seen += total
        if seen >= threshold:
            return round(1.1 ** int(bucket), 1)
    return None


def merge_group(groups, group):
    """Fold a sample's route and cache group into one row per page type.

    Only requests the page cache did not answer are timed: a hit says nothing
    about how quickly the website itself responds.
    """
    target = groups.setdefault(group['route'], {'route': group['route'], 'count': 0, 'hits': 0, 'misses': 0,
                                                'errors': 0, 'timed': 0, 'bins': Counter()})
    target['count'] += group['count']
    target['errors'] += group['errors']
    if group['cache'] == 'HIT':
        target['hits'] += group['count']
        return
    target['misses'] += group['count'] if group['cache'] == 'MISS' else 0
    target['timed'] += group['timed']
    target['bins'].update(group['bins'])


def finish_groups(groups):
    routes = []
    for group in groups.values():
        group = dict(group)
        bins = group.pop('bins')
        group['typical_ms'] = percentile(bins, group['timed'], .5) if group['timed'] else None
        group['slowest_ms'] = percentile(bins, group['timed'], .95) if group['timed'] else None
        routes.append(group)
    return sorted(routes, key=lambda row: row['count'], reverse=True)


def disk_trend(fit, now, free):
    """Growth of used space as the least-squares slope of free space over the retained week.

    One staging refresh or log rotation moves a line fitted to every sample far less
    than it moves a first-to-last difference. No estimate before a day of samples.
    """
    count, first = fit['count'], fit['first']
    spread = count * fit['xx'] - fit['x'] ** 2
    if first is None or now - first < 86400 or count < 60 or spread <= 0 or type(free) is not int:
        return None
    per_day = round(-(count * fit['xy'] - fit['x'] * fit['y']) / spread)
    # Growth that would take a century to fill the disk is no growth worth dating.
    return {'since': first, 'growth': round(per_day * (now - first) / 86400), 'free': free,
            'full_at': int(now + free / per_day * 86400) if per_day > 0 and free / per_day < 36500 else None}


def export(db, now):
    # Stream history once. Keeping thousands of decoded service/request objects
    # in memory would make the collector grow expensive after a week of use.
    result = {'observed_at': now, 'started_at': None, 'windows': {}, 'latest': None}
    windows = {name: {'buckets': {}, 'routes': {}, 'errors': Counter(), 'samples': 0, 'gaps': 0, 'php_queue_max': None} for name in WINDOWS}
    changes, previous = deque(maxlen=20), {}
    fit = {'count': 0, 'first': None, 'x': 0.0, 'y': 0.0, 'xx': 0.0, 'xy': 0.0}
    for at, payload in db.execute('SELECT at,payload FROM samples WHERE at>=? ORDER BY at', (now - 604800,)):
        row = json.loads(payload)
        if result['started_at'] is None:
            result['started_at'] = at
        result['latest'] = row
        if type(row.get('disk_free')) is int:
            # Days relative to now keep the sums small enough for exact float arithmetic.
            x, y = (at - now) / 86400, row['disk_free']
            fit['first'] = at if fit['first'] is None else fit['first']
            fit['count'] += 1
            fit['x'], fit['y'], fit['xx'], fit['xy'] = fit['x'] + x, fit['y'] + y, fit['xx'] + x * x, fit['xy'] + x * y
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
                changes.append({'at': at, 'unit': item['unit'], 'name': item['name'], 'before': previous[item['unit']],
                                'after': item['state']})
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
    result['disk_trend'] = disk_trend(fit, now, (result['latest'] or {}).get('disk_free'))
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
        try:
            system = json.loads(Path('/var/lib/cloudpanel-companion-system-observations/latest.json').read_text())
            # History needs only which unit was in which state; the system export owns the rest.
            sample['services'] = ([{key: item[key] for key in ('unit', 'name', 'state')} for item in system['services']]
                                  if 0 <= now - system['observed_at'] <= FRESH_SECONDS else [])
        except (OSError, ValueError, KeyError, TypeError):
            sample['services'] = []
        wordpress = previous.get('wordpress')
        if config.get('wordpress_probe') and (not wordpress or not 0 <= now - wordpress['checked_at'] < WORDPRESS_INTERVAL):
            wordpress = wordpress_sample(config, now)
        sample['at'] = now
        try:
            payload = json.dumps(sample, separators=(',', ':'))
            if len(payload) > 65536:
                raise ValueError('Grouped telemetry exceeded its bound')
            with database:
                database.execute('DELETE FROM samples WHERE at<?', (now - 604800,))
                database.execute('INSERT OR REPLACE INTO samples VALUES(?,?)', (now, payload))
                database.execute('DELETE FROM samples WHERE at NOT IN (SELECT at FROM samples ORDER BY at DESC LIMIT 10081)')
                # Commit the log cursor with its counters. A killed collector
                # cannot count the same request twice on its next invocation.
                database.execute('INSERT INTO cursor VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
                                 (json.dumps({'cpu': cpu, 'access': cursor, 'errors': offsets, 'wordpress': wordpress}),))
            database.execute('PRAGMA incremental_vacuum(256)')
            exported = export(database, now)
            exported['wordpress'] = wordpress
        finally:
            database.close()
        write_export(output, json.dumps(exported, separators=(',', ':')))
        return {'observed_at': now, 'samples': exported['windows']['7d']['sample_count'], 'unavailable': unavailable}
    finally:
        os.close(lock)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/etc/cloudpanel-companion/telemetry.json'))
    args = parser.parse_args()
    print(json.dumps(collect(args.config)))
