"""Presentation of bounded aggregate exports, never direct server access."""
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import time


def close(result, segment):
    """Store one measured run as a line plus its filled area down to the zero axis."""
    result['segments'].append(' '.join(segment))
    first, last = segment[0].split(',')[0], segment[-1].split(',')[0]
    result['areas'].append(' '.join(segment) + f' {last},140.0 {first},140.0')


def chart(points, key, title, unit, description, step, ceiling=None):
    available = [(point['at'], point.get(key)) for point in points
                 if type(point.get(key)) in (int, float) and math.isfinite(point[key])]
    result = {'title': title, 'unit': unit, 'description': description, 'segments': [], 'areas': [], 'points': len(available)}
    if not available:
        return result
    start, end = points[0]['at'], points[-1]['at']
    maximum = ceiling or max(1, max(value for _, value in available) * 1.15)
    segment, previous = [], None
    for at, value in available:
        if previous is not None and at - previous > step * 1.5:
            close(result, segment)
            segment = []
        x = 42 + (at - start) / max(step, end - start) * 550
        y = 140 - min(maximum, max(0, value)) / maximum * 125
        segment.append(f'{x:.1f},{y:.1f}')
        previous = at
    close(result, segment)
    result.update(maximum=f'{maximum:.0f}', latest=f'{available[-1][1]:.1f}',
                  start=datetime.fromtimestamp(start, timezone.utc), end=datetime.fromtimestamp(end, timezone.utc),
                  last_x=f'{x:.1f}', last_y=f'{y:.1f}')
    return result


def presentation(path, window='1h', now=None):
    now = now or time.time()
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('Oversized export')
        history = json.loads(path.read_text())
        selected = history['windows'][window]
        points = selected['points']
        if len(points) > 1000 or len(selected['routes']) > 50:
            raise ValueError('Oversized aggregate')
        stale = not 0 <= now - history['observed_at'] <= 180
        latest = {key: None for key in ('php_active', 'php_queue', 'php_limit_hits', 'opcache_free', 'opcache_restarts',
                                      'db_connections', 'db_running', 'disk_free', 'iowait')}
        latest.update(history.get('latest') or {})
        latest.setdefault('security', {'firewall': None, 'ssh_jail': None})
        charts = [chart(points, key, title, unit, description, step, ceiling)
                  for key, title, unit, description, ceiling in (
                      ('cpu', 'CPU use', '%', 'Share of CPU time in use.', 100),
                      ('memory', 'Memory in use', '%', 'Memory in use. Reclaimable cache counts as free.', 100),
                      ('origin_ms', 'Uncached origin response', 'ms', 'Average time for uncached pages to start responding.', None),
                      ('requests', 'Website requests', '', 'Page requests per interval. Static files and health checks are excluded.', None),
                  ) for step in [{'1h': 60, '24h': 300, '7d': 1800}[window]]]
        routes = selected['routes']
        request_count = sum(row['count'] for row in routes)
        errors = sum(row['errors'] for row in routes)
        hits = sum(row['count'] for row in routes if row['cache'] == 'HIT')
        known = sum(row['count'] for row in routes if row['cache'] in ('HIT', 'MISS'))
        findings = []
        queue_peak = selected.get('php_queue_max')
        if queue_peak is not None and queue_peak > 0:
            findings.append(f'PHP had queued requests in this window. The highest sampled queue was {queue_peak}. This confirms queueing, but does not by itself establish the cause.')
        if errors:
            findings.append(f'{errors:,} of {request_count:,} observed website requests returned a server error (HTTP 5xx). Check the route and error groups below.')
        if latest.get('opcache_free') is not None and latest['opcache_free'] < 8 * 1024 * 1024:
            findings.append('PHP OPcache has less than 8 MB free. Check its restart counter and PHP configuration before changing its size.')
        if selected['gaps']:
            findings.append('Some request or error logs could not be read completely. Counts for this window are incomplete.')
        return {'history': history, 'window': selected, 'selected_window': window, 'latest': latest, 'stale': stale,
                'observed_at': datetime.fromtimestamp(history['observed_at'], timezone.utc),
                'started_at': datetime.fromtimestamp(history['started_at'], timezone.utc) if history.get('started_at') else None,
                'charts': charts, 'request_count': request_count, 'error_count': errors,
                'cache_percent': round(100 * hits / known, 1) if known else None,
                'findings': findings, 'sample_rows': [dict(point, observed_at=datetime.fromtimestamp(point['at'], timezone.utc)) for point in points[-12:]][::-1],
                'service_changes': [dict(item, observed_at=datetime.fromtimestamp(item['at'], timezone.utc)) for item in history.get('service_changes', [])]}
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        return {'history': None, 'selected_window': window}
