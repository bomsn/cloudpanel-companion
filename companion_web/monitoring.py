"""Presentation of bounded aggregate exports, never direct server access."""
from datetime import datetime, timezone
import json
import math
import time
from companion.monitor_setup import SERVICE_GROUPS, service_profile
from companion.telemetry import FRESH_SECONDS, WINDOWS as COLLECTED, WORDPRESS_INTERVAL


def trace(available, start, end, step, maximum, box):
    """SVG polyline segments and filled areas for (time, value) pairs inside box (left, top, width, height).

    A gap longer than one and a half intervals stays a gap: nothing is drawn across
    time that was not measured. Returns the segments, their areas and the last point.
    """
    left, top, width, height = box
    bottom = top + height
    segments, areas, segment, previous, x, y = [], [], [], None, left, bottom

    def close():
        segments.append(' '.join(segment))
        areas.append(' '.join(segment) + f' {segment[-1].split(",")[0]},{bottom:.1f} {segment[0].split(",")[0]},{bottom:.1f}')

    for at, value in available:
        if previous is not None and at - previous > step * 1.5:
            close()
            segment = []
        x = left + (at - start) / max(step, end - start) * width
        y = bottom - min(maximum, max(0, value)) / maximum * height
        segment.append(f'{x:.1f},{y:.1f}')
        previous = at
    close()
    return segments, areas, f'{x:.1f}', f'{y:.1f}'


def measured(points, key):
    return [(point['at'], point[key]) for point in points
            if type(point.get(key)) in (int, float) and math.isfinite(point[key])]


def moment(value):
    return datetime.fromtimestamp(value, timezone.utc) if type(value) is int else None


# History windows offered by the page: navigation label, the collector's interval in
# seconds and how that interval reads in a sentence.
LABELS = {'1h': ('Last hour', '1-minute'), '24h': ('24 hours', '5-minute'), '7d': ('7 days', '30-minute')}
WINDOWS = {name: {'label': LABELS[name][0], 'interval': LABELS[name][1], 'step': step} for name, (_, step) in COLLECTED.items()}
SAMPLES_PENDING = 'Waiting for measured samples'
CHARTS = (
    ('cpu', 'CPU use', '%', 'Share of CPU time in use.', 100, SAMPLES_PENDING),
    ('memory', 'Memory in use', '%', 'Memory in use. Reclaimable cache counts as free.', 100, SAMPLES_PENDING),
    ('origin_ms', 'Uncached response time', 'ms', 'Average time for uncached pages to start responding.', None,
     'Waiting for uncached website requests'),
    ('requests', 'Website requests', '', 'Page requests per interval. Static files and health checks are excluded.', None,
     SAMPLES_PENDING),
)


def chart(points, key, title, unit, description, step, ceiling=None, empty=SAMPLES_PENDING):
    available = measured(points, key)
    result = {'title': title, 'unit': unit, 'suffix': unit if unit in ('', '%') else ' ' + unit, 'description': description,
              'empty': empty, 'segments': [], 'areas': [], 'points': len(available)}
    if not available:
        return result
    start, end = points[0]['at'], points[-1]['at']
    maximum = ceiling or max(1, max(value for _, value in available) * 1.15)
    segments, areas, last_x, last_y = trace(available, start, end, step, maximum, (42, 15, 550, 125))
    # The summary is the chart's text equivalent: the same intervals, so a peak is
    # the highest interval average, never a value the line does not show.
    peak_at, peak = max(available, key=lambda item: item[1])
    result.update(segments=segments, areas=areas, maximum=f'{maximum:.0f}', latest=f'{available[-1][1]:.1f}',
                  average=f'{sum(value for _, value in available) / len(available):.1f}',
                  peak=f'{peak:.1f}', peak_at=moment(peak_at),
                  start=moment(start), end=moment(end), last_x=last_x, last_y=last_y)
    return result


def sparkline(points, key, step, ceiling=None):
    """A small trend line for a stat tile, drawn from zero to ceiling (or 15% above the peak).

    low and high are its text equivalent. None until two intervals are measured.
    """
    available = measured(points, key)
    if len(available) < 2:
        return None
    values = [value for _, value in available]
    maximum = ceiling or max(1, max(values) * 1.15)
    segments, areas, last_x, last_y = trace(available, points[0]['at'], points[-1]['at'], step, maximum, (1, 2, 118, 28))
    return {'segments': segments, 'areas': areas, 'last_x': last_x, 'last_y': last_y, 'low': min(values), 'high': max(values)}


# A usage bar turns amber at 80% and red at 90%: past 80% little room is left for a
# traffic spike, a backup or a staging copy; past 90% there is none.
USAGE_WARNING, USAGE_DANGER = 80, 90


def usage(used, total):
    """A usage bar's fill (0 to 100) and tone; None when the total is unknown."""
    if type(used) not in (int, float) or type(total) not in (int, float) or total <= 0:
        return None
    percent = max(0, min(100, 100 * used / total))
    return {'percent': round(percent), 'width': f'{percent:.1f}',
            'tone': 'danger' if percent >= USAGE_DANGER else 'warning' if percent >= USAGE_WARNING else ''}


def resources(current, history):
    """The Overview's server tiles: the latest reading, its usage bar and its 24-hour trend.

    current is the endpoint monitor's resource reading and history the collector's
    current export (empty when missing or stale), whose 24-hour window supplies the
    trends. A trend is left out, never invented, without that history.
    """
    if not current:
        return None
    points = history.get('windows', {}).get('24h', {}).get('points', [])
    step = COLLECTED['24h'][1]
    loads = [value for _, value in measured(points, 'load')]
    used_memory = current['memory_total'] - current['memory_available']
    swap_total = current.get('swap_total')
    swap_points = [{'at': point['at'], 'swap': 100 * point['swap_bytes'] / swap_total}
                   for point in points if swap_total and type(point.get('swap_bytes')) in (int, float)]
    return {
        # A load equal to the CPU count keeps every CPU busy, so the bar measures load against it.
        'load': {'value': current['load'][0], 'cpus': current['cpus'], 'bar': usage(current['load'][0], current['cpus']),
                 'trend': sparkline(points, 'load', step, max([current['cpus'], *loads]))},
        'memory': {'used': used_memory, 'total': current['memory_total'], 'available': current['memory_available'],
                   'bar': usage(used_memory, current['memory_total']), 'trend': sparkline(points, 'memory', step, 100)},
        'disk': {'free': current['disk_free'], 'total': current['disk_total'],
                 'bar': usage(current['disk_total'] - current['disk_free'], current['disk_total']),
                 'trend': sparkline(points, 'disk', step, 100)},
        'swap': {'used': current['swap_used'], 'total': swap_total, 'bar': usage(current['swap_used'], swap_total),
                 'trend': sparkline(swap_points, 'swap', step, 100)},
    }


def bars(values, labels, height=60):
    """A small bar chart's geometry on a 100-unit-wide, zero-based scale, one bar per value.

    Values and labels are in display order; each bar keeps both, so the template can
    print them and build the chart's text equivalent. A non-zero value stays visible.
    """
    peak = max(values, default=0)
    slot = 100 / max(1, len(values))
    result = []
    for index, (value, label) in enumerate(zip(values, labels)):
        size = max(1.5, value / peak * height) if value else 0
        result.append({'value': value, 'label': label, 'x': f'{index * slot + slot * 0.28:.2f}', 'width': f'{slot * 0.44:.2f}',
                       'y': f'{height - size:.1f}', 'height': f'{size:.1f}', 'center': f'{index * slot + slot / 2:.2f}'})
    return {'peak': peak, 'bars': result}


# Page types whose route name is not already a plain label.
ROUTES = {'api': 'API and AJAX', 'other': 'Other pages'}
# Plain state of a watched service, with its label tone.
STATES = {'active': ('Running', 'success'), 'reloading': ('Reloading', 'success'), 'activating': ('Starting', 'info'),
          'deactivating': ('Stopping', 'warning'), 'inactive': ('Stopped', 'warning'), 'failed': ('Failed', 'danger'),
          'not-installed': ('Not installed', 'danger'), 'masked': ('Disabled in systemd', 'danger'),
          'unknown': ('Unknown', 'warning')}
# How a scheduled job's last run ended, from systemd's result.
RESULTS = {'success': 'Succeeded', 'skipped': 'Skipped', 'exit-code': 'Failed', 'signal': 'Stopped by a signal',
           'core-dump': 'Crashed', 'timeout': 'Timed out', 'oom-kill': 'Ran out of memory', 'watchdog': 'Stopped responding',
           'start-limit-hit': 'Failed repeatedly', 'resources': 'Could not start'}


def state(value):
    return STATES.get(value, STATES['unknown'])


def services(system, site):
    """Watched services and scheduled jobs in their catalog groups, each named and described plainly.

    site is the website's domain, which heads the group of units installed for it.
    Rows carry the product name only: the group already says what each serves. The
    jobs are one group of their own, since they report runs rather than a state.
    """
    groups = {group: {'kind': group, 'title': title or site, 'icon': icon, 'role': 'Website' if group == 'site' else None,
                      'anchor': 'scheduled-jobs' if group == 'scheduled' else 'services-' + group, 'rows': []}
              for group, title, icon in SERVICE_GROUPS}
    for item in system.get('services', []):
        group, title, icon, description = service_profile(item['unit'])
        label, tone = state(item['state'])
        groups[group]['rows'].append({**item, 'title': title or item['name'], 'icon': icon, 'description': description,
                                      'label': label, 'tone': tone, 'since_at': moment(item.get('since'))})
    jobs = groups.pop('scheduled')
    for job in system.get('scheduled', []):
        _, title, icon, description = service_profile(job['unit'])
        if job['running']:
            label, tone = 'Running now', 'info'
        elif not job['scheduled']:
            label, tone = ('Not scheduled', 'danger') if job['enabled'] else ('Off', '')
        elif job['result'] is None:
            label, tone = 'Not run yet', ''
        else:
            label, tone = RESULTS.get(job['result'], 'Failed'), 'success' if job['result'] == 'success' else (
                '' if job['result'] == 'skipped' else 'danger')
        jobs['rows'].append({**job, 'title': title, 'icon': icon, 'description': description, 'label': label, 'tone': tone,
                             'last_at': moment(job['last_run']), 'next_at': moment(job['next_run'])})
    return {'groups': [group for group in groups.values() if group['rows']], 'jobs': jobs}


# What an endpoint check found, in words. Healthy HTTP checks show their status code.
CHECK_RESULTS = {'certificate-valid': 'Certificate only, no page request', 'certificate-expiring': 'Certificate expires soon',
                 'certificate-invalid': 'Certificate is not trusted', 'application-check-failed': 'WordPress or database check failed',
                 'unexpected-status': 'Unexpected response', 'dns': 'Address not found',
                 'probe-deadline': 'No answer in time', 'probe-unavailable': 'Check could not run'}


def check_result(check):
    category = check.get('category', '')
    if check.get('healthy') and check.get('status') is None:
        # A certificate check's expiry is its status label; what it did is the useful detail.
        text = CHECK_RESULTS['certificate-valid']
    elif category in CHECK_RESULTS:
        text = CHECK_RESULTS[category]
    elif category.endswith('-timeout'):
        text = 'No answer in time'
    elif category.endswith('-failure'):
        text = 'Connection failed'
    else:
        text = ''
    if check.get('status'):
        text = (text + ', HTTP ' if text else 'HTTP ') + str(check['status'])
    return text


# The icon beside each known domain: the website, this interface and CloudPanel.
ROLE_ICONS = {'Website': 'globe', 'Companion': 'layers', 'CloudPanel': 'server'}


def check_state(check, attention):
    if not check.get('healthy'):
        return 'Needs attention', 'danger'
    if attention:
        return 'Expires soon', 'warning'
    return ('Valid' if check.get('status') is None else 'Responding'), 'success'


def endpoints(checks, roles):
    """Endpoint checks grouped under their domain; roles names what each known domain is.

    Check names keep their domain because they also name alerts. Under the domain's
    own heading that prefix is repeated noise, so a row shows the rest of the name.
    """
    groups = {}
    for check in checks:
        host = check.get('host') or ''
        name = check['name'].removeprefix(host + ': ') if host else check['name']
        attention = not check.get('healthy') or check.get('category') == 'certificate-expiring'
        label, tone = check_state(check, attention)
        groups.setdefault(host, {'host': host or 'Other checks', 'role': roles.get(host),
                                 'icon': ROLE_ICONS.get(roles.get(host), 'globe'), 'anchor': 'endpoint-' + (host or 'other'),
                                 'rows': []})['rows'].append({
            **check, 'title': name[:1].upper() + name[1:], 'result': check_result(check), 'attention': attention,
            'label': label, 'tone': tone})
    order = list(roles)
    return sorted(groups.values(), key=lambda group: (order.index(group['host']) if group['host'] in order else len(order),
                                                     group['host']))


# Disk growth that fills the disk within this many days needs attention now.
DISK_ATTENTION_DAYS = 30
# A certificate this close to expiry is a problem; earlier warnings are a note, since renewal is usually automatic.
CERTIFICATE_ATTENTION_DAYS = 14


def disk(trend, now):
    if not trend:
        return None
    full = moment(trend['full_at'])
    days = (trend['full_at'] - now) / 86400 if full else None
    return {**trend, 'since_at': moment(trend['since']), 'full': full,
            'state': 'flat' if not full else 'slow' if days > 365 else 'growing',
            'soon': full is not None and days <= DISK_ATTENTION_DAYS}


def wordpress(report, now):
    if not report:
        return None
    result = {**report, 'checked': moment(report['checked_at']),
              # Read hourly; twice that without a reading means the collector stopped.
              'stale': not 0 <= now - report['checked_at'] <= 2 * WORDPRESS_INTERVAL}
    if report.get('available'):
        updates = [dict(item, kind='Plugin') for item in report['plugins']] + [dict(item, kind='Theme') for item in report['themes']]
        if report['core']['update']:
            updates.insert(0, {'name': 'WordPress', 'kind': 'Core', 'version': report['core']['version'],
                               'update': report['core']['update'], 'package': True})
        result.update(updates=updates, blocked=sum(not item['package'] for item in updates),
                      updates_label=f'{len(updates)} update{"s" if len(updates) != 1 else ""}',
                      updates_checked_at=moment(report['updates_checked']),
                      cron_oldest=moment(report['cron']['oldest']))
    return result


# What the nightly OPcache upkeep did (companion.php_runtime), in words.
UPKEEP_ACTIONS = {'not-needed': 'Not needed', 'reloaded': 'PHP-FPM reloaded', 'reload-failed': 'Reload failed',
                  'unavailable': 'OPcache could not be read', 'refused': 'Not reloaded: PHP-FPM failed its check',
                  'workflow-running': 'Skipped: a staging or release task was running'}


def upkeep(record):
    if not record or type(record.get('checked_at')) is not int:
        return None
    return {**record, 'checked': moment(record['checked_at']), 'reloaded': moment(record.get('last_reload')),
            'label': UPKEEP_ACTIONS.get(record.get('action'), 'Unknown')}


def mail(queue):
    return {**queue, 'oldest': moment(queue.get('oldest_at')), 'stuck_hours': queue['stuck_after'] // 3600} if queue else None


def attention(checks, watched, queue, trend, site, missed_backups):
    """The Overview's findings, the one place that decides how serious each is.

    Problems ('danger' or 'warning', worst first) go in the Overview's alert; notes
    ('info') are worth knowing but are not problems. Each links to the exact section
    that explains it and carries the icon of what it is about. watched is None while
    the service watch has no fresh observation: nothing it covers can then be called healthy.
    """
    items = []
    for group in checks:
        for row in group['rows']:
            days = row.get('certificate_days')
            if row.get('healthy') and row['attention']:
                items.append(('warning' if days <= CERTIFICATE_ATTENTION_DAYS else 'info', 'lock',
                              f'The {group["host"]} certificate expires in {days} day{"s" if days != 1 else ""}.',
                              '#' + group['anchor']))
            elif row['attention']:
                items.append(('danger', group['icon'], f'{row["title"]} on {group["host"]} needs attention: '
                              f'{row["result"] or "no answer"}.', '#' + group['anchor']))
    if watched is None:
        items.append(('warning', 'server', 'Services, scheduled jobs, mail and backups have not been checked recently.',
                      '#services-title'))
    for group in (watched or {}).get('groups', []):
        for row in group['rows']:
            if not row['healthy']:
                items.append(('danger', row['icon'], f'{row["title"]}: {row["label"].lower()}.', '/monitoring/#' + group['anchor']))
    if watched:
        for job in watched['jobs']['rows']:
            if not job['healthy']:
                items.append(('danger', job['icon'], f'Scheduled job "{job["title"]}": {job["label"].lower()}.',
                              '/monitoring/#' + watched['jobs']['anchor']))
    if missed_backups:
        items.append(('danger', 'archive', f'{missed_backups} scheduled backup{"s" if missed_backups != 1 else ""} '
                      'did not succeed in time.', '#backups-title'))
    if queue and not queue['available']:
        items.append(('danger', 'mail', 'The mail queue cannot be read. Outgoing mail may be stopped.', '/monitoring/#mail-title'))
    elif queue and queue['stuck']:
        items.append(('danger', 'mail', f'Mail is stuck: {queue["count"]} message{"s" if queue["count"] != 1 else ""} waiting.',
                      '/monitoring/#mail-title'))
    if trend and trend['soon']:
        items.append(('warning', 'hard-drive', f'The disk may be full by {trend["full"].day} {trend["full"]:%B}.',
                      '/monitoring/#disk-title'))
    if site and site.get('available'):
        if site['blocked']:
            items.append(('warning', 'package', f'{site["blocked"]} update{"s" if site["blocked"] != 1 else ""} cannot install: '
                                                'the licence or download is missing.', '/monitoring/#wordpress-updates'))
        if site['cron']['overdue']:
            items.append(('warning', 'timer', f'{site["cron"]["overdue"]} WordPress scheduled task'
                                              f'{"s are" if site["cron"]["overdue"] != 1 else " is"} overdue.',
                          '/monitoring/#wordpress-title'))
        if len(site['updates']) > site['blocked']:
            pending = len(site['updates']) - site['blocked']
            items.append(('info', 'package', f'{pending} WordPress update{"s" if pending != 1 else ""} available.',
                          '/monitoring/#wordpress-updates'))
    elif site:
        items.append(('warning', 'circle-alert', 'WordPress health could not be read.', '/monitoring/#wordpress-title'))
    order = {'danger': 0, 'warning': 1, 'info': 2}
    found = [{'tone': tone, 'icon': icon, 'text': text, 'link': link}
             for tone, icon, text, link in sorted(items, key=lambda item: order[item[0]])]
    return {'problems': [item for item in found if item['tone'] != 'info'],
            'notes': [item for item in found if item['tone'] == 'info']}


def read(path, max_bytes):
    """A private JSON export, or None when it is missing, oversized or unreadable."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def presentation(path, window='1h', now=None):
    now = now or time.time()
    try:
        history = read(path, 2 * 1024 * 1024)
        selected = history['windows'][window]
        points = selected['points']
        if len(points) > 1000 or len(selected['routes']) > 50:
            raise ValueError('Oversized aggregate')
        stale = not 0 <= now - history['observed_at'] <= FRESH_SECONDS
        latest = {key: None for key in ('php_active', 'php_queue', 'php_limit_hits', 'opcache_free', 'opcache_restarts',
                                      'opcache_wasted', 'opcache_wasted_percent', 'opcache_full', 'opcache_scripts',
                                      'db_connections', 'db_running', 'disk_free', 'iowait')}
        latest.update(history.get('latest') or {})
        step = WINDOWS[window]['step']
        charts = [chart(points, key, title, unit, description, step, ceiling, empty)
                  for key, title, unit, description, ceiling, empty in CHARTS]
        routes = [dict(row, label=ROUTES.get(row['route'], row['route'].capitalize()),
                       cache_share=round(100 * row['hits'] / row['count'])) for row in selected['routes'] if row['count']]
        request_count = sum(row['count'] for row in routes)
        errors = sum(row['errors'] for row in routes)
        hits = sum(row['hits'] for row in routes)
        known = hits + sum(row['misses'] for row in routes)
        findings = []
        queue_peak = selected.get('php_queue_max')
        if queue_peak is not None and queue_peak > 0:
            findings.append(f'PHP had requests waiting in this period, up to {queue_peak} at once. That shows PHP was busy, not why.')
        if errors:
            findings.append(f'{errors:,} of {request_count:,} observed website requests returned a server error (HTTP 5xx). Check the page types and error groups below.')
        if latest.get('opcache_free') is not None and latest['opcache_free'] < 8 * 1024 * 1024:
            findings.append('PHP OPcache has less than 8 MB free. Check its restart counter and PHP configuration before changing its size.')
        if selected['gaps']:
            findings.append('Some request or error logs could not be read completely, so counts for this period are incomplete.')
        return {'history': history, 'window': selected, 'routes': routes, 'selected_window': window, 'latest': latest, 'stale': stale,
                'observed_at': moment(history['observed_at']), 'started_at': moment(history.get('started_at')),
                'charts': charts, 'interval': WINDOWS[window]['interval'], 'request_count': request_count, 'error_count': errors,
                'cache_percent': round(100 * hits / known, 1) if known else None, 'findings': findings,
                'request_trend': sparkline(points, 'requests', step), 'error_trend': sparkline(points, 'errors', step),
                'disk': disk(history.get('disk_trend'), now),
                'disk_history': sparkline(history['windows'].get('7d', {}).get('points', []), 'disk', COLLECTED['7d'][1], 100),
                'wordpress': wordpress(history.get('wordpress'), now),
                'service_changes': [dict(item, observed_at=moment(item['at']),
                                         title=(profile := service_profile(item['unit']))[1] or item['name'], icon=profile[2],
                                         before=state(item['before'])[0], after=state(item['after'])[0])
                                    for item in history.get('service_changes', [])]}
    except (OSError, ValueError, KeyError, TypeError, OverflowError, ZeroDivisionError):
        return {'history': None, 'selected_window': window}
