"""The Security page: the root collector's export beside the interface's own sign-in records.

Nothing here reads a server log or CloudPanel's database: CloudPanel, SSH and the
website's probes come from the bounded export of companion.security_log, the
Companion from its records.
"""
from companion import probe_guard, security_log
from . import signins
from .monitoring import bars, moment

TABS = {'companion': 'Companion', 'cloudpanel': 'CloudPanel', 'ssh': 'SSH', 'website': 'Website'}
TAB_ICONS = {'companion': 'layers', 'cloudpanel': 'server', 'ssh': 'terminal', 'website': 'globe'}
PATTERN_SOURCES = {'probe': 'Already blocked here', 'not-found': 'Missing page, not blocked'}
SOURCES = {'country': 'New country', 'ip': 'New IP'}
METHODS = {'password': 'Password', 'code': 'Two-factor code', 'key': 'Key', 'other': 'Other'}
PANEL_LOG = {
    'disconnected': "CloudPanel rewrote its vhost and dropped the Companion's access log, so failed CloudPanel "
                    'sign-ins and visits are not being recorded. Run sudo bash install.sh to connect it again.',
    'not-installed': "CloudPanel's access log is not connected, so failed CloudPanel sign-ins and visits are not "
                     "recorded. Run sudo bash install.sh: it connects the log when CloudPanel has a custom domain, "
                     'and otherwise says what stops it.',
}


def labelled(row):
    return {**row, 'when': moment(row['at']), 'country_name': security_log.country_label(row['country']),
            'source_label': SOURCES.get(row.get('new_source'), ''), 'method_label': METHODS.get(row.get('method'), '')}


def labelled_panel(summary):
    for key in ('signins', 'new_sources', 'bursts'):
        summary[key] = [labelled(row) for row in summary[key]]
    summary['failed_sources'] = [{**item, 'first': moment(item['first_at']), 'last': moment(item['last_at']),
                                  'country_name': security_log.country_label(item['country']),
                                  'step_labels': [METHODS[step] for step in item['steps'] if step in METHODS]}
                                 for item in summary['failed_sources']]
    summary['last'] = summary['signins'][0] if summary['signins'] else None
    labels = [moment(day['day']).strftime('%a') for day in summary['days']]
    summary['chart_signins'] = bars([day['signins'] for day in summary['days']], labels)
    summary['chart_failed'] = bars([day['failed'] for day in summary['days']], labels)
    return summary


def labelled_visits(visits):
    visits['days'] = [{**day, 'date': moment(day['day'])} for day in visits['days']]
    # The export lists days newest first; the chart reads left to right, oldest first.
    oldest_first = visits['days'][::-1]
    visits['chart'] = bars([day['requests'] for day in oldest_first], [day['date'].strftime('%a') for day in oldest_first])
    for key in ('countries', 'top_ips'):
        visits[key] = [{**item, 'country_name': security_log.country_label(item['country'])} for item in visits[key]]
    return visits


def labelled_probes(probes):
    labels = [moment(day['day']).strftime('%a') for day in probes['days']]
    probes['chart'] = bars([day['requests'] for day in probes['days']], labels)
    probes['today'] = probes['days'][-1]['requests']
    for key in ('top_sources', 'missing_sources'):
        probes[key] = [{**item, 'country_name': security_log.country_label(item['label'])} for item in probes[key]]
    # Current bans first, then the week's ended ones; a repeat offender's week-long ban began before the week shown.
    active = {(ban['ip'], ban['start']) for ban in probes['active']}
    probes['bans'] = [{**ban, 'active': (ban['ip'], ban['start']) in active, 'since': moment(ban['start']),
                       'until_at': moment(ban['until']), 'country_name': security_log.country_label(ban['country'])}
                      for ban in probes['active'] + [ban for ban in probes['recent'] if (ban['ip'], ban['start']) not in active]]
    probes['patterns']['conditions'] = [{**item, 'source_label': PATTERN_SOURCES[item['source']]}
                                        for item in probes['patterns']['conditions']]
    return probes


def presentation(export, now, tab, hosts):
    panels = {'companion': labelled_panel(signins.summary(now))}
    probes = labelled_probes(export['probes']) if export and export.get('probes') else None
    if export:
        panels.update((key, labelled_panel(export['panels'][key])) for key in ('cloudpanel', 'ssh'))
    attention = []
    for key, summary in panels.items():
        attention += [{'panel': TABS[key], 'kind': 'new-source', 'icon': 'map-pin', 'row': row} for row in summary['new_sources']]
        attention += [{'panel': TABS[key], 'kind': 'burst', 'icon': 'shield-alert', 'row': row} for row in summary['bursts']]
    attention.sort(key=lambda item: item['row']['at'], reverse=True)
    return {
        'export': export, 'tab': tab, 'tab_name': TABS[tab], 'tab_host': hosts.get(tab, ''),
        'attention': attention,
        'observed_at': moment(export['observed_at']) if export else None,
        'summary': [{'key': key, 'name': name, 'icon': TAB_ICONS[key], 'host': hosts.get(key, ''),
                     'data': probes if key == 'website' else panels.get(key)} for key, name in TABS.items()],
        'probes': probes,
        'ban_rule': probe_guard.RULE,
        'panel': panels.get(tab), 'panel_log_problem': PANEL_LOG.get(export['panel_log']) if export else None,
        'visits': labelled_visits(export['visits'][tab]) if export and tab in export['visits'] else None,
        'protection': export['protection'] if export else None,
        'unavailable': export['unavailable'] if export else [],
        'burst_minutes': security_log.BURST_WINDOW // 60,
        'thresholds': security_log.BURST_THRESHOLD,
    }
