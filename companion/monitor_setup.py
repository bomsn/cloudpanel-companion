"""Build repeatable monitoring configuration without replacing operator choices.

The native website registry owns the origin/health identities. Installation can
merge those checks and known installed services; it never discovers HTTP targets
from customer content or gives browser callers control of recovery services.
"""
import copy
import hashlib
import re
from urllib.parse import urlsplit
from .health import Target
from .site_trust import bundle_path
from .staging import HOSTNAME


def site_label(host):
    return host if len(host) <= 80 else host[:64] + '...' + hashlib.sha256(host.encode()).hexdigest()[:8]


def origin_targets(targets, host):
    """Checks that meet the website's own certificate: HTTPS to it through the local origin.

    A check without a connect address meets whatever ends the visitor's HTTPS
    (Cloudflare's edge, for example) and keeps the system store.
    """
    return [target for target in targets if target.get('connect_host') == '127.0.0.1' and
            urlsplit(target['url']).scheme == 'https' and urlsplit(target['url']).hostname == host]


def origin_trust(targets, host, site_ca):
    """Give the website's origin checks its installed certificate authority, or the system store.

    Only the managed bundle is added or removed. An operator's own ca_file on an
    origin check stays while the system store applies and conflicts otherwise.
    """
    managed = str(bundle_path(host))
    for target in origin_targets(targets, host):
        if target.get('ca_file') not in (None, managed):
            if site_ca:
                raise ValueError('An origin check already trusts another certificate authority')
            continue
        if site_ca:
            target['ca_file'] = managed
        else:
            target.pop('ca_file', None)


def origin_trust_pending(config, host, site_ca):
    """Whether the monitoring configuration still needs the website's current trust applied."""
    targets = copy.deepcopy(config.get('targets', []))
    try:
        origin_trust(targets, host, site_ca)
    except ValueError:
        return True
    return targets != config.get('targets', [])


def certificate_hosts(web):
    """Domains of the Companion interface and the CloudPanel address, from the interface's configuration.

    Their certificates are watched alongside the website's checks. A panel reached by
    IP address or on a non-default port has no domain certificate to watch.
    """
    panel = urlsplit(web['panel_url'])
    hosts = [web['host']] + ([panel.hostname] if panel.scheme == 'https' and panel.port is None else [])
    return [host for host in dict.fromkeys(hosts) if host and re.fullmatch(HOSTNAME, host)]


def certificate_target(host):
    return {'name': site_label(host) + ': certificate', 'url': 'https://' + host + '/',
            'connect_host': '127.0.0.1', 'certificate_only': True}


def certificates_pending(config, hosts):
    """Whether a watched domain still lacks its certificate check."""
    watched = {(target.get('url'), target.get('certificate_only', False)) for target in config.get('targets', [])}
    return any(('https://' + host + '/', True) not in watched for host in hosts)


def endpoint_configuration(existing, host, application=None, database=None, site_ca=False, certificates=()):
    """Merge the website's origin checks and the certificate checks of `certificates` (domains).

    site_ca: the website's certificate authority bundle is installed.
    """
    if not re.fullmatch(HOSTNAME, host) or any(not re.fullmatch(HOSTNAME, item) for item in certificates):
        raise ValueError('Explicit website hostname required')
    result = copy.deepcopy(existing) if existing is not None else {'failure_threshold': 2, 'targets': []}
    if set(result) - {'failure_threshold', 'targets'} or not isinstance(result.get('targets'), list):
        raise ValueError('Invalid monitoring configuration')
    threshold = result.get('failure_threshold', 2)
    if type(threshold) is not int or not 1 <= threshold <= 10:
        raise ValueError('Invalid monitoring failure threshold')
    candidates = [{'name': site_label(host) + ': page HTML', 'url': 'https://' + host + '/',
                   'connect_host': '127.0.0.1', 'expected_statuses': [200]}]
    if application is not None:
        if (not re.fullmatch(r'companion-origin-[a-f0-9]{32}[.]php', application) or
                not isinstance(database, str) or not re.fullmatch(r'[a-z][a-z0-9_]{2,47}', database)):
            raise ValueError('Registered application identity required')
        candidates.append({'name': site_label(host) + ': application and database',
                           'url': 'https://' + host + '/' + application, 'connect_host': '127.0.0.1',
                           'expected_statuses': [200], 'expected_json': {
                               'ready': True, 'database_identity': hashlib.sha256(database.encode()).hexdigest()}})
    candidates += [certificate_target(item) for item in certificates if item != host]
    # Earlier versions called the page check "origin HTML"; it keeps its target under the plain name.
    renamed = {site_label(host) + ': origin HTML': candidates[0]['name']}
    for target in result['targets']:
        Target(**target).validate()
    for candidate in candidates:
        matches = [target for target in result['targets']
                   if target['url'] == candidate['url'] and target.get('connect_host') == '127.0.0.1' and
                   target.get('certificate_only', False) == candidate.get('certificate_only', False)]
        if matches:
            for target in matches:
                target['name'] = renamed.get(target['name'], target['name'])
                if tuple(target.get('expected_statuses', (200,))) != (200,):
                    raise ValueError('An origin check already has conflicting accepted statuses')
                if 'expected_json' in candidate:
                    expected = target.get('expected_json') or {}
                    if any(key in expected and (type(expected[key]) is not type(value) or expected[key] != value)
                           for key, value in candidate['expected_json'].items()):
                        raise ValueError('An application check already has conflicting expectations')
                    target['expected_json'] = {**expected, **candidate['expected_json']}
        else:
            if any(target['name'] == candidate['name'] for target in result['targets']):
                raise ValueError('An origin check name belongs to another target')
            result['targets'].append(candidate)
    origin_trust(result['targets'], host, site_ca)
    if not 1 <= len(result['targets']) <= 50 or len({target['name'] for target in result['targets']}) != len(result['targets']):
        raise ValueError('Monitoring requires unique names and at most fifty targets')
    for target in result['targets']:
        Target(**target).validate()
    return result


# Units earlier versions registered under a label that belongs to another unit:
# CloudPanel's own PHP is clp-php-fpm.service, not the stock PHP 8.1 pool, which
# an operator may disable together with the other unused PHP versions. Each maps to
# the legacy unit and the plain name its label then ended with.
CORRECTED_UNITS = {'clp-php-fpm.service': ('php8.1-fpm.service', 'CloudPanel PHP')}


def validate_units(units):
    """The service watch registry: unique units and labels, each with an explicit recovery choice."""
    if not isinstance(units, list):
        raise ValueError('Invalid service monitoring configuration')
    for unit in units:
        if (not isinstance(unit, dict) or set(unit) != {'name', 'label', 'recover'} or
                not isinstance(unit['name'], str) or not re.fullmatch(r'[a-zA-Z0-9@_.-]{1,100}\.service', unit['name']) or
                not isinstance(unit['label'], str) or not 1 <= len(unit['label']) <= 150 or
                type(unit['recover']) is not bool):
            raise ValueError('Invalid registered service')
    if (not 1 <= len(units) <= 20 or len({unit['name'] for unit in units}) != len(units) or
            len({unit['label'] for unit in units}) != len(units)):
        raise ValueError('Service monitoring requires unique names/labels and at most twenty units')


def service_configuration(existing, candidates, enable_recovery=False):
    result = copy.deepcopy(existing) if existing is not None else {'units': []}
    if set(result) != {'units'} or not isinstance(result['units'], list):
        raise ValueError('Invalid service monitoring configuration')
    for name, label in candidates:
        legacy, legacy_title = CORRECTED_UNITS.get(name, (None, None))
        if legacy and not any(unit['name'] == name for unit in result['units']):
            # The installer's label then was the same site prefix and the legacy plain name.
            prefix, separator, _ = label.rpartition(': ')
            for unit in result['units']:
                if unit['name'] == legacy and unit['label'] == prefix + separator + legacy_title:
                    unit['name'] = name  # keeps the operator's recovery choice and label
    for name, label in candidates:
        if any(unit['name'] == name for unit in result['units']):
            continue
        result['units'].append({'name': name, 'label': label, 'recover': bool(enable_recovery)})
    validate_units(result['units'])
    return result


# How the interface groups watched units, in display order: group, heading and icon.
# A 'site' unit is installed for one website (its private Redis, its staging copy's
# relay), and install-monitor.py registers those only for the website this interface
# serves, so that group is headed by the website's domain. Every other group is shared
# by the whole server, and the Companion's own components and jobs come last.
SERVICE_GROUPS = (('site', None, 'globe'), ('web', 'Web server and PHP', 'server'), ('database', 'Database', 'database'),
                  ('cache', 'Caches', 'zap'), ('protection', 'Server protection', 'shield'),
                  ('other', 'Other services', 'server'), ('companion', 'Companion services', 'layers'),
                  ('scheduled', 'Scheduled jobs', 'timer'))
# The package's timers: plain name and what each job does. The service watch
# observes whichever of them are installed.
TIMERS = {
    'companion-monitor.timer': ('Website and certificate checks', 'Checks the website and certificates every minute.'),
    'companion-delivery.timer': ('Website alerts to Slack', 'Sends website and certificate alerts to Slack.'),
    'companion-system-watch.timer': ('Service checks', 'Checks services, scheduled jobs, mail and backups every minute.'),
    'companion-system-delivery.timer': ('Service alerts to Slack', 'Sends service, mail and backup alerts to Slack.'),
    'companion-telemetry.timer': ('Performance history', 'Records server and request history every minute, and WordPress health hourly.'),
    'companion-retention.timer': ('Staging cleanup', 'Removes old staging copies when automatic cleanup is on.'),
    'companion-security-log.timer': ('Sign-in and visit history', 'Records sign-ins, panel visits and blocked scans for the Security page every minute.'),
    'companion-opcache-upkeep.timer': ('Nightly OPcache check', 'Reloads PHP-FPM gracefully when OPcache is full or wastes '
                                                                '10% or more of its memory.'),
}
# Every unit an installer registers, by unit-name pattern: group, the product's own
# name (a pattern group fills {0}), its icon in static/icons.svg and what it does.
# Products with a brand mark use it; the rest use a Lucide icon. Installers label new
# registrations "<website>: <name>" because labels name alerts; the interface shows
# and describes each watched unit only from here.
SERVICES = (
    (r'nginx\.service', 'web', 'NGINX', 'nginx', 'Receives every visitor request and serves the websites.'),
    (r'php(8\.[0-9])-fpm\.service', 'web', 'PHP-FPM {0}', 'php',
     'Runs the PHP pools of the websites on this version, including WordPress pages not served from cache.'),
    (r'clp-php-fpm\.service', 'web', 'CloudPanel (PHP-FPM)', 'php', 'Runs the CloudPanel control panel.'),
    (r'mariadb\.service', 'database', 'MariaDB', 'mariadb', "Stores the websites' content, orders and settings."),
    (r'mysql\.service', 'database', 'MySQL', 'mysql', "Stores the websites' content, orders and settings."),
    (r'varnish\.service', 'cache', 'Varnish Cache', 'zap', 'Serves saved copies of pages to visitors.'),
    (r'cache-manager-control\.service', 'cache', 'Cache clearing', 'refresh-cw', 'Clears saved pages when content changes.'),
    (r'fail2ban\.service', 'protection', 'Fail2ban', 'shield', 'Bans addresses that keep failing to sign in over SSH or keep scanning the website for secret files.'),
    (r'companion-redis-[a-z][a-z0-9-]*\.service', 'site', 'Redis', 'redis',
     "Keeps this website's WordPress data in memory between requests."),
    (r'companion-relay@[a-z][a-z0-9-]*\.service', 'site', 'Staging email and test requests', 'send',
     'Captures staging email and passes on approved test requests.'),
    (r'companion-web\.service', 'companion', 'Web interface', 'layout-dashboard', "Serves the Companion's pages."),
    (r'companion-security-cache\.service', 'companion', 'Sign-in sessions', 'lock-keyhole',
     'Keeps sign-in sessions and sign-in rate limits for the Companion.'),
    (r'companion-operations\.service', 'companion', 'Staging and release actions', 'cpu', 'Carries out staging and release changes.'),
) + tuple((re.escape(name), 'scheduled', title, 'timer', description) for name, (title, description) in TIMERS.items())


def service_profile(unit):
    """(group, plain name, icon, description) of a unit; an operator's own unit is 'other'."""
    for pattern, group, title, icon, description in SERVICES:
        match = re.fullmatch(pattern, unit)
        if match:
            return group, title.format(*match.groups()), icon, description
    return 'other', None, 'server', None
