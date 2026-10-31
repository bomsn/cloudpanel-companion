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


def endpoint_configuration(existing, host, application=None, database=None, site_ca=False):
    """Merge the website's origin checks; site_ca: its certificate authority bundle is installed."""
    if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', host):
        raise ValueError('Explicit website hostname required')
    result = copy.deepcopy(existing) if existing is not None else {'failure_threshold': 2, 'targets': []}
    if set(result) - {'failure_threshold', 'targets'} or not isinstance(result.get('targets'), list):
        raise ValueError('Invalid monitoring configuration')
    threshold = result.get('failure_threshold', 2)
    if type(threshold) is not int or not 1 <= threshold <= 10:
        raise ValueError('Invalid monitoring failure threshold')
    candidates = [{'name': site_label(host) + ': origin HTML', 'url': 'https://' + host + '/',
                   'connect_host': '127.0.0.1', 'expected_statuses': [200]}]
    if application is not None:
        if (not re.fullmatch(r'companion-origin-[a-f0-9]{32}[.]php', application) or
                not isinstance(database, str) or not re.fullmatch(r'[a-z][a-z0-9_]{2,47}', database)):
            raise ValueError('Registered application identity required')
        candidates.append({'name': site_label(host) + ': application and database',
                           'url': 'https://' + host + '/' + application, 'connect_host': '127.0.0.1',
                           'expected_statuses': [200], 'expected_json': {
                               'ready': True, 'database_identity': hashlib.sha256(database.encode()).hexdigest()}})
    for target in result['targets']:
        Target(**target).validate()
    for candidate in candidates:
        matches = [target for target in result['targets']
                   if target['url'] == candidate['url'] and target.get('connect_host') == '127.0.0.1']
        if matches:
            for target in matches:
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
# an operator may disable together with the other unused PHP versions.
CORRECTED_UNITS = {'clp-php-fpm.service': 'php8.1-fpm.service'}


def service_configuration(existing, candidates, enable_recovery=False):
    result = copy.deepcopy(existing) if existing is not None else {'units': []}
    if set(result) != {'units'} or not isinstance(result['units'], list):
        raise ValueError('Invalid service monitoring configuration')
    for name, label in candidates:
        legacy = CORRECTED_UNITS.get(name)
        if legacy and not any(unit['name'] == name for unit in result['units']):
            for unit in result['units']:
                if unit['name'] == legacy and unit['label'] == label:
                    unit['name'] = name  # keeps the operator's recovery choice
    for name, label in candidates:
        if any(unit['name'] == name for unit in result['units']):
            continue
        result['units'].append({'name': name, 'label': label, 'recover': bool(enable_recovery)})
    for unit in result['units']:
        if (set(unit) != {'name', 'label', 'recover'} or
                not re.fullmatch(r'[a-zA-Z0-9@_.-]{1,100}\.service', unit['name']) or
                not isinstance(unit['label'], str) or not 1 <= len(unit['label']) <= 150 or
                type(unit['recover']) is not bool):
            raise ValueError('Invalid registered service')
    if (not 1 <= len(result['units']) <= 20 or
            len({unit['name'] for unit in result['units']}) != len(result['units']) or
            len({unit['label'] for unit in result['units']}) != len(result['units'])):
        raise ValueError('Service monitoring requires unique names/labels and at most twenty units')
    return result
