"""Render evidence snapshots without filesystem or shell access to hosted sites."""
from pathlib import Path
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.http.request import split_domain_port
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from allauth.account.internal.flows.reauthentication import did_recently_reauthenticate
from companion.php_runtime import RECORD as UPKEEP_RECORD
from companion.relay import destination, normalize_policy
from companion.security_log import EXPORT_LIMIT as SECURITY_LIMIT, OUTPUT as SECURITY_EXPORT
from companion.telemetry import FRESH_SECONDS
from . import operations_client, security_page
from .monitoring import WINDOWS, attention, disk, endpoints, mail, presentation, read, resources, services, upkeep, wordpress


# Written every minute by companion-system-watch.service: services and scheduled backups.
SYSTEM_SNAPSHOT = Path('/var/lib/cloudpanel-companion-system-observations/latest.json')
# Written every minute by companion-telemetry.service.
HISTORY_EXPORT = Path('/var/lib/cloudpanel-companion-telemetry-observations/history.json')
BACKUP_STATES = {'succeeded': 'Succeeded', 'not-due-yet': 'Not due yet', 'job-script-missing': 'Job script missing'}
COMPARE_PHASES = {'queued': 'Starting the file check', 'scanning-website': 'Checking website files',
                  'scanning-staging': 'Checking staging files', 'comparing-code': 'Comparing the files'}
# A refresh as the operator follows it: the steps shown while it runs, and for each
# receipt phase what is happening and which step it belongs to (None once it ended).
REFRESH_STEPS = ('Prepare', 'Copy files', 'Copy database', 'Update URLs', 'Check the copy', 'Switch', 'Final check')
REFRESH_PHASES = {'queued': ('Starting refresh', 0), 'prepared': ('Preparing refresh', 0),
                  'new-database-created': ('Copying website files', 1), 'generation-prepared': ('Preparing the new database', 2),
                  'database-imported': ('Updating staging URLs', 3), 'clone-complete-acceptance-pending': ('Checking the prepared copy', 4),
                  'generation-ready': ('Preparing the switch', 4), 'exchange-intent': ('Switching staging versions', 5),
                  'generation-switched': ('Checking the new copy', 6), 'completed': ('Refresh complete', None),
                  'rolled-back': ('Previous copy restored', None), 'recovery-needs-review': ('Recovery needs attention', None)}
# Release phase: label and status tone, for both the history table and the review card.
RELEASE_PHASES = {'preview': ('Ready to review', 'info'), 'applying': ('Applying files', ''),
                  'completed': ('Applied and checked', 'success'), 'rolled-back': ('Previous code restored', ''),
                  'recovery-needs-review': ('Newer edits need review', 'danger'), 'not-applied': ('No code applied', ''),
                  'rejected-php-syntax': ('PHP check failed', 'danger')}


def https_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Only explicit HTTPS links are allowed')
    return value


def operate(request, operation, **values):
    """Run an operation attributed to the signed-in operator for the audit trail."""
    return operations_client.call(operation, actor=request.user.get_username(), **values)


def reauthenticate_url(next_path):
    return reverse('account_reauthenticate') + '?' + urlencode({'next': next_path})


def access_context(request, next_path):
    return {'access_unlocked': did_recently_reauthenticate(request), 'unlock_url': reauthenticate_url(next_path)}


def confirm_access_first(request, message, page):
    """Send the operator to confirm access before a protected change.

    Allauth's own guard suspends the POST in the session, which would retain a
    new staging password there; redirecting first stores nothing.
    """
    messages.info(request, message)
    return redirect(reauthenticate_url(reverse(page)))


def read_export(path, max_bytes):
    """Return a private JSON export, or None unless it is a current observation."""
    export = read(Path(path), max_bytes)
    try:
        return export if 0 <= time.time() - export['observed_at'] <= FRESH_SECONDS else None
    except (KeyError, TypeError):
        return None


def job_description(job):
    if not job:
        return None
    if job['operation'] == 'compare':
        if job['running']:
            return COMPARE_PHASES.get(job.get('phase'), 'Checking code changes')
        return 'File check did not finish. Try again in Releases.' if job['failed'] else 'File check complete'
    if job['operation'] == 'deploy':
        return 'Checking the code release' if job['running'] else ('Code release needs attention' if job['failed'] or job['blocked'] else 'Code release checked')
    if job['failed'] and job['phase'] == 'queued':
        return 'Refresh did not start'
    return REFRESH_PHASES.get(job['phase'], ('Refresh needs attention', None))[0]


def refresh_step(job):
    """The index of the refresh step under way, or None when no refresh is running."""
    if not job or job['operation'] != 'refresh' or not job['running']:
        return None
    return REFRESH_PHASES.get(job['phase'], ('', 0))[1]


@login_required
def dashboard(request):
    snapshot = read_export(settings.CONFIG['snapshot_path'], 262144)
    system = read_export(settings.CONFIG.get('system_snapshot_path', SYSTEM_SNAPSHOT), 65536)
    backups = [{**job, 'label': BACKUP_STATES.get(job.get('state'), 'Missed'),
                'last_success_at': datetime.fromtimestamp(job['last_success'], timezone.utc)
                if isinstance(job.get('last_success'), int) else None}
               for job in (system or {}).get('backups', [])]
    history = read_export(settings.CONFIG.get('history_path', HISTORY_EXPORT), 2 * 1024 * 1024) or {}
    now = time.time()
    site = urlsplit(settings.CONFIG['site_url']).hostname
    # Endpoint groups are headed by what each known domain is.
    checks = endpoints(snapshot['checks'] if snapshot else [], {
        site: 'Website', split_domain_port(request.get_host())[0]: 'Companion',
        urlsplit(settings.CONFIG['panel_url']).hostname: 'CloudPanel'})
    watched = services(system, site) if system else None
    trend = disk(history.get('disk_trend'), now)
    missed = sum(not job.get('healthy', False) for job in backups)
    items = attention(checks, watched, mail((system or {}).get('mail')), trend, wordpress(history.get('wordpress'), now), missed)
    return render(request, 'dashboard.html', {
        'snapshot': snapshot,
        'resources': resources(snapshot.get('resources') if snapshot else None, history),
        'checks': checks,
        'attention': items,
        'watched': watched,
        'disk': trend,
        'missed_backups': missed,
        'backups': backups,
        'system': system,
        'observed_at': datetime.fromtimestamp(snapshot['observed_at'], timezone.utc) if snapshot else None,
        'panel_url': https_url(settings.CONFIG['panel_url']),
        'site_url': https_url(settings.CONFIG['site_url']),
        'site_name': settings.CONFIG['site_name'],
    })


@login_required
def monitoring(request):
    window = request.GET.get('window')
    if window not in WINDOWS:
        window = '1h'
    system = read_export(settings.CONFIG.get('system_snapshot_path', SYSTEM_SNAPSHOT), 65536)
    return render(request, 'monitoring.html', {
        **presentation(Path(settings.CONFIG.get('history_path', HISTORY_EXPORT)), window), 'windows': WINDOWS,
        'system': system, 'watched': services(system or {}, urlsplit(settings.CONFIG['site_url']).hostname), 'mail': mail((system or {}).get('mail')),
        'upkeep': upkeep(read(Path(settings.CONFIG.get('upkeep_path', UPKEEP_RECORD)), 4096))})



@login_required
def security(request):
    tab = request.GET.get('panel')
    if tab not in security_page.TABS:
        tab = 'companion'
    export = read_export(settings.CONFIG.get('security_path', SECURITY_EXPORT), SECURITY_LIMIT)
    hosts = {'companion': settings.CONFIG['host'], 'cloudpanel': urlsplit(settings.CONFIG['panel_url']).hostname,
             'website': urlsplit(settings.CONFIG['site_url']).hostname}
    return render(request, 'security.html', security_page.presentation(export, int(time.time()), tab, hosts))


@login_required
def staging(request):
    status, error = None, None
    try:
        status = operations_client.call('status')
    except (OSError, ValueError, KeyError):
        error = 'Staging controls are unavailable. No change has been made.'
    job = status.get('job') if status else None
    access = access_context(request, reverse('staging'))
    step = refresh_step(job)
    steps = None if step is None else [{'label': label, 'state': 'done' if index < step else 'current' if index == step else 'pending'}
                                       for index, label in enumerate(REFRESH_STEPS)]
    return render(request, 'staging.html', {'staging': status, 'error': error, 'job': job, 'steps': steps,
                                           'job_label': job_description(job), **access,
                                           # Masked only while confirming access would make the controls usable.
                                           'locked': not access['access_unlocked'] and not (job and (job['running'] or job['blocked']))})


@login_required
def staging_job_status(request):
    try:
        job = operations_client.call('status').get('job')
        return JsonResponse({'job': job, 'label': job_description(job), 'step': refresh_step(job)})
    except (OSError, ValueError, KeyError):
        return JsonResponse({'error': 'Current workflow status is unavailable.'}, status=503)


@login_required
@require_POST
def staging_change(request):
    operation = request.POST.get('operation')
    json_request = request.headers.get('Accept') == 'application/json'
    enabled = request.POST.get('enabled') == 'true'
    sensitive = operation in ('password', 'refresh') or (operation == 'protection' and not enabled)
    if sensitive and not did_recently_reauthenticate(request):
        if json_request:
            return JsonResponse({'error': 'Unlock changes again before allowing public access.',
                                 'reauthenticate': reauthenticate_url(reverse('staging'))}, status=403)
        return confirm_access_first(request, 'Confirm access, then submit the staging change again.', 'staging')
    try:
        if operation in ('pause', 'protection'):
            # An unchecked protection switch submits no value when posted without script.
            if request.POST.get('enabled') not in (('true', 'false', None) if operation == 'protection' else ('true', 'false')):
                raise ValueError('Choose an explicit state')
            operate(request, operation, enabled=enabled)
        elif operation == 'password':
            operate(request, 'password', password=request.POST.get('password', ''))
        elif operation == 'refresh':
            if request.POST.get('confirm_refresh') != 'yes':
                raise ValueError('Confirm that the current staging copy may be replaced')
            operate(request, 'refresh', confirmed=True)
        else:
            raise ValueError('Unsupported staging action')
        if json_request:
            status = operations_client.call('status')
            return JsonResponse({'protected': status['protected'], 'paused': status['paused']})
        messages.success(request, 'Refresh started.' if operation == 'refresh' else 'Staging settings saved.')
    except (OSError, ValueError, KeyError) as error:
        if json_request:
            return JsonResponse({'error': 'The access setting could not be verified. Reload to check its current state.'}, status=503)
        messages.error(request, str(error) if isinstance(error, ValueError) else 'Staging operation failed. Check its current state before retrying.')
    return redirect('staging')


def rule_text(rules):
    return '\n'.join(method + ' https://' + rule['host'] + rule['path'] for rule in rules for method in rule['methods'])


def parse_rules(text):
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 2:
            raise ValueError('List each destination as a method and an HTTPS URL, for example GET https://example.com/test.')
        parsed = destination(parts[1])
        if parsed.query:
            raise ValueError('List a destination path without a query string.')
        rows.append({'host': parsed.hostname, 'path': parsed.path or '/', 'methods': [parts[0].upper()]})
    return rows


def external_context(request, status, error=None, draft=None):
    policy = status.get('external', {}) if status else {}
    values = draft if draft is not None else {
        'mail_recipients': '\n'.join(policy.get('mail_recipients', [])),
        'http_rules': rule_text(policy.get('http_rules', [])),
        'webhook_rules': rule_text(policy.get('webhook_rules', [])),
    }
    controls = [
        {'id': 'mail-enabled', 'flag': 'mail_enabled', 'title': 'Test emails', 'icon': 'mail',
         'off': 'All outgoing emails are blocked.', 'on': 'Approved emails are captured here. Nothing is delivered.',
         'field': 'mail_recipients', 'field_id': 'test-recipients', 'label': 'Approved test addresses',
         'help': 'One address per line. Other recipients remain blocked. Attachments are blocked.', 'example': 'you@example.com', 'limit': 2560},
        {'id': 'http-enabled', 'flag': 'http_enabled', 'title': 'External requests', 'icon': 'send',
         'off': 'No general HTTPS destinations are approved.', 'on': 'Only the approved HTTPS destinations below are allowed.',
         'field': 'http_rules', 'field_id': 'http-rules', 'label': 'Approved methods and test URLs',
         'help': 'One method and URL per line. Listed paths include subpaths. Redirects are blocked.', 'example': 'GET https://example.com/test-api', 'limit': 5000},
        {'id': 'webhooks-enabled', 'flag': 'webhooks_enabled', 'title': 'WooCommerce webhooks', 'icon': 'webhook',
         'off': 'WooCommerce webhook delivery is blocked.', 'on': 'WooCommerce webhooks may use approved test destinations.',
         'field': 'webhook_rules', 'field_id': 'webhook-rules', 'label': 'Approved methods and test URLs',
         'help': 'Use sandbox endpoints only. Approved HTTPS destinations are shared with external requests. Scheduled jobs and payments stay off.', 'example': 'POST https://example.com/test-webhook', 'limit': 5000},
    ]
    for control in controls:
        control['enabled'] = policy.get(control['flag'], False)
        control['value'] = values.get(control['field'], '')
    return {'staging': status, 'error': error, 'controls': controls,
            'any_enabled': any(item['enabled'] for item in controls), 'unsaved': draft is not None,
            **access_context(request, reverse('staging_external'))}


@login_required
def staging_external(request):
    status, error = None, None
    try:
        status = operations_client.call('status')
    except (OSError, ValueError, KeyError):
        error = 'Staging controls are unavailable. External tests cannot be changed.'
    return render(request, 'staging_external.html', external_context(request, status, error))


@login_required
@require_POST
def staging_external_change(request):
    stop = request.POST.get('operation') == 'external_stop'
    if not stop and not did_recently_reauthenticate(request):
        return confirm_access_first(request, 'Confirm access, then save the external test settings again.', 'staging_external')
    status = None
    enabled = {name: request.POST.get(name) == 'yes' for name in ('http_enabled', 'webhooks_enabled', 'mail_enabled')}
    try:
        if stop:
            operate(request, 'external_stop')
        else:
            status = operations_client.call('status')
            previous = status['external']
            # A switched-off category keeps its saved list; its hidden field is not trusted.
            policy = normalize_policy({
                **enabled,
                'http_rules': parse_rules(request.POST.get('http_rules', '')) if enabled['http_enabled'] else previous.get('http_rules', []),
                'webhook_rules': parse_rules(request.POST.get('webhook_rules', '')) if enabled['webhooks_enabled'] else previous.get('webhook_rules', []),
                'mail_recipients': ([line.strip() for line in request.POST.get('mail_recipients', '').splitlines() if line.strip()]
                                    if enabled['mail_enabled'] else previous.get('mail_recipients', [])),
            }, set(status['protected_hosts']))
            operate(request, 'external', policy=policy)
        messages.success(request, 'All external tests are off.' if stop else 'External test settings saved.')
    except (OSError, ValueError, KeyError) as error:
        explanation = str(error) if isinstance(error, ValueError) else 'The external test settings could not be saved.'
        if status and not stop:
            status['external'] = {**status['external'], **enabled}
            return render(request, 'staging_external.html', external_context(request, status, explanation, request.POST), status=400)
        messages.error(request, explanation)
    return redirect('staging_external')


@login_required
def staging_inbox(request):
    inbox, selected, error = [], None, None
    try:
        inbox = operate(request, 'mail_list')['messages']
        if request.GET.get('message'):
            selected = operate(request, 'mail_read', id=request.GET['message'])
    except (OSError, ValueError, KeyError):
        error = 'The test inbox is unavailable or the selected message has expired.'
    return render(request, 'staging_inbox.html', {'inbox': inbox, 'selected': selected, 'error': error})


@login_required
def releases(request):
    items, selected, job, error = [], None, None, None
    try:
        status = operate(request, 'release_status')
        items, job = status['releases'], status['job']
        for item in items:
            item['expired'] = item['expires_at'] < int(time.time())
            item['created'] = datetime.fromtimestamp(item['created_at'], timezone.utc)
            item['mine'] = item['actor'] == request.user.get_username()
            item['label'], item['tone'] = RELEASE_PHASES.get(item['phase'], ('Needs review', ''))
            if job and job['running'] and job.get('token') == item['token']:
                item['label'] = 'Checking release'
            if item['token'] == request.GET.get('preview'):
                selected = {**item, **operate(request, 'release_detail', token=item['token'])}
                selected['changed'] = selected['changed_count'] > 0
    except (OSError, ValueError, KeyError):
        error = 'Code releases are unavailable. No files have been changed.'
    return render(request, 'releases.html', {'releases': items, 'selected': selected, 'job': job, 'error': error,
                                            **access_context(request, request.get_full_path())})


@login_required
def comparison_status(request):
    try:
        result = operate(request, 'comparison_status')
        return JsonResponse({**result, 'label': job_description(result.get('job'))})
    except (OSError, ValueError, KeyError):
        return JsonResponse({'error': 'The file check is unavailable. Your files have not changed. Try again shortly.'}, status=503)


@login_required
def comparison_detail(request):
    try:
        return JsonResponse(operate(request, 'comparison_detail', folder=request.GET.get('folder', ''),
                                    page=int(request.GET.get('page', '1')), generation=request.GET.get('generation', '')))
    except (OSError, ValueError, KeyError):
        return JsonResponse({'error': 'These results are no longer available. Check changes again to continue.'}, status=409)


@login_required
@require_POST
def comparison_start(request):
    try:
        return JsonResponse(operate(request, 'compare'), status=202)
    except (OSError, ValueError, KeyError):
        return JsonResponse({'error': 'The check could not start. Wait for any current workflow to finish, then try again.'}, status=409)


@login_required
@require_POST
def release_change(request):
    operation = request.POST.get('operation')
    if operation in ('release_apply', 'release_recover') and not did_recently_reauthenticate(request):
        return confirm_access_first(request, 'Confirm access, then submit the reviewed release again.', 'releases')
    try:
        if operation == 'release_preview':
            selection = request.POST.get('files', '')
            if len(selection) > 50000:
                raise ValueError('Choose a smaller group of files for this release.')
            record = operate(request, operation, files=[line.strip() for line in selection.splitlines() if line.strip()])
            return redirect(reverse('releases') + '?' + urlencode({'preview': record['token']}))
        if operation == 'release_discard':
            operate(request, operation, token=request.POST.get('token', ''))
            messages.success(request, 'Unapplied preview removed.')
            return redirect('releases')
        if operation not in ('release_apply', 'release_recover'):
            raise ValueError('Choose a supported release action.')
        if request.POST.get('confirmed') != 'yes':
            raise ValueError('Confirm the selected code change before continuing.')
        operate(request, operation, token=request.POST.get('token', ''), confirmed=True)
        messages.success(request, 'Code recovery started.' if operation == 'release_recover' else 'Selected-code release started.')
    except (OSError, ValueError, KeyError) as error:
        messages.error(request, str(error) if isinstance(error, ValueError) else 'The release could not be started. No new approval was granted.')
    return redirect('releases')
