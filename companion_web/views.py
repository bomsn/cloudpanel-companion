"""Render evidence snapshots without filesystem or shell access to hosted sites."""
import json
from pathlib import Path
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib import messages
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from allauth.account.internal.flows.reauthentication import did_recently_reauthenticate


# Written every minute by companion-system-watch.service: services and scheduled backups.
SYSTEM_SNAPSHOT = Path('/var/lib/cloudpanel-companion-system-observations/latest.json')


def https_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Only explicit HTTPS links are allowed')
    return value


def job_description(job):
    if not job:
        return None
    if job['operation'] == 'compare':
        return 'Checking code differences' if job['running'] else ('File check did not finish. Try again in Releases.' if job['failed'] else 'File check complete')
    if job['operation'] == 'deploy':
        return 'Checking the code release' if job['running'] else ('Code release needs attention' if job['failed'] or job['blocked'] else 'Code release checked')
    phases = {'prepared': 'Preparing refresh', 'new-database-created': 'Copying website files',
              'generation-prepared': 'Preparing the new database', 'database-imported': 'Updating staging URLs',
              'clone-complete-acceptance-pending': 'Checking the prepared copy', 'generation-ready': 'Preparing the switch',
              'exchange-intent': 'Switching staging versions', 'generation-switched': 'Checking the new copy',
              'completed': 'Refresh complete', 'rolled-back': 'Previous copy restored',
              'recovery-needs-review': 'Recovery needs attention', 'queued': 'Starting refresh'}
    if job['failed'] and job['phase'] == 'queued':
        return 'Refresh did not start'
    return phases.get(job['phase'], 'Refresh needs attention')


@login_required
def dashboard(request):
    snapshot = None
    system = None
    try:
        path = Path(settings.CONFIG['snapshot_path'])
        if path.stat().st_size > 262144:
            raise ValueError('Snapshot too large')
        snapshot = json.loads(path.read_text())
        if time.time() - snapshot['observed_at'] > 180 or snapshot['observed_at'] > time.time() + 30:
            snapshot = None
    except (OSError, ValueError, KeyError, TypeError):
        snapshot = None
    try:
        path = Path(settings.CONFIG.get('system_snapshot_path', SYSTEM_SNAPSHOT))
        if path.stat().st_size > 65536:
            raise ValueError('System snapshot too large')
        system = json.loads(path.read_text())
        if not 0 <= time.time() - system['observed_at'] <= 180:
            system = None
    except (OSError, ValueError, KeyError, TypeError):
        system = None
    backups = []
    for job in (system or {}).get('backups', []):
        backups.append({**job, 'last_success_at': datetime.fromtimestamp(job['last_success'], timezone.utc)
                        if isinstance(job.get('last_success'), int) else None})
    return render(request, 'dashboard.html', {
        'snapshot': snapshot,
        'unhealthy_checks': sum(not check.get('healthy', False) for check in snapshot.get('checks', [])) if snapshot else None,
        'unhealthy_services': sum(service.get('state') != 'active' for service in system.get('services', [])) if system else None,
        'missed_backups': sum(not job.get('healthy', False) for job in backups),
        'backups': backups,
        'system': system,
        'observed_at': datetime.fromtimestamp(snapshot['observed_at'], timezone.utc) if snapshot else None,
        'panel_url': https_url(settings.CONFIG['panel_url']),
        'site_url': https_url(settings.CONFIG['site_url']),
        'site_name': settings.CONFIG['site_name'],
    })


@login_required
def monitoring(request):
    from .monitoring import presentation
    window = request.GET.get('window', '1h')
    if window not in ('1h', '24h', '7d'):
        window = '1h'
    return render(request, 'monitoring.html', presentation(
        Path(settings.CONFIG.get('history_path', '/var/lib/cloudpanel-companion-telemetry-observations/history.json')), window))


@login_required
def staging(request):
    from .operations_client import call
    status, error = None, None
    try:
        status = call('status')
    except (OSError, ValueError, KeyError):
        error = 'Staging controls are unavailable. No change has been made.'
    job = status.get('job') if status else None
    return render(request, 'staging.html', {'staging': status, 'error': error, 'job': job,
                                           'job_label': job_description(job),
                                           'access_unlocked': did_recently_reauthenticate(request)})


@login_required
def staging_job_status(request):
    from .operations_client import call
    try:
        status = call('status')
        job = status.get('job')
        return JsonResponse({'job': job, 'label': job_description(job),
                             'access': {'protected': status['protected'], 'paused': status['paused']}})
    except (OSError, ValueError, KeyError):
        return JsonResponse({'error': 'Current workflow status is unavailable.'}, status=503)


@login_required
@require_POST
def staging_change(request):
    from .operations_client import call
    operation = request.POST.get('operation')
    json_request = request.headers.get('Accept') == 'application/json'
    protected = request.POST.get('enabled') == 'true'
    sensitive = operation in ('password', 'refresh') or (operation == 'protection' and not protected)
    if sensitive and not did_recently_reauthenticate(request):
        # Redirect before allauth can serialize a suspended POST, so a new
        # staging password is never retained in the session database.
        if json_request:
            return JsonResponse({'error': 'Unlock changes again before allowing public access.',
                                 'reauthenticate': '/accounts/reauthenticate/?next=/staging/'}, status=403)
        messages.info(request, 'Confirm access, then submit the staging change again.')
        return redirect('/accounts/reauthenticate/?next=/staging/')
    try:
        if operation in ('pause', 'protection'):
            if request.POST.get('enabled') not in (('true', 'false', None) if operation == 'protection' else ('true', 'false')):
                raise ValueError('Choose an explicit state')
            call(operation, enabled=protected, actor=request.user.get_username())
        elif operation == 'password':
            call('password', password=request.POST.get('password', ''), actor=request.user.get_username())
        elif operation == 'refresh':
            if request.POST.get('confirm_refresh') != 'yes':
                raise ValueError('Confirm that the current staging copy may be replaced')
            call('refresh', confirmed=True, actor=request.user.get_username())
        else:
            raise ValueError('Unsupported staging action')
        if json_request:
            status = call('status')
            return JsonResponse({'protected': status['protected'], 'paused': status['paused']})
        messages.success(request, 'Refresh started.' if operation == 'refresh' else 'Staging settings saved.')
    except (OSError, ValueError, KeyError) as error:
        if json_request:
            return JsonResponse({'error': 'The access setting could not be verified. Reload to check its current state.'}, status=503)
        messages.error(request, str(error) if isinstance(error, ValueError) else 'Staging operation failed. Check its current state before retrying.')
    return redirect('staging')


def rule_text(rules):
    return '\n'.join(method + ' https://' + rule['host'] + rule['path'] for rule in rules for method in rule['methods'])


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
        {'id': 'http-enabled', 'flag': 'http_enabled', 'title': 'External requests', 'icon': 'globe',
         'off': 'No general HTTPS destinations are approved.', 'on': 'Only the approved HTTPS destinations below are allowed.',
         'field': 'http_rules', 'field_id': 'http-rules', 'label': 'Approved methods and test URLs',
         'help': 'One method and URL per line. Listed paths include subpaths. Redirects are blocked.', 'example': 'GET https://example.com/test-api', 'limit': 5000},
        {'id': 'webhooks-enabled', 'flag': 'webhooks_enabled', 'title': 'WooCommerce webhooks', 'icon': 'send',
         'off': 'WooCommerce webhook delivery is blocked.', 'on': 'WooCommerce webhooks may use approved test destinations.',
         'field': 'webhook_rules', 'field_id': 'webhook-rules', 'label': 'Approved methods and test URLs',
         'help': 'Use sandbox endpoints only. Approved HTTPS destinations are shared with external requests. Scheduled jobs and payments stay off.', 'example': 'POST https://example.com/test-webhook', 'limit': 5000},
    ]
    for control in controls:
        control['enabled'] = policy.get(control['flag'], False)
        control['value'] = values.get(control['field'], '')
    return {'staging': status, 'error': error, 'controls': controls,
            'any_enabled': any(item['enabled'] for item in controls), 'unsaved': draft is not None,
            'access_unlocked': did_recently_reauthenticate(request)}


@login_required
def staging_external(request):
    from .operations_client import call
    status, error = None, None
    try:
        status = call('status')
    except (OSError, ValueError, KeyError):
        error = 'Staging controls are unavailable. External tests cannot be changed.'
    return render(request, 'staging_external.html', external_context(request, status, error))


@login_required
@require_POST
def staging_external_change(request):
    from .operations_client import call
    from companion.relay import destination, normalize_policy
    stop = request.POST.get('operation') == 'external_stop'
    status = None
    if not stop and not did_recently_reauthenticate(request):
        messages.info(request, 'Confirm access, then save the external test settings again.')
        return redirect('/accounts/reauthenticate/?next=/staging/external/')
    try:
        if stop:
            call('external_stop', actor=request.user.get_username())
        else:
            def rules(name):
                rows = []
                for line in request.POST.get(name, '').splitlines():
                    if not line.strip():
                        continue
                    method, url = line.strip().split(None, 1)
                    parsed = destination(url)
                    if parsed.query:
                        raise ValueError('List a destination path without a query string.')
                    rows.append({'host': parsed.hostname, 'path': parsed.path or '/', 'methods': [method.upper()]})
                return rows
            status = call('status')
            enabled = {name: request.POST.get(name) == 'yes' for name in ('http_enabled', 'webhooks_enabled', 'mail_enabled')}
            previous = status['external']
            policy = normalize_policy({
                **enabled,
                'http_rules': rules('http_rules') if enabled['http_enabled'] else previous.get('http_rules', []),
                'webhook_rules': rules('webhook_rules') if enabled['webhooks_enabled'] else previous.get('webhook_rules', []),
                'mail_recipients': ([line.strip() for line in request.POST.get('mail_recipients', '').splitlines() if line.strip()]
                                    if enabled['mail_enabled'] else previous.get('mail_recipients', [])),
            }, set(status['protected_hosts']))
            call('external', policy=policy, actor=request.user.get_username())
        messages.success(request, 'All external tests are off.' if stop else 'External test settings saved.')
    except (OSError, ValueError, KeyError) as error:
        explanation = str(error) if isinstance(error, ValueError) else 'The external test settings could not be saved.'
        if status and not stop:
            status['external'] = {**status['external'], **{name: request.POST.get(name) == 'yes'
                for name in ('http_enabled', 'mail_enabled', 'webhooks_enabled')}}
            return render(request, 'staging_external.html', external_context(request, status, explanation, request.POST), status=400)
        messages.error(request, explanation)
    return redirect('staging_external')


@login_required
def staging_inbox(request):
    from .operations_client import call
    inbox, selected, error = [], None, None
    try:
        inbox = call('mail_list', actor=request.user.get_username())['messages']
        if request.GET.get('message'):
            selected = call('mail_read', id=request.GET['message'], actor=request.user.get_username())
    except (OSError, ValueError, KeyError):
        error = 'The test inbox is unavailable or the selected message has expired.'
    return render(request, 'staging_inbox.html', {'inbox': inbox, 'selected': selected, 'error': error})


@login_required
def releases(request):
    from .operations_client import call
    items, selected, job, error, folders = [], None, None, None, []
    try:
        status = call('release_status', actor=request.user.get_username())
        items, job = status['releases'], status['job']
        folders = status.get('folders', [])
        for item in items:
            item['expired'] = item['expires_at'] < int(time.time())
            item['changed'] = item['changed_count'] > 0
            item['created'] = datetime.fromtimestamp(item['created_at'], timezone.utc)
            item['mine'] = item['actor'] == request.user.get_username()
            item['label'] = {'preview': 'Ready to review', 'applying': 'Applying files',
                'completed': 'Applied and checked', 'rolled-back': 'Previous code restored',
                'recovery-needs-review': 'Newer edits need review', 'not-applied': 'No code applied',
                'rejected-php-syntax': 'PHP check failed'}.get(item['phase'], 'Needs review')
            if job and job['running'] and job.get('token') == item['token']:
                item['label'] = 'Checking release'
            if item['token'] == request.GET.get('preview'):
                selected = {**item, **call('release_detail', token=item['token'], actor=request.user.get_username())}
                selected['changed'] = selected['changed_count'] > 0
    except (OSError, ValueError, KeyError):
        error = 'Code releases are unavailable. No files have been changed.'
    return render(request, 'releases.html', {'releases': items, 'selected': selected, 'job': job,
                  'error': error, 'folders': folders, 'access_unlocked': did_recently_reauthenticate(request)})


@login_required
def comparison_status(request):
    from .operations_client import call
    try:
        return JsonResponse(call('comparison_status', actor=request.user.get_username()))
    except (OSError, ValueError, KeyError):
        return JsonResponse({'error': 'The file check is unavailable. Your files have not changed. Try again shortly.'}, status=503)


@login_required
def comparison_detail(request):
    from .operations_client import call
    try:
        return JsonResponse(call('comparison_detail', folder=request.GET.get('folder', ''),
            page=int(request.GET.get('page', '1')), generation=request.GET.get('generation', ''), actor=request.user.get_username()))
    except (OSError, ValueError, KeyError):
        return JsonResponse({'error': 'These results are no longer available. Check changes again to continue.'}, status=409)


@login_required
@require_POST
def comparison_start(request):
    from .operations_client import call
    try:
        result = call('compare', actor=request.user.get_username())
        return JsonResponse(result, status=202)
    except (OSError, ValueError, KeyError):
        return JsonResponse({'error': 'The check could not start. Wait for any current workflow to finish, then try again.'}, status=409)


@login_required
@require_POST
def release_change(request):
    from .operations_client import call
    operation = request.POST.get('operation')
    if operation in ('release_apply', 'release_recover') and not did_recently_reauthenticate(request):
        messages.info(request, 'Confirm access, then submit the reviewed release again.')
        return redirect('/accounts/reauthenticate/?next=/staging/releases/')
    try:
        if operation == 'release_preview':
            selection = request.POST.get('files', '')
            if len(selection) > 50000:
                raise ValueError('Choose a smaller group of files for this release.')
            files = [line.strip() for line in selection.splitlines() if line.strip()]
            folder = request.POST.get('folder', '')
            if folder:
                if len(folder) > 300:
                    raise ValueError('Invalid code folder selection.')
                files.append(folder)
            record = call(operation, files=files, actor=request.user.get_username())
            return redirect('/staging/releases/?preview=' + record['token'])
        if operation == 'release_discard':
            call(operation, token=request.POST.get('token', ''), actor=request.user.get_username())
            messages.success(request, 'Unapplied preview removed.')
            return redirect('releases')
        if operation not in ('release_apply', 'release_recover'):
            raise ValueError('Choose a supported release action.')
        if request.POST.get('confirmed') != 'yes':
            raise ValueError('Confirm the selected code change before continuing.')
        call(operation, token=request.POST.get('token', ''), confirmed=True, actor=request.user.get_username())
        messages.success(request, 'Code recovery started.' if operation == 'release_recover' else 'Selected-code release started.')
    except (OSError, ValueError, KeyError) as error:
        messages.error(request, str(error) if isinstance(error, ValueError) else 'The release could not be started. No new approval was granted.')
    return redirect('releases')
