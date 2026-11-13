"""Companion sign-ins and failed attempts, recorded from allauth's own signals.

The address is the one Nginx forwards (companion/client_address.py), read through
allauth's own client-IP lookup so rate limits and these records agree; the country
is Nginx's Cloudflare-validated X-Companion-Country header. A rejected password keeps
the name tried only when it is an account's, since any other name may be a password
typed into the name field; the password itself is never read. Entries are kept for
90 days and pruned on every write.

New sources and bursts follow the collector's rules (companion.security_log), and
every successful sign-in alerts. This service cannot reach Slack, so an alert is
written as fields to a private spool that the root collector validates, words and
queues for delivery.
"""
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import secrets
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_login_failed
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Max
from django.dispatch import receiver
from django.utils import timezone
from allauth.account.adapter import get_adapter
from allauth.account.authentication import get_authentication_records
from allauth.account.signals import user_logged_in
from allauth.mfa.signals import authentication_failed
from companion import client_address, security_log
from .models import SignIn

MAX_RECORDS = 20000
# The collector empties the spool every minute; past this many files, alerts are dropped
# rather than letting a flood of failures fill the interface's state directory.
SPOOL_LIMIT = 100


def spool_directory():
    # The collector reads the same directory under the installed state path.
    return Path(settings.STATE) / security_log.WEB_SPOOL.name


def client(request):
    try:
        ip = security_log.valid_ip(get_adapter().get_client_ip(request))
    except PermissionDenied:
        ip = ''
    country = request.headers.get('X-Companion-Country', '')
    return ip, country if client_address.COUNTRY.fullmatch(country) else ''


def record(request, username, succeeded, two_factor):
    if request is None:
        return
    ip, country = client(request)
    now = timezone.now()
    alert = None
    with transaction.atomic():
        SignIn.objects.filter(at__lt=now - timedelta(seconds=security_log.RETENTION)).delete()
        excess = SignIn.objects.order_by('-id').values_list('id', flat=True)[MAX_RECORDS - 1:MAX_RECORDS]
        if excess:
            SignIn.objects.filter(id__lte=excess[0]).delete()
        source, known = '', set()
        if succeeded:
            previous = SignIn.objects.filter(succeeded=True, at__gte=now - timedelta(seconds=security_log.RETENTION))
            known = set(previous.values_list('ip', 'country').distinct())
            source = security_log.new_source({ip for ip, _ in known},
                                             {code for _, code in known if security_log.country_known(code)}, ip, country)
        entry = SignIn.objects.create(at=now, succeeded=succeeded, username=security_log.clean_user(username)[:150],
                                      ip=ip, country=country, two_factor=two_factor, new_source=source,
                                      browser=security_log.browser(request.headers.get('User-Agent', '')))
        if succeeded:
            # Every sign-in to the Companion alerts, marked when its source is new.
            alert = {'kind': 'signin', 'source': source, 'first': not known, 'user': entry.username,
                     'two_factor': two_factor, 'browser': entry.browser}
        else:
            failures = SignIn.objects.filter(succeeded=False, at__gt=now - timedelta(seconds=security_log.BURST_WINDOW)).count()
            last = SignIn.objects.filter(burst__gt=0).aggregate(last=Max('at'))['last']
            if security_log.burst_due(failures, 'companion', last.timestamp() if last else None, now.timestamp()):
                entry.burst = failures
                entry.save(update_fields=['burst'])
                alert = {'kind': 'burst', 'count': failures}
    if alert:
        try:
            spool({**alert, 'at': int(now.timestamp()), 'ip': ip, 'country': country})
        except OSError:
            # A sign-in must never fail because its alert could not be handed over;
            # the entry above is already recorded and highlighted on the Security page.
            pass


def spool(alert):
    directory = spool_directory()
    directory.mkdir(mode=0o700, exist_ok=True)
    if len(os.listdir(directory)) >= SPOOL_LIMIT:
        return
    name = f'{alert["at"]:010d}-{secrets.token_hex(8)}.json'
    # Written under another name and renamed, so the collector never reads half a file.
    temporary = directory / ('.' + name + '.new')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(alert, stream)
    os.replace(temporary, directory / name)


@receiver(user_logged_in)
def signed_in(sender, request, user, **kwargs):
    two_factor = any(item.get('method') == 'mfa' for item in get_authentication_records(request, user))
    record(request, user.get_username(), True, two_factor)


@receiver(user_login_failed)
def password_rejected(sender, credentials, request=None, **kwargs):
    # Django has already masked the password in `credentials`; only the name is read, and
    # kept as the account's own name (sign-in ignores case) or recorded as no account.
    tried, account = credentials.get('username'), None
    if isinstance(tried, str) and tried:
        account = get_user_model().objects.filter(username__iexact=tried).values_list('username', flat=True).first()
    record(request, account or '', False, False)


@receiver(authentication_failed)
def code_rejected(sender, request, user, **kwargs):
    record(request, user.get_username(), False, True)


def summary_rows(entries):
    """Records in the collector's row shape, so every panel is summarised the same way."""
    return [{'outcome': 'signin' if entry.succeeded else 'failed', 'at': int(entry.at.timestamp()),
             'user': entry.username, 'ip': entry.ip, 'country': entry.country, 'browser': entry.browser,
             'method': 'code' if entry.two_factor and not entry.succeeded else 'password',
             'two_factor': entry.two_factor, 'verified': True, 'new_source': entry.new_source, 'burst': entry.burst}
            for entry in entries]


def summary(now):
    since = datetime.fromtimestamp(now - 7 * 86400, UTC)
    newest = SignIn.objects.order_by('-at', '-id')
    return security_log.panel_summary(summary_rows(newest.filter(at__gte=since)),
                                      summary_rows(newest.filter(succeeded=True)[:security_log.LATEST]), now)
