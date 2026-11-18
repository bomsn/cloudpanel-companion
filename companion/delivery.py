"""Deliver queued incident notifications without coupling monitoring to Slack.

The webhook is read from a private file and passed to a bounded child over stdin,
never a command argument. A failed or ambiguous delivery stays in the outbox.

Every message, from the website checks, the service watch or the security history,
is laid out here: first the server (its name and public address) and the website it
is about, then the event and its details. Setup saves the server and website once
(`write_context`); that file holds no secret, so every delivery service can read it.
"""
import argparse
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
from urllib.parse import urlsplit

from .incidents import IncidentStore
from .monitor import private_json
from .operations import write_private
from .staging import HOSTNAME

CONTEXT = Path('/etc/cloudpanel-companion/alert-context.json')
SERVER_NAME = r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}'
LABELS = {'down': 'Needs attention', 'healthy': 'Recovered', 'warning': 'Certificate warning', 'security': 'Security alert'}


def validate_webhook(url: str):
    if not isinstance(url, str) or not re.fullmatch(
            r'https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+', url):
        raise ValueError('Use a Slack incoming webhook URL')


def utc_time(at) -> str:
    """How an alert dates an event, in its text and in its Slack context line."""
    return datetime.fromtimestamp(at, timezone.utc).strftime('%d %b %Y, %H:%M UTC')


def context_values(server, address, site):
    """The alert context as saved, refusing anything but a plain server name, an IP address (or none) and a domain."""
    if (not isinstance(server, str) or not re.fullmatch(SERVER_NAME, server) or not isinstance(site, str)
            or not re.fullmatch(HOSTNAME, site) or not isinstance(address, str)
            or (address and str(ipaddress.ip_address(address)) != address)):
        raise ValueError('Use a plain server name, its IP address and the website domain')
    return {'server': server, 'address': address, 'site': site}


def write_context(server, address, site, path=CONTEXT):
    write_private(path, json.dumps(context_values(server, address, site)), 0o644)


def context(path=CONTEXT):
    """Which server and website alerts are about: setup's saved context, or this host's name alone."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor) as stream:
            info = os.fstat(stream.fileno())
            # Root's file, which no other account can change.
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096:
                raise ValueError('The alert context must be a root-owned file')
            values = json.load(stream)
        return context_values(values['server'], values['address'], values['site'])
    except (OSError, ValueError, KeyError, TypeError):
        return {'server': socket.gethostname()[:63], 'address': '', 'site': ''}


def payload(event, where) -> dict:
    """One Slack message: the server and website first, then the event, its details and its identity."""
    event_id, name, state, created_at, attempts, details = event
    label = LABELS[state]
    server = where['server'] + (f' ({where["address"]})' if where['address'] else '')
    origin = [('Server', server)] + ([('Website', where['site'])] if where['site'] else [])
    listed = [(str(key), str(value)) for key, value in json.loads(details or '[]')][:10]

    def fields(pairs):
        return {'type': 'section', 'fields': [{'type': 'plain_text', 'text': f'{key}: {value}'[:1900]} for key, value in pairs]}
    # The text is what a notification shows, so it too starts with where the event happened.
    text = f'{label} · {server}' + (f' · {where["site"]}' if where['site'] else '') + f': {name}'
    return {'text': text[:2900] + f'\nEvent: {event_id}', 'mrkdwn': False, 'unfurl_links': False, 'unfurl_media': False,
            'blocks': [
                {'type': 'header', 'text': {'type': 'plain_text',
                                            'text': (label + (' · ' + where['site'] if where['site'] else ''))[:150]}},
                fields(origin),
                {'type': 'section', 'text': {'type': 'plain_text', 'text': name[:2900]}},
                *([fields(listed)] if listed else []),
                {'type': 'context', 'elements': [{'type': 'plain_text', 'text': f'{utc_time(created_at)} · Event {event_id}'}]},
            ]}


def post_json(url: str, data: dict, ca_file: str | None = None) -> bool:
    """HTTPS transport; no redirects, verified TLS and bounded response reading."""
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('A direct HTTPS endpoint is required')
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=5,
                                            context=ssl.create_default_context(cafile=ca_file))
    try:
        path = parsed.path + ('?' + parsed.query if parsed.query else '')
        connection.request('POST', path or '/', body=json.dumps(data).encode(),
                           headers={'Content-Type': 'application/json', 'User-Agent': 'CloudPanel-Companion/0.1'})
        response = connection.getresponse()
        return response.status == 200 and response.read(16).strip() == b'ok'
    finally:
        connection.close()


def bounded_delivery(url: str, data: dict) -> bool:
    validate_webhook(url)
    environment = dict(os.environ)
    environment.pop('SSLKEYLOGFILE', None)
    try:
        result = subprocess.run([sys.executable, '-m', 'companion.delivery', '--worker'],
                                input=json.dumps({'url': url, 'payload': data}).encode(),
                                capture_output=True, timeout=8, env=environment)
        return result.returncode == 0 and result.stdout.strip() == b'accepted'
    except (OSError, subprocess.TimeoutExpired):
        return False


def run(config: Path, state_dir: Path):
    import fcntl
    settings = private_json(config)
    if set(settings) != {'slack_webhook'}:
        raise ValueError('Configure one Slack webhook')
    validate_webhook(settings['slack_webhook'])
    if state_dir.is_symlink() or not state_dir.is_dir() or state_dir.stat().st_uid != os.geteuid() or state_dir.stat().st_mode & 0o077:
        raise ValueError('State directory must be private and owned by the service user')
    database = state_dir / 'monitor.sqlite3'
    if database.is_symlink() or not database.is_file():
        raise ValueError('An existing monitoring database is required')
    descriptor = os.open(state_dir / 'delivery.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = IncidentStore(database)
        counts = {'delivered': 0, 'deferred': 0}
        where = context()
        try:
            for event in store.pending():
                if bounded_delivery(settings['slack_webhook'], payload(event, where)):
                    store.delivered(event[0])
                    counts['delivered'] += 1
                else:
                    store.failed(event[0])
                    counts['deferred'] += 1
            return counts
        finally:
            store.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--state-dir', type=Path)
    args = parser.parse_args()
    try:
        if args.worker:
            job = json.load(sys.stdin)
            validate_webhook(job['url'])
            if post_json(job['url'], job['payload']):
                print('accepted')
                return 0
            return 1
        if args.config is None or args.state_dir is None:
            parser.error('--config and --state-dir are required')
        print(json.dumps(run(args.config, args.state_dir)))
        return 0
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, http.client.HTTPException):
        print('Notification delivery unavailable; queued incidents are retained.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
