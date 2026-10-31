"""Deliver queued incident notifications without coupling monitoring to Slack.

The webhook is read from a private file and passed to a bounded child over stdin,
never a command argument. A failed or ambiguous delivery stays in the outbox.
"""
import argparse
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

from .incidents import IncidentStore
from .monitor import private_json


def validate_webhook(url: str):
    if not isinstance(url, str) or not re.fullmatch(
            r'https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+', url):
        raise ValueError('Use a Slack incoming webhook URL')


def payload(event) -> dict:
    event_id, name, state, created_at, attempts = event
    label = {'down': 'Needs attention', 'healthy': 'Recovered', 'warning': 'Certificate warning'}[state]
    message = f'{label}: {name}\nEvent: {event_id}'
    timestamp = datetime.fromtimestamp(created_at, timezone.utc).strftime('%d %b %Y, %H:%M UTC')
    return {'text': message, 'mrkdwn': False, 'unfurl_links': False, 'unfurl_media': False,
            'blocks': [
                {'type': 'header', 'text': {'type': 'plain_text', 'text': 'Website monitoring · ' + label}},
                {'type': 'section', 'text': {'type': 'plain_text', 'text': name}},
                {'type': 'context', 'elements': [{'type': 'plain_text', 'text': f'{timestamp} · Event {event_id}'}]},
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
        try:
            for event in store.pending():
                if bounded_delivery(settings['slack_webhook'], payload(event)):
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
