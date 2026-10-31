"""Explicit operator CLI for reviewed code deployment under a site identity.

This command does not elevate privileges. Cache invalidation, write quiescence
and an appropriate health URL are deployment prerequisites owned by the caller.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

from .deployment import apply, recover
from .promotion import preview


def health(url, expected_text):
    parsed = urlsplit(url)
    if (parsed.username or parsed.password or parsed.fragment or
            any(ord(char) < 33 for char in url) or
            not (parsed.scheme == 'https' or
                 (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', '::1')))):
        raise ValueError('Health check requires HTTPS or explicit loopback HTTP')
    result = subprocess.run(['/usr/bin/curl', '--silent', '--show-error', '--fail',
                             '--max-time', '10', '--connect-timeout', '3', '--max-filesize', '1048576',
                             '--proto', '=http,https', '--output', '-', '--write-out', '\n%{http_code}',
                             url], capture_output=True, timeout=12)
    if result.returncode:
        return False
    body, _, status = result.stdout.rpartition(b'\n')
    return status == b'200' and expected_text.encode() in body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    plan = sub.add_parser('preview')
    plan.add_argument('--source', type=Path, required=True)
    plan.add_argument('--target', type=Path, required=True)
    plan.add_argument('files', nargs='+')
    deploy = sub.add_parser('apply')
    deploy.add_argument('--source', type=Path, required=True)
    deploy.add_argument('--php', required=True)
    for command in (deploy, sub.add_parser('recover')):
        command.add_argument('--target', type=Path, required=True)
        command.add_argument('--state', type=Path, required=True)
        command.add_argument('--health-url', required=True)
        command.add_argument('--health-text', required=True)
    sub.choices['recover'].add_argument('transaction')
    args = parser.parse_args()
    if args.operation == 'preview':
        print(json.dumps(preview(args.source, args.target, args.files), indent=2))
    else:
        check = lambda: health(args.health_url, args.health_text)
        if args.operation == 'apply':
            raw = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('Approval manifest exceeds size limit')
            receipt = apply(args.source, args.target, json.loads(raw), args.state, args.php, check)
            print(json.dumps({'receipt': str(receipt), 'status': 'completed'}))
        else:
            print(json.dumps(recover(args.target, args.state, args.transaction, check)))


if __name__ == '__main__':
    main()
