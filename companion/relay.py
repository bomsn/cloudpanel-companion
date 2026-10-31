"""Allowlisted staging HTTPS and private email capture over a Unix socket.

The website retains its kernel outbound deny. This separate unprivileged
identity can send only operator-approved HTTPS requests. DNS answers are
validated and the chosen public address is pinned through verified TLS.
"""
import argparse
import base64
from email.utils import getaddresses
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
import sys
import time
from urllib.parse import urlsplit
from .monitor import private_json

REQUEST_LIMIT = 1024 * 1024
BODY_LIMIT = 512 * 1024
RESPONSE_LIMIT = 2 * 1024 * 1024
METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'}


def default_policy():
    return {'mail_enabled': False, 'mail_recipients': [], 'http_enabled': False,
            'http_rules': [], 'webhooks_enabled': False, 'webhook_rules': []}


def operator_inbox(socket_path, operation, identifier=None):
    if operation not in ('mail_list', 'mail_read'):
        raise ValueError('Unsupported inbox operation')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(22)
        connection.connect(str(socket_path))
        connection.sendall(json.dumps({'operation': operation, 'id': identifier}).encode() + b'\n')
        with connection.makefile('rb') as stream:
            raw = stream.readline(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024 or not raw.endswith(b'\n'):
        raise ValueError('Invalid inbox response')
    response = json.loads(raw)
    if not response.get('ok'):
        raise ValueError('Test inbox is unavailable')
    return response['result']


def destination(url):
    if not isinstance(url, str) or len(url) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in url):
        raise ValueError('Use an explicit ASCII HTTPS URL')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or
            parsed.fragment or parsed.port not in (None, 443) or
            not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', parsed.hostname)):
        raise ValueError('Use an HTTPS hostname on port 443 without credentials or fragments')
    path = parsed.path or '/'
    if '%' in path or '\\' in path or any(part in ('.', '..') for part in path.split('/')) or '//' in path:
        raise ValueError('The destination path must be unambiguous')
    return parsed


def normalize_policy(data, forbidden):
    keys = {'mail_enabled', 'mail_recipients', 'http_enabled', 'http_rules', 'webhooks_enabled', 'webhook_rules'}
    if not isinstance(data, dict) or set(data) != keys:
        raise ValueError('Supply the complete external test policy')
    result = {}
    for name in ('mail_enabled', 'http_enabled', 'webhooks_enabled'):
        if type(data[name]) is not bool:
            raise ValueError('Explicit enabled states are required')
        result[name] = data[name]
    recipients = data['mail_recipients']
    if not isinstance(recipients, list) or len(recipients) > 10:
        raise ValueError('Choose at most ten test recipients')
    if any(not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}', value) for value in recipients):
        raise ValueError('Use plain test email addresses')
    result['mail_recipients'] = sorted(set(value.lower() for value in recipients))
    if result['mail_enabled'] and not result['mail_recipients']:
        raise ValueError('Choose test recipients before enabling email capture')
    for category in ('http', 'webhook'):
        rules = data[category + '_rules']
        if not isinstance(rules, list) or len(rules) > 20:
            raise ValueError('Choose at most twenty destinations per category')
        normalized = []
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {'host', 'path', 'methods'}:
                raise ValueError('Each destination needs its hostname, path and methods')
            if not isinstance(rule['host'], str) or not isinstance(rule['path'], str):
                raise ValueError('Invalid destination')
            parsed = destination('https://' + rule['host'] + rule['path'])
            if parsed.hostname != rule['host'] or parsed.query or parsed.hostname in forbidden:
                raise ValueError('Live commerce sites and ambiguous destinations cannot be test targets')
            if not isinstance(rule['methods'], list) or not rule['methods'] or any(method not in METHODS for method in rule['methods']):
                raise ValueError('Choose explicit HTTP methods')
            normalized.append({'host': parsed.hostname, 'path': parsed.path or '/', 'methods': sorted(set(rule['methods']))})
        enabled = 'http_enabled' if category == 'http' else 'webhooks_enabled'
        if data[enabled] and not normalized:
            raise ValueError('Choose destinations before enabling external tests')
        result[category + '_rules'] = normalized
    return result


def load_policy(path, forbidden):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
            raise ValueError('External policy must be operator-owned')
        return normalize_policy(json.load(stream), forbidden)


def permitted(policy, url, method):
    parsed = destination(url)
    if method not in METHODS:
        return False
    rules = (policy['http_rules'] if policy['http_enabled'] else []) + (policy['webhook_rules'] if policy['webhooks_enabled'] else [])
    for rule in rules:
        prefix = rule['path'].rstrip('/')
        if parsed.hostname == rule['host'] and method in rule['methods'] and ((parsed.path or '/') == prefix or (parsed.path or '/').startswith(prefix + '/')):
            return True
    return False


def public_addresses(host):
    addresses = list(dict.fromkeys(answer[4][0] for answer in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)))
    if not addresses or len(addresses) > 20:
        raise ValueError('Unsupported destination DNS answer')
    for address in addresses:
        value = ipaddress.ip_address(address)
        mapped = isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped is not None
        if not value.is_global or value.is_multicast or value.is_reserved or value.is_unspecified or mapped:
            raise ValueError('Private and special-use destinations are forbidden')
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, 443, timeout=5, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def request_https(policy, request):
    url, method = request.get('url'), request.get('method')
    if not permitted(policy, url, method):
        raise ValueError('This destination and method are not enabled for staging')
    parsed = destination(url)
    headers = request.get('headers', {})
    if not isinstance(headers, dict) or len(headers) > 50:
        raise ValueError('Invalid request headers')
    blocked = {'host', 'connection', 'content-length', 'transfer-encoding', 'proxy-authorization', 'proxy-connection', 'upgrade', 'trailer', 'te'}
    clean, seen = {}, set()
    for key, value in headers.items():
        if (not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9!#$%&\x27*+.^_`|~-]{1,128}', key) or
                not isinstance(value, str) or len(value) > 8192 or any(ord(char) < 32 or ord(char) > 126 for char in value)):
            raise ValueError('Invalid request header')
        if key.lower() in seen:
            raise ValueError('Duplicate request header')
        seen.add(key.lower())
        if key.lower() not in blocked | {'accept-encoding'}:
            clean[key] = value
    if sum(len(key) + len(value) for key, value in clean.items()) > 32768:
        raise ValueError('Request headers exceed the limit')
    clean['Accept-Encoding'] = 'identity'
    body = base64.b64decode(request.get('body', ''), validate=True)
    if len(body) > BODY_LIMIT:
        raise ValueError('Request body exceeds the limit')
    address = public_addresses(parsed.hostname)[0]
    connection = PinnedHTTPS(parsed.hostname, address)
    try:
        path = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
        connection.request(method, path, body=body, headers=clean)
        response = connection.getresponse()
        response_headers = response.getheaders()
        if sum(len(key) + len(value) for key, value in response_headers) > 32768:
            raise ValueError('External response headers exceed the limit')
        # Slow streaming peers cannot extend a request forever with tiny chunks.
        deadline = time.monotonic() + 10
        blocks, length = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('External response deadline exceeded')
            if connection.sock:
                connection.sock.settimeout(min(5, remaining))
            block = response.read1(min(65536, RESPONSE_LIMIT + 1 - length))
            if not block:
                break
            blocks.append(block)
            length += len(block)
            if length > RESPONSE_LIMIT:
                raise ValueError('External response exceeds the limit')
        if response.getheader('Content-Encoding', 'identity').lower() not in ('', 'identity'):
            raise ValueError('The approved endpoint ignored the identity encoding request')
        return {'status': response.status, 'reason': response.reason[:128],
                'headers': response_headers, 'body': base64.b64encode(b''.join(blocks)).decode()}
    finally:
        connection.close()


def capture_mail(policy, request, inbox):
    if not policy['mail_enabled']:
        raise ValueError('Test email capture is disabled')
    recipients = request.get('recipients')
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 10 or any(not isinstance(value, str) for value in recipients):
        raise ValueError('Invalid test recipients')
    parsed = getaddresses(recipients)
    if len(parsed) != len(recipients) or any(address.lower() not in policy['mail_recipients'] for _, address in parsed):
        raise ValueError('Every recipient must be an approved test address')
    subject, body = request.get('subject'), request.get('body')
    if not isinstance(subject, str) or len(subject) > 255 or any(char in subject for char in '\r\n') or not isinstance(body, str) or len(body.encode()) > BODY_LIMIT:
        raise ValueError('Invalid test email content')
    inbox.mkdir(mode=0o700, exist_ok=True)
    identifier = str(time.time_ns()) + '-' + secrets.token_hex(8)
    encoded = json.dumps({'id': identifier, 'captured_at': int(time.time()), 'recipients': recipients, 'subject': subject, 'body': body}).encode()
    existing = sorted(inbox.glob('*.json'), key=lambda path: path.name)
    # Bound storage before adding the message; website identities cannot write
    # this directory, and contents are displayed as escaped text by the UI.
    total = sum(path.stat().st_size for path in existing)
    while existing and (len(existing) >= 50 or total + len(encoded) > 8 * 1024 * 1024):
        oldest = existing.pop(0)
        total -= oldest.stat().st_size
        oldest.unlink()
    path = inbox / (identifier + '.json')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return {'captured': True, 'id': identifier}


class Relay:
    def __init__(self, configuration, state):
        self.configuration, self.state = configuration, state
        self.events = []

    def action(self, uid, request):
        config = self.configuration
        if uid == config['staging_uid']:
            now = time.monotonic()
            self.events = [value for value in self.events if now - value < 60]
            if len(self.events) >= 30:
                raise ValueError('Staging external tests are limited to thirty requests per minute')
            self.events.append(now)
            # A child deadline also bounds DNS, TLS and a peer trickling bytes.
            # The worker shares this unprivileged identity, not root or PHP.
            result = subprocess.run([sys.executable, '-m', 'companion.relay', '--worker'],
                                    input=json.dumps({'configuration': config, 'state': str(self.state), 'request': request}).encode(),
                                    capture_output=True, timeout=18, cwd='/opt/cloudpanel-companion')
            if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
                raise ValueError('External test worker failed')
            response = json.loads(result.stdout)
            if not response.get('ok'):
                raise ValueError('External test worker refused the request')
            return response['result']
        elif uid == 0 and request.get('operation') == 'mail_list':
            inbox = self.state / 'mail'
            messages = []
            for path in sorted(inbox.glob('*.json'), reverse=True)[:50]:
                with path.open() as stream:
                    value = json.load(stream)
                    value.pop('body', None)
                    messages.append(value)
            return {'messages': messages}
        elif uid == 0 and request.get('operation') == 'mail_read':
            identifier = request.get('id', '')
            if not isinstance(identifier, str) or not re.fullmatch(r'[0-9]{10,30}-[a-f0-9]{16}', identifier):
                raise ValueError('Invalid message identity')
            with (self.state / 'mail' / (identifier + '.json')).open() as stream:
                return json.load(stream)
        raise ValueError('This operation is not available to this Unix identity')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--config', type=Path)
    parser.add_argument('--state', type=Path)
    parser.add_argument('--socket', type=Path)
    arguments = parser.parse_args()
    if arguments.worker:
        try:
            if os.geteuid() == 0:
                raise ValueError('A relay worker cannot run as root')
            raw = sys.stdin.buffer.read(REQUEST_LIMIT + 65536 + 1)
            if len(raw) > REQUEST_LIMIT + 65536:
                raise ValueError('Worker input too large')
            task = json.loads(raw)
            policy = load_policy(Path(task['configuration']['policy_path']), set(task['configuration']['forbidden_hosts']))
            if task['request'].get('operation') == 'http':
                result = request_https(policy, task['request'])
            elif task['request'].get('operation') == 'mail':
                result = capture_mail(policy, task['request'], Path(task['state']) / 'mail')
            else:
                raise ValueError('Unsupported test request')
            print(json.dumps({'ok': True, 'result': result}))
        except Exception:
            print(json.dumps({'ok': False}))
            raise SystemExit(1)
        return
    if not arguments.config or not arguments.state or not arguments.socket:
        parser.error('Server requires configuration, state and socket paths')
    config = private_json(arguments.config)
    if (os.geteuid() == 0 or arguments.state.is_symlink() or arguments.state.stat().st_mode & 0o077 or
            arguments.state.stat().st_uid != os.geteuid() or
            type(config.get('staging_uid')) is not int or config['staging_uid'] < 1000):
        raise ValueError('Relay requires its own unprivileged identity and private state')
    relay = Relay(config, arguments.state)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(20)
            _, uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid not in (0, config['staging_uid']):
                return
            try:
                raw = self.rfile.readline(REQUEST_LIMIT + 1)
                if len(raw) > REQUEST_LIMIT or not raw.endswith(b'\n'):
                    raise ValueError('Invalid relay request size')
                response = {'ok': True, 'result': relay.action(uid, json.loads(raw))}
            except Exception:
                response = {'ok': False, 'error': 'The staging relay refused or could not complete this test request.'}
            self.wfile.write(json.dumps(response).encode() + b'\n')

    if arguments.socket.exists():
        if not arguments.socket.is_socket():
            raise ValueError('Relay socket is occupied')
        arguments.socket.unlink()
    with socketserver.UnixStreamServer(str(arguments.socket), Handler) as server:
        os.chmod(arguments.socket, 0o660)
        server.serve_forever()


if __name__ == '__main__':
    main()
