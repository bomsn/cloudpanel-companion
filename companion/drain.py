"""Drain customer PHP requests before a code release without terminating them."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


def drain(user, host, php_version, timeout=30):
    if not re.fullmatch(r'[a-z0-9.-]+', host) or php_version not in ('8.2', '8.3', '8.4'):
        raise ValueError('Invalid registered PHP pool')
    pool = Path('/etc/php') / php_version / 'fpm/pool.d' / (host + '.conf')
    fd = os.open(pool, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Native PHP pool must be operator-owned')
        text = stream.read(65537)
    users = re.findall(r'^user\s*=\s*(\S+)\s*$', text, re.M)
    ports = re.findall(r'^listen\s*=\s*127\.0\.0\.1:([0-9]+)\s*$', text, re.M)
    status_paths = re.findall(r'^pm.status_path\s*=\s*(/\S+)\s*$', text, re.M)
    if users != [user] or len(ports) != 1 or status_paths != ['/status']:
        raise ValueError('Native PHP identity/listener/status contract changed')
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'SCRIPT_NAME': '/status',
                   'SCRIPT_FILENAME': '/status', 'REQUEST_URI': '/status?json&full',
                   'QUERY_STRING': 'json&full', 'REQUEST_METHOD': 'GET',
                   'SERVER_PROTOCOL': 'HTTP/1.1', 'GATEWAY_INTERFACE': 'CGI/1.1',
                   'REMOTE_ADDR': '127.0.0.1', 'SERVER_NAME': host, 'SERVER_PORT': '443'}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(['/usr/bin/cgi-fcgi', '-bind', '-connect', '127.0.0.1:' + ports[0]],
                                    capture_output=True, timeout=3, env=environment)
            if result.returncode:
                raise ValueError('PHP status responder failed')
            _, separator, body = result.stdout.partition(b'\r\n\r\n')
            if not separator:
                _, separator, body = result.stdout.partition(b'\n\n')
            observation = json.loads(body)
            if observation.get('pool') != host:
                raise ValueError('PHP status responder belongs to another pool')
            if (observation.get('listen queue') == 0 and observation.get('active processes') == 1 and
                    all(item.get('state') == 'Idle' or
                        (item.get('state') == 'Running' and item.get('request uri', '').startswith('/status?'))
                        for item in observation.get('processes', []))):
                return {'listen_queue': observation['listen queue'], 'active_processes': observation['active processes']}
        except subprocess.TimeoutExpired:
            # A busy status request can queue behind customer work; let those
            # requests finish, then refuse the release when the deadline passes.
            pass
        time.sleep(.2)
    raise ValueError('Existing customer requests did not finish in time; no code may be changed')
