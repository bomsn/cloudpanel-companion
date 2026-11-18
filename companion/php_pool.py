"""The native CloudPanel PHP-FPM pool contract and its FastCGI status responder.

Release draining, staging quiescence, server history and monitoring setup all
rely on the same pool: a root-owned file named after the site, run as the site
user and listening on one loopback TCP port. One reader keeps those checks equal.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess

VERSIONS = ('8.2', '8.3', '8.4')


def pool(user: str, host: str, php_version: str) -> tuple[str, int]:
    """The pool's configuration text and port, refusing a pool that is not the site's own."""
    if not re.fullmatch(r'[a-z0-9.-]+', host) or php_version not in VERSIONS:
        raise ValueError('Invalid registered PHP pool')
    path = Path('/etc/php') / php_version / 'fpm/pool.d' / (host + '.conf')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Native PHP pool must be operator-owned')
        text = stream.read(65537)
    users = re.findall(r'^user\s*=\s*(\S+)\s*$', text, re.M)
    ports = re.findall(r'^listen\s*=\s*127\.0\.0\.1:([0-9]+)\s*$', text, re.M)
    if users != [user] or len(ports) != 1 or not 1024 <= int(ports[0]) <= 65535:
        raise ValueError('Native PHP pool identity or listener changed')
    return text, int(ports[0])


def fastcgi_json(port: int, path: str, query: str = '', server_name: str = 'localhost', timeout: float = 3):
    """The JSON a pool's FastCGI responder returns: its status page or an operator diagnostic."""
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'SCRIPT_NAME': path,
                   'SCRIPT_FILENAME': path, 'REQUEST_URI': path + ('?' + query if query else ''),
                   'QUERY_STRING': query, 'REQUEST_METHOD': 'GET', 'SERVER_PROTOCOL': 'HTTP/1.1',
                   'GATEWAY_INTERFACE': 'CGI/1.1', 'REMOTE_ADDR': '127.0.0.1',
                   # The request a site's code sees from a visitor, so loading it reports no missing host or scheme.
                   'SERVER_NAME': server_name, 'HTTP_HOST': server_name, 'SERVER_PORT': '443', 'HTTPS': 'on'}
    result = subprocess.run(['/usr/bin/cgi-fcgi', '-bind', '-connect', f'127.0.0.1:{port}'],
                            capture_output=True, timeout=timeout, env=environment)
    if result.returncode or len(result.stdout) > 262144:
        raise ValueError('PHP FastCGI responder failed')
    _, separator, body = result.stdout.partition(b'\r\n\r\n')
    if not separator:
        _, separator, body = result.stdout.partition(b'\n\n')
    return json.loads(body)
