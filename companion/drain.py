"""Drain customer PHP requests before a code release without terminating them."""
import re
import subprocess
import time
from .php_pool import fastcgi_json, pool


def drain(user, host, php_version, timeout=30):
    text, port = pool(user, host, php_version)
    if re.findall(r'^pm.status_path\s*=\s*(/\S+)\s*$', text, re.M) != ['/status']:
        raise ValueError('Native PHP status contract changed')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            observation = fastcgi_json(port, '/status', 'json&full', host)
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
