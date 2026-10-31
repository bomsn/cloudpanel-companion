"""Render an operator-owned VCL without modifying CloudPanel-generated files."""
import argparse
import json
from pathlib import Path
import re
import hashlib
import secrets
from .monitor import private_json


def render(config: dict, policy: str, revisions: dict | None = None) -> str:
    if set(config) != {'backend_port', 'sites'}:
        raise ValueError('Expected backend_port and sites')
    port = config['backend_port']
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError('Invalid local backend port')
    sites = config['sites']
    if not isinstance(sites, list) or not 1 <= len(sites) <= 100:
        raise ValueError('Register between 1 and 100 sites')
    names, keys = set(), set()
    for site in sites:
        if set(site) != {'host', 'purge_key'}:
            raise ValueError('Each site needs a host and purge_key')
        host, key = site['host'], site['purge_key']
        if not isinstance(host, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host):
            raise ValueError('Invalid hostname')
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
            raise ValueError('Invalid hostname label')
        if not isinstance(key, str) or not re.fullmatch(r'[a-f0-9]{64}', key):
            raise ValueError('Invalid purge key')
        if host in names or key in keys:
            raise ValueError('Every site must have a unique hostname and credential')
        names.add(host)
        keys.add(key)
    allowed = ' && '.join(f'req.http.host != "{site["host"]}"' for site in sites)
    revisions = revisions if revisions is not None else {host: secrets.token_hex(16) for host in names}
    if set(revisions) != names or any(not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{32}', value) for value in revisions.values()):
        raise ValueError('Each registered host needs a unique revision value')
    epoch = hashlib.sha256(policy.encode()).hexdigest()[:32]
    assignments = '\n'.join(f'    if (req.http.host == "{host}") {{ set req.http.X-Cache-Manager-For-CloudPanel-Revision = "{epoch}:{revisions[host]}"; return; }}' for host in sorted(names))
    # Purge authentication belongs to the separate loopback control endpoint.
    # No credentials are embedded in VCL, and no optional VMOD is required.
    return f'''vcl 4.1;
backend default {{ .host = "127.0.0.1"; .port = "{port}"; }}
sub vcl_recv {{
    if ({allowed}) {{ return (synth(421, "Unregistered cache host")); }}
}}
sub cache_manager_for_cloudpanel_revision {{
{assignments}
    return (synth(421, "Unregistered cache host"));
}}
{policy}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Exclusive creation avoids replacing a running configuration. Installation
    # must compile and verify this candidate before an explicit service reload.
    result = render(private_json(args.config), args.policy.read_text())
    import os
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(result)


if __name__ == '__main__':
    main()
