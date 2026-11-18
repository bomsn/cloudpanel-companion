"""The address a request really came from, decided once in Nginx for every Companion consumer.

CloudPanel's nginx.conf trusts every IPv4 peer to rewrite the client address
(`set_real_ip_from 0.0.0.0/0` with the default `real_ip_header X-Real-IP`), so
`$remote_addr` is whatever a client puts in X-Real-IP. These rules never read
it. `$realip_remote_addr` is the connecting peer itself, and only when that peer
is in Cloudflare's published ranges are its CF-Connecting-IP and CF-IPCountry
headers believed. Every other request is recorded with the peer address and no
country. The interface's proxy headers, its rate limits and both private access
logs use the result, so no consumer can be given a forged address.

The website's own vhost decides the same address with Nginx's realip module, through
two includes that `nginx_templates.integration()` places: its public server blocks
believe only a Cloudflare edge (CF-Connecting-IP), its 8080 PHP backend only loopback,
where the public block's proxied requests arrive with the address it decided in X-Real-IP.
A `set_real_ip_from` in a server block replaces the http-level list for that block, so
CloudPanel's trust in every peer no longer applies there. WordPress then receives the
visitor's address as REMOTE_ADDR, and with Cloudflare removed it is the connecting peer.
"""
import ipaddress
import json
import math
import os
from pathlib import Path
import re
from .operations import write_private

CLOUDFLARE_RANGES = Path(__file__).resolve().parents[1] / 'assets' / 'cloudflare-ips.txt'
# CloudPanel loads sites-enabled at HTTP scope; the 000- name sorts before the vhosts using these variables.
HTTP_CONFIG = Path('/etc/nginx/sites-enabled/000-companion-security.conf')
LOG_DIRECTORY = Path('/var/log/cloudpanel-companion')
# One private access log per panel. The interface's log is written by its routing include
# (assets/companion-web-proxy.conf); CloudPanel's by the include install-security.py adds to its vhost.
LOGS = {'companion': LOG_DIRECTORY / 'companion-access.log', 'cloudpanel': LOG_DIRECTORY / 'cloudpanel-access.log'}
LOG_FORMAT = 'companion_access'
LOGROTATE = Path('/etc/logrotate.d/cloudpanel-companion-access')
# Server-block includes for the website and staging vhosts (see the module docstring).
PUBLIC_TRUST = Path('/etc/cloudpanel-companion/client-address-public.conf')
BACKEND_TRUST = Path('/etc/cloudpanel-companion/client-address-backend.conf')
TRUST_INCLUDES = (PUBLIC_TRUST, BACKEND_TRUST)
# The only peers of the 8080 backend: the public block's own proxying and Varnish, both on loopback.
LOOPBACK = ('127.0.0.1', '::1')
# Path classes. CloudPanel signs in at POST /login and asks for its code at /login/mfa;
# the Companion (allauth) at /accounts/login/ and /accounts/2fa/authenticate/.
PATHS = ('login', 'code', 'other')
# Where a redirect sends the browser: CloudPanel answers a rejected password with a
# redirect back to /login and an accepted one with a redirect onwards (its code page or /sites).
NEXT = ('login', 'code', 'other', '')
COUNTRY = re.compile(r'[A-Z0-9]{2}')
METHOD = re.compile(r'[A-Z]{1,12}')


def cloudflare_ranges(text=None):
    """The published ranges, refusing anything that is not an explicit network."""
    text = CLOUDFLARE_RANGES.read_text() if text is None else text
    networks = [ipaddress.ip_network(line.strip()) for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
    if not networks or any(network.is_private or network.prefixlen < 8 for network in networks):
        raise ValueError('The Cloudflare range list is empty or contains an implausible network')
    return networks


def http_configuration(networks):
    ranges = ''.join(f'    {network} 1;\n' for network in networks)
    return f'''# CloudPanel Companion: trusted client address and private panel access logs.
# Generated from assets/cloudflare-ips.txt by install-web.py. Changes here are overwritten.
geo $realip_remote_addr $companion_via_cloudflare {{
    default 0;
{ranges}}}
map "$companion_via_cloudflare:$http_cf_connecting_ip" $companion_client_ip {{
    default $realip_remote_addr;
    "~^1:(?<companion_cloudflare_ip>[0-9A-Fa-f:.]{{2,45}})$" $companion_cloudflare_ip;
}}
map "$companion_via_cloudflare:$http_cf_ipcountry" $companion_client_country {{
    default "";
    "~^1:(?<companion_cloudflare_country>[A-Z0-9]{{2}})$" $companion_cloudflare_country;
}}
map $uri $companion_access_path {{
    default other;
    /login login;
    /login/mfa code;
    /accounts/login/ login;
    /accounts/2fa/authenticate/ code;
}}
map $sent_http_location $companion_access_next {{
    default other;
    "" "";
    ~/login/mfa([?]|$) code;
    ~/login([?]|$) login;
}}
map $uri $companion_access_observe {{
    default 1;
    ~^/static/ 0;
    ~^/\\.well-known/ 0;
    ~*\\.(css|js|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot)$ 0;
}}
log_format {LOG_FORMAT} escape=json '{{"at":$msec,"ip":"$companion_client_ip","country":"$companion_client_country","method":"$request_method","path":"$companion_access_path","status":$status,"next":"$companion_access_next"}}';
'''


def public_trust(networks):
    """The realip rules of a website's public server blocks: Cloudflare's edge names the visitor, nobody else."""
    ranges = ''.join(f'set_real_ip_from {network};\n' for network in networks)
    return f'''# CloudPanel Companion: the visitor address in a website's public server blocks.
# Generated from assets/cloudflare-ips.txt by install-web.py. Changes here are overwritten.
# Only a request from Cloudflare's edge may name the visitor, in CF-Connecting-IP. Any other
# peer is the visitor itself, and every address header it sends is ignored. These lines
# replace nginx.conf's set_real_ip_from list in each block that includes them.
{ranges}real_ip_header CF-Connecting-IP;
real_ip_recursive off;
'''


def backend_trust():
    """The realip rules of a website's 8080 PHP backend: only loopback forwards an address."""
    peers = ''.join(f'set_real_ip_from {address};\n' for address in LOOPBACK)
    return f'''# CloudPanel Companion: the visitor address in a website's 8080 PHP backend block.
# Generated by install-web.py. Changes here are overwritten.
# Only the website's public block and Varnish reach this block, over loopback, carrying the
# address the public block decided in X-Real-IP. Any other peer is taken as it connects.
{peers}real_ip_header X-Real-IP;
real_ip_recursive off;
'''


def access_directive(panel):
    return f'access_log {LOGS[panel]} {LOG_FORMAT} if=$companion_access_observe;'


ROTATION = ' '.join(str(path) for path in LOGS.values()) + ''' {
    daily
    maxsize 20M
    rotate 3
    missingok
    notifempty
    nocompress
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/sbin/nginx -s reopen
    endscript
}
'''


# CloudPanel's vhost for its own custom domain ships with `#access_log` commented out.
# install-security.py adds this one include after its server_name; CloudPanel rewrites
# the file when its custom domain or certificate changes, and install.sh adds it again.
PANEL_VHOST = Path('/etc/nginx/sites-enabled/custom-domain.conf')
PANEL_INCLUDE = Path('/etc/cloudpanel-companion/cloudpanel-access.conf')
PANEL_INCLUDE_LINE = '  include ' + str(PANEL_INCLUDE) + ';'


def panel_server_name(host):
    """The line by which CloudPanel's custom-domain vhost serves `host`."""
    return '  server_name ' + host + ';\n'


def panel_vhost(text, host):
    """CloudPanel's custom-domain vhost with the access-log include, added once."""
    anchor, include = panel_server_name(host), PANEL_INCLUDE_LINE.strip()
    if text.count(PANEL_INCLUDE_LINE) == 1 and text.count(include) == 1:
        return text
    # Any other copy of the include (a second one, or one re-indented by hand) is not ours to rewrite.
    if include in text or text.count(anchor) != 1 or text.count('server {') != 1:
        raise ValueError('CloudPanel\'s custom-domain vhost has an unexpected layout; no change made')
    return text.replace(anchor, anchor + PANEL_INCLUDE_LINE + '\n', 1)


def panel_log_state(vhost=None, include=None):
    """'connected', 'disconnected' (CloudPanel rewrote its vhost) or 'not-installed'."""
    vhost, include = vhost or PANEL_VHOST, include or PANEL_INCLUDE
    if not include.exists():
        return 'not-installed'
    try:
        text = vhost.read_text()
    except OSError:
        return 'disconnected'
    return 'connected' if text.count(PANEL_INCLUDE_LINE) == 1 else 'disconnected'


def install():
    """Write the HTTP-level rules, the website's address includes and the private log location.

    The caller tests and reloads Nginx. The includes exist before any vhost text naming
    them is offered for pasting, since Nginx refuses a configuration with a missing file.
    """
    if LOG_DIRECTORY.is_symlink():
        raise ValueError('The Companion log directory cannot be a link')
    LOG_DIRECTORY.mkdir(mode=0o750, exist_ok=True)
    os.chown(LOG_DIRECTORY, 0, 0)
    LOG_DIRECTORY.chmod(0o750)
    networks = cloudflare_ranges()
    write_private(HTTP_CONFIG, http_configuration(networks), 0o644)
    write_private(PUBLIC_TRUST, public_trust(networks), 0o644)
    write_private(BACKEND_TRUST, backend_trust(), 0o644)
    write_private(LOGROTATE, ROTATION, 0o644)


def access_entry(line):
    """One private access-log line as validated fields, or None for anything else."""
    try:
        item = json.loads(line)
        entry = {'at': float(item['at']), 'ip': str(ipaddress.ip_address(item['ip'])), 'country': item['country'],
                 'method': item['method'], 'path': item['path'], 'status': int(item['status']), 'next': item['next']}
    except (ValueError, TypeError, KeyError):
        return None
    if (not math.isfinite(entry['at']) or not isinstance(entry['country'], str)
            or (entry['country'] and not COUNTRY.fullmatch(entry['country'])) or not isinstance(entry['method'], str) or not METHOD.fullmatch(entry['method'])
            or entry['path'] not in PATHS or entry['next'] not in NEXT or not 100 <= entry['status'] <= 599):
        return None
    return entry
