"""Website probe guard: requests for secrets, configuration and backups end at Nginx.

Bots try thousands of paths such as /.env, /backup.zip or /terraform.tfstate. Many of
them used to reach WordPress, which booted for each one only to answer "not found";
one address sending them at 30 to 50 a second saturated the CPUs. This module is the
one owner of what counts as such a probe (RULES). From it come:

- the HTTP-level Nginx file that classifies `$uri` and keeps the ban list
  (000-companion-probes.conf), and the per-site security include both of a website's
  server blocks already include (<user>-security.conf). A probe gets a 404 there,
  never a 444 (Cloudflare turns a closed connection into a 520), and one line in a
  private probe log;
- a Fail2ban jail that reads only that log, never ordinary 404s, so a visitor
  following an old link is never counted: 3 probes within an hour ban the address for
  24 hours, longer for repeat offenders, up to a week;
- the Fail2ban action that enforces a ban in Nginx, keyed on the visitor address
  companion/client_address.py decides at HTTP level (CF-Connecting-IP only from
  Cloudflare's edge), so neither a forged header nor a vhost's own realip rules can
  aim a ban at someone else. All traffic arrives through Cloudflare, so a firewall ban
  would block nothing. The action keeps the
  banned addresses in a file and starts companion-probe-reload, which waits a few
  seconds before applying them: further bans while it waits join it, so a wave of bans
  costs one tested, graceful Nginx reload;
- the Security page's view of what was seen: classification for the not-found report
  and the plain Cloudflare rule conditions an operator can copy (`edge_patterns`).

Loopback, this server's own addresses, Cloudflare's ranges and the operator's allowlist
are never banned, whatever the jail asks. A probe is counted only when its address is
certain, and never inside WordPress's own folders. Requests that claim to come from a
search engine crawler or an uptime monitor still get their 404 but are never counted:
a forged claim only avoids the ban.
"""
from collections import Counter
from datetime import datetime
import fcntl
import grp
import ipaddress
import json
import math
import os
from pathlib import Path
import posixpath
import re
import subprocess
import sys
import time
from urllib.parse import unquote
from . import client_address
from .operations import write_private

HEADER = '# Managed by CloudPanel Companion.'
# Files with either header are the Companion's: the per-site include was written by the
# application safeguards (assets/cloudpanel-application-hardening.py) before this module owned it.
OWNED_PREFIX = '# Managed by CloudPanel Companion'
PROBE_LOG = client_address.LOG_DIRECTORY / 'probes.log'
LOG_FORMAT = 'companion_probe'
# CloudPanel loads sites-enabled at HTTP scope; the 000- name sorts before the vhosts using these variables.
HTTP_CONFIG = Path('/etc/nginx/sites-enabled/000-companion-probes.conf')
SITE_INCLUDES = Path('/etc/cloudpanel-companion/sites')
# The operator's allowlist and the website's own access log (for the not-found report); root only.
CONFIG = Path('/etc/cloudpanel-companion/probe-guard.json')
LOGROTATE = Path('/etc/logrotate.d/cloudpanel-companion-probes')
STATE = Path('/var/lib/cloudpanel-companion-probe-guard')
# The banned addresses as the Fail2ban action records them, and the Nginx list made from them.
BANNED = STATE / 'banned.json'
BAN_MAP = STATE / 'banned.conf'
LOCK = STATE / 'bans.lock'
JAIL = 'companion-probes'
FAIL2BAN = Path('/etc/fail2ban')
FILTER = FAIL2BAN / 'filter.d' / (JAIL + '.conf')
ACTION = FAIL2BAN / 'action.d' / 'companion-nginx-ban.conf'
JAIL_FILE = FAIL2BAN / 'jail.d' / (JAIL + '.conf')
SERVER_SETTINGS = FAIL2BAN / 'fail2ban.d' / 'cloudpanel-companion.conf'
# Fail2ban refuses to start at all (every jail, SSH's too) while one jail's log is missing.
FAIL2BAN_DROPIN = Path('/etc/systemd/system/fail2ban.service.d/companion-probes.conf')
RELOAD_UNIT = 'companion-probe-reload.service'
# How long the reload waits for further bans before applying them.
SETTLE_SECONDS = 5
SYSTEMD = Path('/etc/systemd/system')
NGINX = '/usr/sbin/nginx'
FAIL2BAN_CLIENT = '/usr/bin/fail2ban-client'

MAX_RETRY = 3
FIND_TIME = '1h'
BAN_TIME = '24h'
MAX_BAN_TIME = '1w'
# Fail2ban lengthens a repeat offender's ban from the bans its database still holds,
# which it keeps for a day by default.
DATABASE_AGE = '30d'
RULE = ('3 scans within an hour ban the address for 24 hours. Each new ban of the same address lasts twice '
        'as long, up to a week.')

# Probe classes ------------------------------------------------------------------
# Where WordPress and visitors work, at any depth (WordPress in a folder, multisite):
# nothing in a path through these folders is ever a probe. Plugins and themes ship
# all kinds of files, and a page can load a broken asset path such as
# /wp-content/plugins/x/dist/.min.js for every visitor; counting it would ban real
# visitors. The files the safeguards always hid there (dotfiles and the extensions
# below) stay hidden with a 404, without being logged or counted.
OPEN_PATHS = ('wp-content', 'wp-includes', 'wp-admin', 'wp-json')
HIDDEN_EXTENSIONS = ('sql', 'sqlite3?', 'bak', 'old', 'orig', 'save', 'swp', 'env', 'ini', 'log')
# Backups, dumps and editor swap files; configuration, secrets and keys.
SECRET_EXTENSIONS = ('bak', 'backup', 'old', 'orig', 'save', 'sav', 'swp', 'swo', 'dump',
                     'env', 'ini', 'conf', 'cfg', 'log', 'ya?ml', 'toml', 'tfvars', 'tfstate', 'py', 'sh',
                     'pem', 'key', 'ppk', 'sql', 'sqlite3?')
# At the web root only: a site's own downloads live under uploads. An archive that exists is served.
ARCHIVES = ('zip', 'rar', '7z', 'tar', 'tgz', 'gz', 'bz2', 'xz', 'zst')
ROOT_NAMES = ('kubeconfig', r'railway\.json', r'composer\.(?:json|lock)', r'package(?:-lock)?\.json')


def any_of(items):
    return '(?:' + '|'.join(items) + ')'


OPEN = any_of(OPEN_PATHS)
# A path through one of WordPress's folders, as a lookahead from the start of the path.
IN_OPEN = rf'^(?=.*/{OPEN}(?:/|$))'
DOTFILE = r'/\.(?!well-known(?:/|$))'
# (class, pattern) in Nginx map order: the first pattern found in the path decides,
# without regard to case. '' is an ordinary request.
RULES = (
    ('', r'^/\.well-known(?:/|$)'),
    ('hidden', rf'{IN_OPEN}.*{DOTFILE}'),
    ('hidden', rf'{IN_OPEN}.*\.{any_of(HIDDEN_EXTENSIONS)}$'),
    ('', rf'/{OPEN}(?:/|$)'),
    # Compressed sitemaps.
    ('', r'\.xml\.gz$'),
    ('probe', DOTFILE),
    # A wp-config name with a dot in it. WordPress slugs never contain a dot, so a post
    # such as /wp-config-explained/ is never a probe.
    ('probe', r'/wp-config[^/]*\.[^/]*$'),
    ('probe', rf'\.{any_of(SECRET_EXTENSIONS)}$'),
    ('probe', rf'^/{any_of(ROOT_NAMES)}$'),
    ('archive', rf'^/[^/]+\.{any_of(ARCHIVES)}$'),
)
COMPILED = tuple((kind, re.compile(pattern, re.I)) for kind, pattern in RULES)


def classify(path):
    """The class Nginx gives a normalized request path (its `$uri`): '', 'probe', 'archive' or 'hidden'."""
    return next((kind for kind, pattern in COMPILED if pattern.search(path)), '')


def normalized(target):
    """A request target as Nginx's `$uri`: no query string, decoded, slashes merged, dot segments resolved."""
    path = re.sub(r'/{2,}', '/', unquote(target.split('?', 1)[0].split('#', 1)[0]))
    if not path.startswith('/'):
        return None
    resolved = posixpath.normpath(path)
    return resolved + ('/' if path.endswith('/') and resolved != '/' else '')


# Requests that claim to come from a search engine crawler, a link preview or an uptime
# monitor are never counted towards a ban. Matched as whole words, case sensitive.
TRUSTED_AGENTS = ('Googlebot', 'Google-InspectionTool', 'GoogleOther', 'AdsBot-Google', 'Mediapartners-Google',
                  'Storebot-Google', 'FeedFetcher-Google', 'APIs-Google', 'bingbot', 'Applebot', 'DuckDuckBot',
                  'YandexBot', 'Baiduspider', 'facebookexternalhit', 'UptimeRobot', 'Pingdom', 'StatusCake',
                  'Better Uptime', 'Better Stack', 'Site24x7', 'Uptime-Kuma', 'HetrixTools', 'Freshping', 'jetmon',
                  'Cloudflare-Healthchecks', 'Cloudflare-Traffic-Manager')


# Nginx ------------------------------------------------------------------------

def http_configuration():
    rules = ''.join(f'    "~*{pattern}" {kind or chr(34) * 2};\n' for kind, pattern in RULES)
    return f'''{HEADER}
# The website probe guard, generated by install-probe-guard.py from companion/probe_guard.py.
# Changes here are overwritten. The website's security include acts on these variables.
# A path is "" (an ordinary request), "probe" (a secret, configuration or backup file no
# visitor asks for), "archive" (an archive at the web root: a probe unless the file exists)
# or "hidden" (a file the safeguards hide where WordPress works; never logged or counted).
map $uri $companion_probe {{
    default "";
{rules}}}
# A probe or missing archive is logged only when its address is certain: Cloudflare's edge
# naming the visitor, or a peer naming no one. CF-Connecting-IP from any other peer is forged,
# or from a Cloudflare range this server does not list yet, which must never be banned.
map "$companion_probe:$companion_via_cloudflare:$http_cf_connecting_ip" $companion_probe_counted {{
    default "";
    "~^(?:probe|archive):1:." 1;
    "~^(?:probe|archive):0:$" 1;
}}
# Only an archive's own file is looked up; no other request costs a file check.
map $companion_probe $companion_probe_archive {{
    default "";
    archive $request_filename;
}}
# Addresses the {JAIL} jail banned. Logged and refused by the visitor address decided at
# HTTP level (000-companion-security.conf), which no client header can forge, whatever
# realip rules a vhost has. In the 8080 backend that is loopback: the public block refuses first.
geo $companion_client_ip $companion_banned_client {{
    default 0;
    include {BAN_MAP};
}}
log_format {LOG_FORMAT} escape=json '{{"at":$msec,"ip":"$companion_client_ip","edge":"$realip_remote_addr","country":"$companion_client_country","host":"$server_name","method":"$request_method","path":"$uri","status":$status,"kind":"$companion_probe","agent":"$http_user_agent"}}';
'''


def site_include():
    """The per-site security include, the same text for the website and its staging copy."""
    return f'''{HEADER}
# Generated by install-probe-guard.py from companion/probe_guard.py. Changes here are overwritten.
disable_symlinks if_not_owner from=$document_root;
# An address the {JAIL} jail banned gets a 403 before anything else.
if ($companion_banned_client) {{ return 403; }}
# A probe (000-companion-probes.conf) ends here with a 404, before WordPress, and is
# logged privately for Fail2ban and the Security page. An archive that exists is a download.
set $companion_probe_hit $companion_probe;
set $companion_probe_logged $companion_probe_counted;
if (-f $companion_probe_archive) {{ set $companion_probe_hit ""; set $companion_probe_logged ""; }}
if ($companion_probe_hit) {{ return 404; }}
access_log {PROBE_LOG} {LOG_FORMAT} if=$companion_probe_logged;
# WooCommerce's private downloads: PHP hands them out with X-Accel-Redirect, never a direct request.
location ^~ /wp-content/uploads/woocommerce_uploads/ {{ internal; }}
location ~* ^/wp-content/(updraft|ai1wm-backups|backups?|wflogs)(/|$) {{ deny all; }}
location ~* ^/wp-content/(uploads|cache|upgrade|backups?)/.*[.](php[0-9]?|phtml|phar)(/|$) {{ deny all; }}
'''


def site_access_log(user):
    """CloudPanel's access log of a site, which the not-found report reads."""
    return f'/home/{user}/logs/nginx/access.log'


def site_include_path(user):
    if not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', user):
        raise ValueError('Explicit site user required')
    return SITE_INCLUDES / (user + '-security.conf')


ROTATION = f'''{PROBE_LOG} {{
    daily
    maxsize 20M
    rotate 7
    missingok
    notifempty
    nocompress
    create 0640 root adm
    postrotate
        {NGINX} -s reopen
    endscript
}}
'''


def ban_map(addresses):
    return HEADER + ' Addresses the ' + JAIL + ' jail banned.\n' + ''.join(f'{address} 1;\n' for address in addresses)


# Fail2ban -----------------------------------------------------------------------

def filter_configuration():
    agents = '|'.join(re.escape(agent) for agent in TRUSTED_AGENTS)
    return f'''{HEADER}
# Every probe-log line counts except a missing archive at the web root, which a customer
# could reach through a dead download link: it is logged for the Security page, never banned.
# Fail2ban cuts the time from the start of the line, so the rest begins with the visitor
# address Nginx decided. Fields are JSON-escaped, so none can add an unescaped quote.
[Definition]
failregex = ^,"ip":"<ADDR>",
ignoreregex = ,"kind":"archive",
              ,"agent":"[^"]*\\b(?:{agents})\\b
datepattern = ^\\{{"at":{{EPOCH}}
'''


def action_configuration():
    return f'''{HEADER}
# Bans are enforced in Nginx (companion/probe_guard.py): traffic arrives through Cloudflare,
# where a firewall ban would block nothing. Stopping Fail2ban lifts its bans; starting it
# restores the ones still running.
[Definition]
companion = cd /opt/cloudpanel-companion && /usr/bin/python3 -m companion.probe_guard
actionstart_on_demand = false
actionstart = %(companion)s clear
actionflush = %(companion)s clear
actionstop =
actioncheck =
actionban = %(companion)s ban <ip>
actionunban = %(companion)s unban <ip>
'''


def jail_configuration(allowlist):
    ignored = ' '.join(['127.0.0.0/8', '::1'] + [str(network) for network in client_address.cloudflare_ranges()]
                       + list(allowlist))
    return f'''{HEADER}
# Generated by install-probe-guard.py; changes here are overwritten. Ubuntu reads the
# journal by default, so this log-file jail names its own backend.
[{JAIL}]
enabled = true
backend = auto
filter = {JAIL}
logpath = {PROBE_LOG}
action = companion-nginx-ban
maxretry = {MAX_RETRY}
findtime = {FIND_TIME}
bantime = {BAN_TIME}
bantime.increment = true
bantime.maxtime = {MAX_BAN_TIME}
ignoreself = true
ignoreip = {ignored}
'''


def server_settings():
    return f'''{HEADER}
# Ban history is kept long enough for repeat offenders' bans to grow ({JAIL} jail).
[Definition]
dbpurgeage = {DATABASE_AGE}
'''


def fail2ban_dropin():
    return f'''{HEADER}
[Service]
ExecStartPre=-/bin/sh -c 'test -e {PROBE_LOG} || install -m 0640 -o root -g adm /dev/null {PROBE_LOG}'
'''


def allowlist(values):
    """The operator's never-ban list as explicit networks (an address is a /32 or /128)."""
    networks = []
    for value in values:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
        if network.prefixlen < (8 if network.version == 4 else 32):
            raise ValueError('An allowlist entry is implausibly wide: ' + str(network))
        networks.append(str(network))
    return list(dict.fromkeys(networks))


def files(users, allowed, access_log):
    """Every file the probe guard installs, with its mode, by what must reload to read it."""
    return {
        'settings': {CONFIG: (json.dumps({'allowlist': allowed, 'access_log': access_log}), 0o600)},
        'nginx': {HTTP_CONFIG: (http_configuration(), 0o644), LOGROTATE: (ROTATION, 0o644),
                  **{site_include_path(user): (site_include(), 0o644) for user in users}},
        'fail2ban': {FILTER: (filter_configuration(), 0o644), ACTION: (action_configuration(), 0o644),
                     JAIL_FILE: (jail_configuration(allowed), 0o644), SERVER_SETTINGS: (server_settings(), 0o644),
                     FAIL2BAN_DROPIN: (fail2ban_dropin(), 0o644)},
    }


def current(path, content):
    try:
        return path.read_text() == content
    except OSError:
        return False


def jail_running(jail=JAIL):
    try:
        return subprocess.run([FAIL2BAN_CLIENT, 'status', jail], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def wait_for_jail(jail=JAIL, seconds=30):
    """Fail2ban reports itself started before it has loaded every jail."""
    deadline = time.monotonic() + seconds
    while not jail_running(jail):
        if time.monotonic() > deadline:
            raise ValueError(f'The {jail} jail is not running; see journalctl -u fail2ban')
        time.sleep(1)


def installed(users, allowed, access_log):
    """Every file current, the probe log present and the jail running."""
    return (all(current(path, content) for group in files(users, allowed, access_log).values()
                for path, (content, _) in group.items())
            and (SYSTEMD / RELOAD_UNIT).is_file()
            and PROBE_LOG.is_file() and BAN_MAP.is_file() and jail_running())


# Bans ---------------------------------------------------------------------------

def settings():
    from .monitor import private_json
    try:
        return private_json(CONFIG)
    except (OSError, ValueError):
        return {'allowlist': [], 'access_log': None}


def own_addresses():
    """Every address on this server's interfaces."""
    try:
        result = subprocess.run(['/usr/sbin/ip', '-j', 'address', 'show'], capture_output=True, timeout=10, check=True)
        return {ipaddress.ip_address(item['local']) for interface in json.loads(result.stdout)
                for item in interface.get('addr_info', []) if 'local' in item}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return set()


def never_banned(address, allowed, local, cloudflare):
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_loopback or ip.is_unspecified or ip in local or any(ip in network for network in cloudflare)
            or any(ip in ipaddress.ip_network(network) for network in allowed))


def enforced(addresses, allowed, local, cloudflare):
    """The addresses Nginx refuses: the jail's bans less every address that is never banned."""
    return sorted(address for address in addresses if not never_banned(address, allowed, local, cloudflare))


def load_bans():
    try:
        addresses = json.loads(BANNED.read_text())
    except (OSError, ValueError):
        return []
    return [str(ipaddress.ip_address(item)) for item in addresses if isinstance(item, str)]


def change(command, address=None):
    """Record one Fail2ban ban, unban or clearing, then ask for the Nginx reload that applies it."""
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        addresses = set(load_bans())
        if command == 'clear':
            addresses = set()
        elif command == 'ban':
            config = settings()
            if never_banned(address, config.get('allowlist', []), own_addresses(), client_address.cloudflare_ranges()):
                print(f'{address} is never banned (loopback, this server, Cloudflare or the allowlist); ban not applied.',
                      file=sys.stderr)
                return
            addresses.add(address)
        else:
            addresses.discard(address)
        write_private(BANNED, json.dumps(sorted(addresses)))
    # While the reload waits, starting it again joins the waiting run, so a wave of bans makes one reload.
    subprocess.run(['/usr/bin/systemctl', 'start', '--no-block', RELOAD_UNIT], capture_output=True, timeout=30)


def apply_bans(settle=SETTLE_SECONDS):
    """Wait for further bans, then write the Nginx ban list and reload Nginx gracefully.

    A list Nginx refuses is put back as it was. A ban recorded while this run applied the
    previous list, when starting the reload again had nothing to join, is applied by the next pass.
    """
    time.sleep(settle)
    allowed, local, cloudflare = settings().get('allowlist', []), own_addresses(), client_address.cloudflare_ranges()
    reloads, applied = 0, None
    while (addresses := load_bans()) != applied:
        applied = addresses
        kept = enforced(addresses, allowed, local, cloudflare)
        text = ban_map(kept)
        previous = BAN_MAP.read_text() if BAN_MAP.exists() else None
        if text == previous:
            continue
        write_private(BAN_MAP, text, 0o644)
        try:
            test = subprocess.run([NGINX, '-t'], capture_output=True, timeout=60)
            if test.returncode:
                raise RuntimeError('nginx -t refused the configuration; the previous ban list was kept: '
                                   + test.stderr.decode(errors='replace')[-600:])
            subprocess.run(['/usr/bin/systemctl', 'reload', 'nginx'], check=True, capture_output=True, timeout=60)
        except BaseException:
            # The file keeps matching what Nginx runs, so the next pass sees the change as still to apply.
            # A missing list is put back empty: Nginx cannot start while its include is missing.
            write_private(BAN_MAP, ban_map([]) if previous is None else previous, 0o644)
            raise
        reloads += 1
    return {'banned': len(kept), 'reloads': reloads}


def prepare():
    """The state the jail and Nginx need before their configuration names it."""
    if STATE.is_symlink():
        raise ValueError('The probe guard state cannot be a link')
    STATE.mkdir(mode=0o700, exist_ok=True)
    os.chown(STATE, 0, 0)
    STATE.chmod(0o700)
    if not BANNED.exists():
        write_private(BANNED, '[]')
    if not BAN_MAP.exists():
        write_private(BAN_MAP, ban_map([]), 0o644)
    if not PROBE_LOG.exists():
        write_private(PROBE_LOG, '', 0o640)
        os.chown(PROBE_LOG, 0, grp.getgrnam('adm').gr_gid)


def active_bans():
    """(address, banned at, banned until) for each current ban, from Fail2ban itself."""
    result = subprocess.run([FAIL2BAN_CLIENT, 'get', JAIL, 'banip', '--with-time'], capture_output=True, timeout=10)
    if result.returncode:
        raise ValueError('The ' + JAIL + ' jail is not running')
    bans = []
    for line in result.stdout.decode(errors='replace').splitlines()[:1000]:
        match = re.match(r'(\S+) \t(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ (\d+) = ', line)
        if match:
            # Fail2ban prints the server's local time.
            start = int(time.mktime(time.strptime(match[2], '%Y-%m-%d %H:%M:%S')))
            bans.append((str(ipaddress.ip_address(match[1])), start, start + int(match[3])))
    return bans


# What was seen ------------------------------------------------------------------
# Paths are kept to this length; the page shows them whole.
PATH_LIMIT = 160


def probe_entry(line):
    """One probe-log line as validated fields, or None."""
    try:
        item = json.loads(line)
        entry = {'at': float(item['at']), 'ip': str(ipaddress.ip_address(item['ip'])), 'country': item['country'],
                 'host': item['host'], 'path': item['path'], 'status': int(item['status'])}
    except (ValueError, TypeError, KeyError):
        return None
    if (not math.isfinite(entry['at']) or not isinstance(entry['country'], str)
            or (entry['country'] and not client_address.COUNTRY.fullmatch(entry['country']))
            or not isinstance(entry['host'], str) or not isinstance(entry['path'], str)
            or not entry['path'].startswith('/')):
        return None
    entry['path'] = entry['path'][:PATH_LIMIT]
    return entry


# CloudPanel's `main` access-log format; its first field is the address the site's realip rules decided.
ACCESS = re.compile(r'(\S+) - \S+ \[(\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4})\] "[A-Z]{1,12} (\S+)[^"]*" (\d{3}) ')


def not_found_entry(line):
    """A 404 from the website's access log that the probe guard did not answer, or None.

    These reached the website's backend: WordPress for a page, the PHP block's own 404
    for a missing .php file. They are the candidates for new probe patterns or Cloudflare rules.
    """
    match = ACCESS.match(line)
    if not match or match[4] != '404':
        return None
    path = normalized(match[3])
    try:
        ip = str(ipaddress.ip_address(match[1]))
    except ValueError:
        return None
    if path is None or classify(path):
        return None
    return {'at': int(datetime.strptime(match[2], '%d/%b/%Y:%H:%M:%S %z').timestamp()), 'ip': ip, 'path': path[:PATH_LIMIT]}


# Never suggested for an edge rule, even when a bot asked for them and got a 404.
NEVER_AT_EDGE = re.compile(rf'/{OPEN}(?:/|$)|^/(?:\.well-known(?:/|$)|(?:robots|llms)\.txt$|wp-(?:login|cron)\.php$|'
                           r'xmlrpc\.php$|$)|\.xml(?:\.gz)?$', re.I)


# A widened edge condition leaves WordPress's folders alone, as the probe guard does.
EDGE_OUTSIDE_WORDPRESS = ' and '.join(f'not http.request.uri.path contains "/{folder}/"' for folder in OPEN_PATHS)


def edge_condition(path, kind):
    """A Cloudflare rule-language condition matching this kind of request, and whether it is widened beyond the path."""
    segments = path.strip('/').split('/')
    dotted = next((segment for segment in segments if segment.startswith('.')), None)
    name = dotted[1:].split('.', 1)[0] if dotted else ''
    extension = segments[-1].rsplit('.', 1)[-1].lower() if '.' in segments[-1] else ''
    if kind == 'probe' and re.fullmatch(r'[A-Za-z0-9_-]+', name):
        return f'http.request.uri.path contains "/.{name}"', True
    if kind == 'probe' and segments[-1].lower().startswith('wp-config.'):
        return 'http.request.uri.path contains "/wp-config."', True
    if kind == 'probe' and re.fullmatch(any_of(SECRET_EXTENSIONS), extension):
        return f'http.request.uri.path.extension eq "{extension}"', True
    return 'http.request.uri.path eq "' + path.replace('\\', '\\\\').replace('"', '\\"') + '"', False


def edge_patterns(probes, missing, limit=10):
    """Plain conditions for a manual Cloudflare rule, from (path, requests) seen in each report.

    Probes group by what makes them probes (a dot folder, an extension), and a widened
    condition leaves WordPress's folders alone; not-found pages are listed by their exact
    path, never widened, since a pattern could match real pages.
    """
    counts, sources = Counter(), {}
    for rows, source in ((probes, 'probe'), (missing, 'not-found')):
        for path, requests in rows:
            if NEVER_AT_EDGE.search(path):
                continue
            condition = edge_condition(path, classify(path) if source == 'probe' else '')
            counts[condition] += requests
            sources.setdefault(condition, source)
    top = counts.most_common(limit)
    # The expression names WordPress's folders once, for all of its conditions.
    joined = ' or '.join(f'({condition})' for (condition, _), _ in top)
    return {'conditions': [{'condition': condition + (' and ' + EDGE_OUTSIDE_WORDPRESS if widened else ''),
                            'requests': requests, 'source': sources[(condition, widened)]}
                           for (condition, widened), requests in top],
            'expression': f'({joined}) and {EDGE_OUTSIDE_WORDPRESS}' if any(widened for (_, widened), _ in top) else joined}


def main(arguments):
    command = arguments[0] if arguments else ''
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    if command in ('ban', 'unban') and len(arguments) == 2:
        change(command, str(ipaddress.ip_address(arguments[1])))
    elif command == 'clear' and len(arguments) == 1:
        change('clear')
    elif command == 'reload' and len(arguments) == 1:
        print(json.dumps(apply_bans()))
    else:
        raise SystemExit('Use: ban ADDRESS | unban ADDRESS | clear | reload')


if __name__ == '__main__':
    main(sys.argv[1:])
