"""The certificate authority the Companion trusts for the website's own certificate.

Behind Cloudflare's proxy a website can use a Cloudflare Origin CA certificate:
Cloudflare's edge trusts it, the system store does not. The Companion's website
checks connect to the origin on this server, so they meet that certificate and
verify it against the bundle installed here. Verification is never turned off.

The installed file is the one setting every check reads; without it they use the
system store, as for Let's Encrypt. Checks of other hosts never use it.
"""
from pathlib import Path
import re
import stat
from .operations import write_private

CONFIG = Path('/etc/cloudpanel-companion')
CLOUDFLARE_ORIGIN_CA = Path(__file__).resolve().parents[1] / 'assets' / 'cloudflare-origin-ca.crt'


def bundle_path(host):
    if not re.fullmatch(r'[a-z0-9.-]{1,253}', host):
        raise ValueError('Explicit website hostname required')
    return CONFIG / ('site-ca-' + host + '.crt')


def site_ca_file(host):
    """The website's installed bundle, or None for the system store."""
    path = bundle_path(host)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    # Root checks and the monitoring user both read it; whoever could change it
    # could make them accept any certificate for the website.
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('The website certificate authority must be a root-owned file only root can change')
    return str(path)


def curl_trust(host):
    """curl arguments that verify the website's origin certificate like the monitoring probe."""
    ca_file = site_ca_file(host)
    return ['--cacert', ca_file] if ca_file else []


def install(host, source):
    # World-readable: the monitoring service reads it as its own unprivileged user.
    write_private(bundle_path(host), Path(source).read_text(), 0o644)


def remove(host):
    bundle_path(host).unlink(missing_ok=True)
