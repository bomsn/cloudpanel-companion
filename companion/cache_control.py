"""Authenticated site revisions using stock Varnish's configuration lifecycle.

Page requests never visit this service. Only content writes do. Activation of a
new hash namespace precedes the success response, keeping pre-edit in-flight
renders out of future reads without a version-specific compiled VMOD. A
single-page clear bans that page's stored objects instead and repeats the ban
once any render already in flight must have finished.
"""
import argparse
import fcntl
import grp
import hmac
import http.server
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time

from .cache_config import ADMIN_PORT, FETCH_SECONDS, STORED_HOST, STORED_URL, ready_marker, render
from .monitor import private_json

# The contract with Cache Manager for CloudPanel. A PURGE authenticates its site
# with KEY_HEADER, optionally names one page with PAGE_HEADER, and POLICY_HEADER
# reports what was cleared: that page (URL_BAN) or the whole site (SITE_REVISION).
# An OPTIONS request with the same Host and key checks them and clears nothing.
KEY_HEADER = 'X-Cache-Manager-For-CloudPanel-Key'
PAGE_HEADER = 'X-Cache-Manager-For-CloudPanel-Url'
TAG_HEADER = 'X-Cache-Manager-For-CloudPanel-Tag'
POLICY_HEADER = 'X-Cache-Manager-For-CloudPanel-Policy'
URL_BAN = 'url-ban-v1'
SITE_REVISION = 'site-revision-v1'
# A request target as a browser sends it: visible ASCII only, so whitespace,
# CR/LF and raw non-ASCII bytes cannot reach the Varnish CLI line.
PAGE = re.compile(r'/[\x21-\x7e]{0,2047}')
# A fetch that began before a ban is stored after it, with pre-ban content.
# Varnish ends any fetch still waiting after FETCH_SECONDS; the margin covers
# connection setup and header reception.
REPEAT_SECONDS = FETCH_SECONDS + 10
# Distinct pages of one site awaiting their repeat. Beyond this the site is
# changing broadly, and one site revision replaces the individual bans.
REPEAT_LIMIT = 256


def cli_string(value: str) -> str:
    """Quote one Varnish CLI argument; inside quotes only \\ and " are special."""
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def ban_expression(host: str, page: str) -> str:
    """Ban one page of one site, tested against stored objects.

    The rendered VCL stamps each object with its host and URL, so the ban lurker
    retires matches in the background; a req.* ban would stay on the list until
    every older object expired. The policy stores a page under its URL after
    dropping campaign parameters. A page given without a query also matches
    query variants a policy may store; one given with a query matches only itself.
    """
    # PCRE's metacharacters outside a character class. Escaped, each is a
    # literal; every other visible ASCII character already is one.
    pattern = re.sub(r'([\\^$.|?*+()\[\]{}])', r'\\\1', page)
    # WordPress links spell percent-escapes in lowercase, browsers encoding typed
    # text in uppercase, and Varnish stores each spelling separately.
    pattern = re.sub(r'%([0-9A-Fa-f]{2})', r'%(?i:\1)', pattern)
    pattern = '^' + pattern + ('$' if '?' in page else '([?]|$)')
    return f'obj.http.{STORED_HOST} == {cli_string(host)} && obj.http.{STORED_URL} ~ {cli_string(pattern)}'


class RevisionController:
    def __init__(self, config: dict, policy: str, state: Path, instance: Path, ready: Path, secret: Path | None = None):
        render(config, policy)  # Validate the complete registry before touching Varnish.
        for path in (state, instance, ready):
            if path.is_symlink() or not path.is_dir() or path.resolve() != path:
                raise ValueError('Explicit existing directories are required')
        info = state.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Cache control state must be private and owned by the service user')
        info = ready.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Cache availability markers must be service-owned and not writable by other users')
        self.config, self.policy, self.state, self.instance = config, policy, state, instance
        self.ready = ready
        self.secret = secret
        self.keys = {site['host']: site['purge_key'] for site in config['sites']}
        self.lock = threading.Lock()
        self.revisions = {host: secrets.token_hex(16) for host in self.keys}
        self.active = None
        self.lock_fd = os.open(state / 'controller.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for host in self.keys:
                self.set_ready(host, False)
        except Exception:
            os.close(self.lock_fd)
            raise
        self.repeats = {}  # (host, page) -> monotonic time its ban is repeated
        self.repeat_ready = threading.Condition()
        self.closing = False
        self.repeater = threading.Thread(target=self.repeat_bans, daemon=True)
        self.repeater.start()

    def close(self):
        with self.repeat_ready:
            self.closing = True
            self.repeat_ready.notify()
        self.repeater.join()
        for host in self.keys:
            self.set_ready(host, False)
        os.close(self.lock_fd)

    def marker(self, host):
        return ready_marker(host, self.ready)

    def set_ready(self, host, enabled):
        """Default Nginx to uncached PHP until a fresh revision is active.

        A failed purge must not leave old public HTML reachable. Marker removal
        makes the frontend bypass Varnish without retrying a shopper request.
        The systemd runtime directory also disappears on process failure.
        """
        path = self.marker(host)
        if enabled:
            temporary = self.ready / ('.new-' + secrets.token_hex(16))
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            try:
                os.fchmod(descriptor, 0o644)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(b'ready\n')
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        else:
            path.unlink(missing_ok=True)
        descriptor = os.open(self.ready, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def authenticated(self, host: str, key: str) -> bool:
        expected = self.keys.get(host)
        return expected is not None and len(key) == 64 and hmac.compare_digest(expected, key)

    def admin(self, *arguments, diagnostic=True):
        connection = ['-T', f'127.0.0.1:{ADMIN_PORT}', '-S', str(self.secret)] if self.secret else ['-n', str(self.instance)]
        result = subprocess.run(['varnishadm', *connection, *arguments],
                                capture_output=True, timeout=10)
        if result.returncode:
            if diagnostic:
                path = self.state / 'last-control-error.txt'
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write((result.stdout + result.stderr)[-8192:])
            raise RuntimeError('Varnish did not accept the configuration operation')
        return result.stdout.decode()

    def activate(self, host: str | None = None):
        with self.lock:
            if host is not None and host not in self.keys:
                raise ValueError('Unknown site')
            affected = [host] if host is not None else list(self.keys)
            for selected in affected:
                self.set_ready(selected, False)
            revisions = dict(self.revisions)
            if host is not None:
                revisions[host] = secrets.token_hex(16)
            name = 'cmcp_' + secrets.token_hex(16)
            # Varnish deliberately compiles as its unprivileged account. Keep
            # credential/state files private and expose only secret-free VCL
            # through a separate root-owned, compiler-readable directory.
            compiler_dir = self.state.parent / 'vcl-input'
            compiler_gid = grp.getgrnam('varnish').gr_gid
            if not compiler_dir.exists():
                compiler_dir.mkdir(mode=0o750)
                compiler_dir.chmod(0o750)
                os.chown(compiler_dir, os.geteuid(), compiler_gid)
            info = compiler_dir.lstat()
            if (compiler_dir.is_symlink() or not compiler_dir.is_dir() or
                    info.st_uid != os.geteuid() or info.st_gid != compiler_gid or info.st_mode & 0o027):
                raise ValueError('Compiler input directory must be owned and compiler-readable only')
            candidate = compiler_dir / (name + '.vcl')
            descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            os.fchmod(descriptor, 0o640)
            os.fchown(descriptor, os.geteuid(), compiler_gid)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(render(self.config, self.policy, revisions))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                self.admin('vcl.load', name, str(candidate))
                self.admin('vcl.use', name)
            except Exception:
                # An unactivated candidate must never be reported as a purge.
                try:
                    self.admin('vcl.discard', name, diagnostic=False)
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                raise
            finally:
                candidate.unlink(missing_ok=True)
            self.revisions, self.active = revisions, name
            self.cleanup()
            for selected in affected:
                self.set_ready(selected, True)
            return name

    def cleanup(self):
        # Discard only configurations owned by this controller. Varnish retains
        # in-flight references until they finish; this does not terminate reads.
        try:
            for line in self.admin('vcl.list').splitlines():
                parts = line.split()
                if len(parts) == 5 and parts[0] != 'active' and parts[-1].startswith('cmcp_'):
                    self.admin('vcl.discard', parts[-1])
        except (RuntimeError, subprocess.TimeoutExpired):
            # Successful activation remains successful. The next write retries
            # housekeeping; Varnish's own VCL limit prevents unbounded growth.
            pass

    def clear_page(self, host: str, page: str) -> str:
        """Remove one page of one site and return the policy actually applied.

        Whenever a ban cannot be relied on, a site revision clears the whole site
        instead, so a reported clear never leaves the old page reachable.
        """
        if host not in self.keys:
            raise ValueError('Unknown site')
        with self.repeat_ready:
            crowded = ((host, page) not in self.repeats and
                       sum(site == host for site, _ in self.repeats) >= REPEAT_LIMIT)
        if not crowded and self.ban(host, page):
            with self.repeat_ready:
                self.repeats[(host, page)] = time.monotonic() + REPEAT_SECONDS
                self.repeat_ready.notify()
            return URL_BAN
        self.activate(host)
        return SITE_REVISION

    def ban(self, host: str, page: str) -> bool:
        try:
            self.admin('ban', ban_expression(host, page))
        except (RuntimeError, subprocess.TimeoutExpired):
            return False
        return True

    def repeat_bans(self):
        """Repeat each page ban once every render begun before it has ended.

        Varnish tests a ban only against objects stored before it, so a render in
        flight when content changed would be stored afterwards with the old
        content. A site revision avoids this by changing the hash namespace; a
        page ban gets the same guarantee from one repeat after the fetch bound.
        Repeats pending at shutdown are dropped: startup activates new revisions.
        """
        while True:
            with self.repeat_ready:
                while True:
                    if self.closing:
                        return
                    due = min(self.repeats, key=self.repeats.get, default=None)
                    remaining = None if due is None else self.repeats[due] - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        break
                    self.repeat_ready.wait(remaining)
                del self.repeats[due]
            if not self.ban(*due):
                try:
                    self.activate(due[0])
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
                    # Activation removed the site's availability marker first, so
                    # Nginx serves the site uncached until a later clear succeeds.
                    pass


class ControlServer(http.server.HTTPServer):
    request_queue_size = 16

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2)
        return connection, address


class Handler(http.server.BaseHTTPRequestHandler):
    def do_PURGE(self):
        pages = self.headers.get_all(PAGE_HEADER, [])
        if len(pages) > 1 or (pages and not PAGE.fullmatch(pages[0])):
            self.respond(400)
            return
        host = self.authenticated_host()
        if host is None:
            return
        try:
            if pages:
                policy = self.server.controller.clear_page(host, pages[0])
            else:
                self.server.controller.activate(host)
                policy = SITE_REVISION
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            self.respond(503)
            return
        self.respond(200, policy)

    def do_OPTIONS(self):
        """Check a site's credential and the path to Varnish without clearing anything.

        A connection test must not purge: a PURGE for a page can fall back to a
        whole-site revision. The answer names the most specific policy a clear
        applies. Controllers that predate this check answer 501 and clear nothing.
        """
        if self.headers.get(PAGE_HEADER) is not None:
            self.respond(400)
            return
        if self.authenticated_host() is None:
            return
        try:
            self.server.controller.admin('ping', diagnostic=False)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            self.respond(503)
            return
        self.respond(200, URL_BAN)

    def authenticated_host(self):
        """The request's registered site, or None once the request has been refused."""
        if (self.path != '/' or self.headers.get('Transfer-Encoding') or
                self.headers.get('Content-Length', '0') != '0' or self.headers.get(TAG_HEADER)):
            self.respond(400)
            return None
        hosts = self.headers.get_all('Host', [])
        keys = self.headers.get_all(KEY_HEADER, [])
        if (len(hosts) != 1 or len(keys) != 1 or
                not self.server.controller.authenticated(hosts[0], keys[0])):
            self.respond(403)
            return None
        return hosts[0]

    def respond(self, code, policy=None):
        self.send_response(code)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', '0')
        if policy:
            # What a clear removed (or, for a check, can remove): one page or the whole site.
            self.send_header(POLICY_HEADER, policy)
        self.end_headers()

    def log_message(self, *_args):
        # Request headers contain the purge credential. Do not log raw requests.
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--instance', type=Path, required=True)
    parser.add_argument('--ready', type=Path, required=True)
    parser.add_argument('--secret', type=Path)
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Use an unprivileged local port')
    os.umask(0o077)
    if (args.ready.parent.parent != Path('/run') or args.ready.name != 'ready' or
            not args.ready.parent.name.startswith('cache-manager-') or args.ready.is_symlink() or
            args.ready.resolve() != args.ready):
        raise ValueError('Availability markers require an explicit cache-manager runtime directory')
    args.ready.mkdir(mode=0o755, exist_ok=True)
    if args.ready.stat().st_uid != os.geteuid():
        raise ValueError('Availability directory belongs to another identity')
    os.chmod(args.ready, 0o755)
    controller = RevisionController(private_json(args.config), args.policy.read_text(), args.state, args.instance, args.ready, args.secret)
    try:
        # Bind before activation so a duplicate listener cannot change routing.
        with ControlServer(('127.0.0.1', args.port), Handler) as server:
            server.controller = controller
            controller.activate()
            server.serve_forever()
    finally:
        controller.close()


if __name__ == '__main__':
    main()
