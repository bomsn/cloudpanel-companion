"""Authenticated site revisions using stock Varnish's configuration lifecycle.

Page requests never visit this service. Only content writes do. Activation of a
new hash namespace precedes the success response, keeping pre-edit in-flight
renders out of future reads without a version-specific compiled VMOD.
"""
import argparse
import fcntl
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading

from .cache_config import render
from .monitor import private_json


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
        except Exception:
            os.close(self.lock_fd)
            raise
        try:
            for host in self.keys:
                self.set_ready(host, False)
        except Exception:
            os.close(self.lock_fd)
            raise

    def close(self):
        for host in self.keys:
            self.set_ready(host, False)
        os.close(self.lock_fd)

    def marker(self, host):
        return self.ready / (hashlib.sha256(host.encode()).hexdigest() + '.ready')

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
        connection = ['-T', '127.0.0.1:6082', '-S', str(self.secret)] if self.secret else ['-n', str(self.instance)]
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
        import grp
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


class ControlServer(http.server.HTTPServer):
    request_queue_size = 16

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2)
        return connection, address


class Handler(http.server.BaseHTTPRequestHandler):
    def do_PURGE(self):
        if (self.path != '/' or self.headers.get('Transfer-Encoding') or
                self.headers.get('Content-Length', '0') != '0' or
                self.headers.get('X-Cache-Manager-For-CloudPanel-Tag')):
            self.respond(400)
            return
        hosts = self.headers.get_all('Host', [])
        keys = self.headers.get_all('X-Cache-Manager-For-CloudPanel-Key', [])
        if (len(hosts) != 1 or len(keys) != 1 or
                not self.server.controller.authenticated(hosts[0], keys[0])):
            self.respond(403)
            return
        try:
            self.server.controller.activate(hosts[0])
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            self.respond(503)
            return
        self.respond(200)

    def respond(self, code):
        self.send_response(code)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', '0')
        if code == 200:
            self.send_header('X-Cache-Manager-For-CloudPanel-Policy', 'site-revision-v1')
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
