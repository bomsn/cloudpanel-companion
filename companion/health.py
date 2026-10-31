"""Bounded HTTP/TLS probes shared by panel adapters and external monitoring.

Inventory belongs to the operator. Probes never discover or modify sites, submit
forms, follow redirects, or disable certificate verification. A redirect is only
healthy when the operator explicitly includes its status in the expected set.
"""
from dataclasses import asdict, dataclass
import http.client
import json
import socket
import ssl
import time
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Target:
    name: str
    url: str
    expected_statuses: tuple[int, ...] = (200,)
    timeout: float = 8
    certificate_warning_days: int = 21
    connect_host: str | None = None
    ca_file: str | None = None
    expected_json: dict | None = None

    def validate(self):
        parsed = urlsplit(self.url)
        if (not self.name or len(self.name) > 128 or
                parsed.scheme not in ('http', 'https') or not parsed.hostname or
                parsed.username or parsed.password or parsed.fragment or
                any(ord(c) < 32 for c in self.url) or
                not 0 < self.timeout <= 30 or
                not self.expected_statuses or
                any(not isinstance(s, int) or not 100 <= s <= 599 for s in self.expected_statuses)):
            raise ValueError('Invalid health target configuration')
        if self.ca_file and parsed.scheme != 'https':
            raise ValueError('A certificate authority file requires HTTPS')
        if self.expected_json is not None:
            if (not isinstance(self.expected_json, dict) or not 1 <= len(self.expected_json) <= 10 or
                    any(not isinstance(key, str) or not 1 <= len(key) <= 64 or
                        type(value) not in (str, int, bool, type(None)) or
                        (isinstance(value, str) and len(value) > 256) for key, value in self.expected_json.items())):
                raise ValueError('Application expectations require a small JSON object of literal fields')
        return parsed


@dataclass(frozen=True)
class Observation:
    name: str
    healthy: bool
    category: str
    status: int | None
    elapsed_ms: int
    certificate_days: int | None = None

    def to_dict(self):
        return asdict(self)


def probe(target: Target) -> Observation:
    parsed = target.validate()
    started = time.monotonic()
    sock = None
    status = None
    days = None
    category = 'connection'
    healthy = False
    try:
        # Separate connect address and TLS hostname allows an origin check while
        # preserving SNI, Host and hostname validation for its actual domain.
        sock = socket.create_connection((target.connect_host or parsed.hostname,
                                         parsed.port or (443 if parsed.scheme == 'https' else 80)), target.timeout)
        if parsed.scheme == 'https':
            category = 'tls'
            context = ssl.create_default_context(cafile=target.ca_file)
            remaining = target.timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError()
            sock.settimeout(remaining)
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
            cert = sock.getpeercert()
            days = int((ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) // 86400)
        category = 'http'
        remaining = target.timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError()
        sock.settimeout(remaining)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        request = (f'GET {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\n'
                   'User-Agent: CloudPanel-Companion-Health/0.1\r\n'
                   'Accept: text/html\r\nConnection: close\r\n\r\n')
        sock.sendall(request.encode('ascii'))
        response = http.client.HTTPResponse(sock)
        response.begin()
        status = response.status
        healthy = status in target.expected_statuses
        category = 'healthy' if healthy else 'unexpected-status'
        if healthy and target.expected_json is not None:
            raw = response.read(65537)
            try:
                body = json.loads(raw) if len(raw) <= 65536 else None
            except (ValueError, UnicodeError):
                body = None
            healthy = isinstance(body, dict) and all(
                key in body and type(body[key]) is type(value) and body[key] == value
                for key, value in target.expected_json.items())
            if not healthy:
                category = 'application-check-failed'
        if healthy and days is not None and days <= target.certificate_warning_days:
            category = 'certificate-expiring'
        response.close()
    except socket.gaierror:
        category = 'dns'
    except ssl.SSLCertVerificationError:
        category = 'certificate-invalid'
    except (TimeoutError, socket.timeout):
        category += '-timeout'
    except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError):
        # Do not log URLs/headers/exception strings: these may contain credentials.
        category += '-failure'
    finally:
        if sock is not None:
            sock.close()
    return Observation(target.name, healthy, category, status,
                       round((time.monotonic() - started) * 1000), days)
