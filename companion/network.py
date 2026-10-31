"""Render a default-deny IP boundary for a dedicated staging Unix identity.

WordPress filters do not cover raw sockets. This separate nftables table blocks
connections initiated by that identity, including loopback proxies, while keeping
responses to inbound application traffic working. Unix sockets and privileged
helpers require separate provisioning controls; this is not a process sandbox.
"""
import re


def table_name(uid: int) -> str:
    if type(uid) is not int or not 1000 <= uid <= 2147483647:
        raise ValueError('An explicit non-system staging UID is required')
    return f'companion_staging_{uid}'


def deny_outbound(uid: int, local_ports: tuple[int, ...] = ()) -> str:
    """Reject what the staging identity initiates; never touch packets without an owner.

    The owner test must be a positive match (`meta skuid UID jump`), not an exclusion
    (`meta skuid != UID return`). nftables cannot read an owner from packets the kernel
    sends for a socket no process holds any more: the ACK or RST of a connection already
    closed by its application (orphaned, TIME-WAIT) or of no connection at all. On those
    `meta skuid` matches neither `UID` nor `!= UID`, so the exclusion fell through to the
    reject rules for every user. That rejected the final ACK of each loopback connection
    a client closed first (oha -> Nginx, Nginx -> Varnish), left the server end in
    LAST-ACK for minutes, and stalled any new connection that reused the port pair.
    A connection the identity initiates always starts from its own socket, so the
    positive match still rejects every one of them.
    """
    name = table_name(uid)
    if any(type(port) is not int or not 1024 <= port <= 65535 for port in local_ports):
        raise ValueError('Only explicit unprivileged loopback service ports are allowed')
    local = ''.join(f'        ip daddr 127.0.0.1 tcp dport {port} return\n' for port in sorted(set(local_ports)))
    return f'''table inet {name} {{
    chain output {{
        type filter hook output priority 10; policy accept;
        meta skuid {uid} jump staging
    }}
    chain staging {{
        ct direction reply return
{local}\
        meta l4proto tcp counter reject with tcp reset
        counter reject with icmpx type admin-prohibited
    }}
}}
'''


def deny_local_submission(users: list[str], existing: str) -> str:
    """Prepend Postfix exclusions without broadening its existing allowlist."""
    if (not users or len(set(users)) != len(users) or
            any(not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', user) for user in users) or
            '\n' in existing or '\r' in existing):
        raise ValueError('Explicit staging accounts and a single Postfix value are required')
    exclusions = ['!' + user for user in sorted(users)]
    # Remove only these exact user-list entries. Other denials and lookup maps
    # keep their order; replaying provisioning must not grow duplicate entries.
    remaining = [entry.strip() for entry in existing.split(',') if entry.strip() and entry.strip() not in exclusions]
    return ', '.join(exclusions + remaining)
