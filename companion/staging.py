"""Validate staging identities before a privileged executor can consume them.

This module does not execute a clone. A plan is not a safety qualification: the
executor must establish access and network isolation before loading copied code.
"""
from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True)
class Site:
    host: str
    user: str
    database: str
    php_version: str

    def validate(self):
        if (not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', self.user) or
                not re.fullmatch(r'[a-z][a-z0-9_]{2,47}', self.database) or
                not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', self.host) or
                self.php_version not in ('8.2', '8.3', '8.4')):
            raise ValueError('Invalid staging site identity')

    @property
    def root(self):
        self.validate()
        return Path('/home') / self.user / 'htdocs' / self.host


def validate_pair(source: Site, target: Site):
    source.validate()
    target.validate()
    if source.host == target.host or source.user == target.user or source.database == target.database:
        raise ValueError('Staging must have a different hostname, operating-system user and database')
    if source.php_version != target.php_version:
        raise ValueError('Clone with the same PHP version before testing an upgrade separately')


def protected_template(original: str, password_file: str, access_include: str | None = None) -> str:
    """Use a new operator-owned template, never edit the vendor template in place."""
    if not re.fullmatch(r'/etc/cloudpanel-companion/[a-z0-9_-]+\.htpasswd', password_file):
        raise ValueError('Invalid staging password file')
    root_anchor = '  {{root}}'
    php_anchor = '    fastcgi_param PHP_VALUE "{{php_settings}}";'
    if (original.count(root_anchor) != 2 or original.count(php_anchor) != 1 or
            original.count('    {{varnish_proxy_pass}}') != 1 or
            original.count('    auth_basic off;\n') != 1):
        raise ValueError('Installed WordPress template has changed; review before generating a staging template')
    protection = (root_anchor + '\n  auth_basic "Private staging";\n'
                  f'  auth_basic_user_file {password_file};\n'
                  '  add_header X-Robots-Tag "noindex, nofollow, noarchive" always;\n'
                  '  location = /wp-cron.php { return 403; }')
    if access_include is not None:
        if not re.fullmatch(r'/etc/cloudpanel-companion/sites/[a-z][a-z0-9-]{2,30}-access[.]conf', access_include):
            raise ValueError('Invalid registered staging access include')
        protection = (root_anchor + '\n  include ' + access_include + ';\n'
                      '  add_header X-Robots-Tag "noindex, nofollow, noarchive" always;\n'
                      '  location = /wp-cron.php { return 403; }')
    result = original.replace(root_anchor, protection).replace('    auth_basic off;\n', '')
    # ACME tokens are the only public files needed for certificate renewal.
    # A token-only path cannot match PHP, nested paths or other well-known data.
    acme = ('  location ~ ^/\\.well-known/acme-challenge/[A-Za-z0-9_-]+$ {\n'
            '    auth_basic off;\n    try_files $uri =404;\n'
            '    default_type text/plain;\n  }\n\n')
    anchor = '  location ~ /.well-known {'
    if result.count(anchor) != 1:
        raise ValueError('Installed ACME route has changed; review the staging template')
    result = result.replace(anchor, acme + anchor)
    # Custom templates do not necessarily receive CloudPanel's cache placeholder
    # expansion. Staging deliberately bypasses page cache; never leave the
    # frontend without a PHP upstream where it could serve PHP source as a file.
    result = result.replace('    {{varnish_proxy_pass}}', '    proxy_pass http://127.0.0.1:8080;')
    # This template has no CloudPanel cache-controller ownership. Preserve all
    # other panel PHP settings, and override only its auto-prepend in this site.
    return result.replace(php_anchor, php_anchor + '\n    fastcgi_param PHP_ADMIN_VALUE "auto_prepend_file=none";')
