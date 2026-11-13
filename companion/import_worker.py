"""Import copied SQL with only the staging OS and database identities.

SQL clients may interpret local commands as well as SQL. A source dump must
therefore never be consumed by a client running as the system administrator.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def restricted_grants(grants, database):
    scope = ' ON `' + database + '`.* TO '
    # CloudPanel grants an explicit database-level privilege list rather than
    # MariaDB's newer ALL set. Scope, not the spelling of that list, is the
    # boundary: global privileges, roles and access to any other DB are rejected.
    return (any(line.startswith('GRANT ') and scope in line for line in grants) and
            all(line.startswith('GRANT USAGE ON *.* TO ') or
                (line.startswith('GRANT ') and scope in line) for line in grants))


def main():
    if os.geteuid() == 0:
        raise SystemExit('Database import must run as the staging site identity')
    settings = json.loads(os.environ.pop('COMPANION_IMPORT_CREDENTIALS'))
    import re
    if not re.fullmatch(r'[a-z][a-z0-9_]{2,47}', settings['database']):
        raise ValueError('Invalid database')
    if settings['user'] != settings['database'] or not re.fullmatch(r'[A-Za-z0-9_-]{40,100}', settings['password']):
        raise ValueError('Invalid staging database identity')
    with tempfile.TemporaryDirectory(prefix='companion-import-') as directory:
        config = Path(directory) / 'client.cnf'
        config.write_text('[client]\nuser=' + settings['user'] + '\npassword=' + settings['password'] + '\nhost=localhost\n')
        config.chmod(0o600)
        client = ['/usr/bin/mariadb', '--defaults-extra-file=' + str(config)]
        grants = subprocess.run(client + ['--batch', '--skip-column-names', '-e', 'SHOW GRANTS FOR CURRENT_USER'],
                                capture_output=True, check=True, timeout=10).stdout.decode().splitlines()
        if not restricted_grants(grants, settings['database']):
            raise ValueError('Staging import account must have access only to its registered database')
        result = subprocess.run(['/usr/bin/mariadb', '--defaults-extra-file=' + str(config),
                                 '--binary-mode=1', '--local-infile=0', settings['database']], stdin=sys.stdin.buffer,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=600)
        if result.returncode:
            raise RuntimeError('Staging database client failed')


if __name__ == '__main__':
    main()
