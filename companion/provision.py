"""Provision one private staging clone from an operator-owned specification.

The web application must never supply this specification. Site identity,
database privileges and network isolation are established before copied code
executes. Failed jobs retain their private evidence and require inspection.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile

from .monitor import private_json
from .network import deny_outbound, table_name, deny_local_submission
from .staging import Site, validate_pair, protected_template

# Workers run as the staging owner, who cannot read an operator's checkout (for
# example /root/cloudpanel-companion), so they import the installed shared runtime.
RUNTIME = '/opt/cloudpanel-companion'


def command(args, *, data=None, timeout=180):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        diagnostic = result.stdout + result.stderr
        for arg in args:
            if 'password=' in arg.lower():
                diagnostic = diagnostic.replace(arg.split('=', 1)[1].encode(), b'[redacted]')
        error = Path('/var/lib/cloudpanel-companion-jobs/last-command-error.txt')
        error.write_bytes(diagnostic[:65536])
        error.chmod(0o600)
        raise RuntimeError(f'{Path(args[0]).name} failed with status {result.returncode}')
    return result.stdout


def site_wp(site, root=None):
    """Keep maintenance PHP identical to the registered site's web runtime."""
    site.validate()
    return ['/usr/sbin/runuser', '-u', site.user, '--', '/usr/bin/php' + site.php_version,
            '/usr/bin/wp', '--path=' + str(root or site.root)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--specification', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--resume-empty-site', action='store_true')
    parser.add_argument('--resume-files-installed', action='store_true')
    parser.add_argument('--resume-database-created', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Provisioning requires an operator-controlled root invocation')
    os.umask(0o077)
    spec = private_json(args.specification)
    source, target = Site(**spec['source']), Site(**spec['target'])
    validate_pair(source, target)
    if not re.fullmatch(r'[a-z][a-z0-9]{2,31}', target.database):
        raise ValueError('New CloudPanel staging databases use 3–32 lowercase letters/digits, starting with a letter')
    if args.resume_files_installed:
        receipt = private_json(args.state / 'receipt.json')
        if receipt != {'source': source.host, 'target': target.host, 'phase': 'guarded-files-installed'}:
            raise ValueError('This job is not waiting for its initial database import')
        database = private_json(args.state / 'database.json')
        if database['user'] != target.database:
            raise ValueError('Database identity mismatch')
        return import_database(source, target, args, receipt, database['password'])
    if args.resume_database_created:
        receipt = private_json(args.state / 'receipt.json')
        if receipt != {'source': source.host, 'target': target.host, 'phase': 'separate-database-created'}:
            raise ValueError('This job is not waiting for its initial file copy')
        database = private_json(args.state / 'database.json')
        if database['user'] != target.database:
            raise ValueError('Database identity mismatch')
        prefix = command(site_wp(source) + ['config', 'get', 'table_prefix', '--type=variable']).decode().strip()
        return copy_and_import(source, target, args, receipt, prefix, database['password'])
    if args.resume_empty_site:
        receipt = private_json(args.state / 'receipt.json')
        if receipt != {'source': source.host, 'target': target.host, 'phase': 'private-empty-site-created'}:
            raise ValueError('This job is not an interrupted empty-site preparation')
        if (target.root / 'wp-config.php').exists() or not (Path('/etc/cloudpanel-companion') / (target.user + '.htpasswd')).is_file():
            raise ValueError('Interrupted site is not an authenticated empty fixture')
        prefix = command(site_wp(source) + ['config', 'get', 'table_prefix', '--type=variable']).decode().strip()
        return finish(source, target, args, receipt, prefix)
    resuming_preparation = False
    if args.state.exists():
        previous = private_json(args.state / 'receipt.json')
        resuming_preparation = previous == {'source': source.host, 'target': target.host, 'phase': 'prepared'}
    if (args.state.exists() and not resuming_preparation) or Path('/home', target.user).exists():
        raise ValueError('Existing staging identity/job must be inspected; creation will not overwrite it')
    if args.state.resolve() != args.state or not args.state.is_relative_to('/var/lib/cloudpanel-companion-jobs'):
        raise ValueError('Use an explicit private job directory under the companion state root')
    if not source.root.is_dir() or source.root.resolve() != source.root:
        raise ValueError('Registered source root is unavailable')
    source_identity = pwd.getpwnam(source.user)
    if source.root.stat().st_uid != source_identity.pw_uid:
        raise ValueError('Source site identity does not own its root')
    args.state.mkdir(parents=True, mode=0o700, exist_ok=resuming_preparation)
    receipt = {'source': source.host, 'target': target.host, 'phase': 'prepared'}

    def phase(value):
        receipt['phase'] = value
        (args.state / 'receipt.json').write_text(json.dumps(receipt, indent=2))

    phase('prepared')

    def wp_get(key, kind='constant'):
        return command(site_wp(source) + ['config', 'get', key, '--type=' + kind]).decode().strip()

    if wp_get('DB_NAME') != source.database:
        raise ValueError('Registered source database does not match WordPress configuration')
    prefix = wp_get('table_prefix', 'variable')
    policy_root = Path('/etc/cloudpanel-companion')
    auth = policy_root / (target.user + '.htpasswd')
    if auth.exists() and not resuming_preparation:
        raise ValueError('Staging authentication file already exists')
    if not resuming_preparation:
        password = secrets.token_urlsafe(32)
        auth.write_bytes(command(['htpasswd', '-niB', 'staging'], data=(password + '\n').encode()))
        auth.chmod(0o600)
        (args.state / 'access.json').write_text(json.dumps({'username': 'staging', 'password': password}))
    from .operations import render_access, write_private
    access = policy_root / 'sites' / (target.user + '-access.conf')
    access.parent.mkdir(mode=0o755, exist_ok=True)
    write_private(access, render_access(target.user, {'protected': True, 'paused': False}), 0o644)
    # The include belongs in CloudPanel's stored template from creation onward;
    # editing only the generated file is lost at the next native settings save.
    template = protected_template(command(['clpctl', 'vhost-template:view', '--name=WordPress']).decode(), str(auth), str(access))
    template_directory = Path('/var/tmp') / ('companion-template-' + secrets.token_hex(12))
    template_directory.mkdir(mode=0o750)
    template_directory.chmod(0o750)
    shutil.chown(template_directory, 'root', 'clp')
    template_path = template_directory / 'staging.tpl'
    template_path.write_text(template)
    template_path.chmod(0o640)
    shutil.chown(template_path, 'root', 'clp')
    template_name = 'Companion ' + target.user
    try:
        command(['clpctl', 'vhost-template:add', '--name=' + template_name, '--file=' + str(template_path)])
        command(['clpctl', 'site:add:php', '--domainName=' + target.host, '--phpVersion=' + target.php_version,
                 '--vhostTemplate=' + template_name, '--siteUser=' + target.user,
                 '--siteUserPassword=' + secrets.token_urlsafe(40)])
    finally:
        shutil.rmtree(template_directory)
    command(['usermod', '--lock', target.user])
    phase('private-empty-site-created')
    return finish(source, target, args, receipt, prefix)


def finish(source, target, args, receipt, prefix):
    policy_root = Path('/etc/cloudpanel-companion')
    identity = pwd.getpwnam(target.user)

    def phase(value):
        receipt['phase'] = value
        (args.state / 'receipt.json').write_text(json.dumps(receipt, indent=2))

    policy = policy_root / (target.user + '-outbound.nft')
    policy.write_text(deny_outbound(identity.pw_uid))
    policy.chmod(0o600)
    from .isolation import install
    install(identity.pw_uid)
    mail = command(['postconf', '-h', 'authorized_submit_users']).decode().strip()
    command(['postconf', '-e', 'authorized_submit_users = ' + deny_local_submission([target.user], mail)])
    unit_name = 'companion-isolation-' + target.user + '.service'
    unit = Path('/etc/systemd/system') / unit_name
    unit.write_text('[Unit]\nDescription=Companion staging outbound isolation\nAfter=ufw.service\n'
                    'Before=php' + target.php_version + '-fpm.service\n[Service]\nType=oneshot\n'
                    'WorkingDirectory=/opt/cloudpanel-companion\n'
                    'ExecStart=/usr/bin/python3 -m companion.isolation --uid ' + str(identity.pw_uid) + '\nRemainAfterExit=yes\n'
                    '[Install]\nWantedBy=multi-user.target\n')
    unit.chmod(0o644)
    dropins = Path('/etc/systemd/system') / ('php' + target.php_version + '-fpm.service.d')
    dropins.mkdir(exist_ok=True, mode=0o755)
    (dropins / ('companion-' + target.user + '.conf')).write_text(
        '[Unit]\nRequires=' + unit_name + '\nAfter=' + unit_name + '\n')
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', unit_name])
    # Verify the endpoint is accepting connections, then require an explicit
    # denial for the staging UID. TCP reset rejects surface as ECONNREFUSED.
    with socket.create_connection(('127.0.0.1', 443), 2):
        pass
    probe = ('import socket,errno\ntry: socket.create_connection(("127.0.0.1",443),2)\n'
             'except OSError as e: raise SystemExit(0 if e.errno in (errno.EACCES,errno.EPERM,errno.ECONNREFUSED) else 2)\n'
             'raise SystemExit(1)')
    blocked = subprocess.run(['runuser', '-u', target.user, '--', '/usr/bin/python3', '-c', probe],
                             capture_output=True, timeout=5)
    if blocked.returncode != 0:
        raise RuntimeError('Staging raw outbound boundary is not active')
    phase('network-isolated')
    dbuser = target.database
    dbpassword = secrets.token_urlsafe(30)
    (args.state / 'database.json').write_text(json.dumps({'user': dbuser, 'password': dbpassword}))
    command(['clpctl', 'db:add', '--domainName=' + target.host, '--databaseName=' + target.database,
             '--databaseUserName=' + dbuser, '--databaseUserPassword=' + dbpassword])
    phase('separate-database-created')
    return copy_and_import(source, target, args, receipt, prefix, dbpassword)


def copy_and_import(source, target, args, receipt, prefix, dbpassword):
    """Copy the guarded files into the empty staging root, then import the database."""
    def phase(value):
        receipt['phase'] = value
        (args.state / 'receipt.json').write_text(json.dumps(receipt, indent=2))

    dbuser = target.database
    from dataclasses import asdict
    task = {'source': asdict(source), 'target': asdict(target), 'database_user': dbuser,
            'database_password': dbpassword, 'table_prefix': prefix}
    # CloudPanel may supply an empty index; remove only that known placeholder,
    # under the target identity, before the worker requires an empty webroot.
    placeholder = target.root / 'index.php'
    if placeholder.exists():
        if placeholder.stat().st_size > 4096:
            raise ValueError('Unexpected content in new staging root')
        command(['runuser', '-u', target.user, '--', '/usr/bin/rm', '--', str(placeholder)])
    transfer(source, target, task)
    phase('guarded-files-installed')
    return import_database(source, target, args, receipt, dbpassword)


def transfer(source, target, task):
    from .clone_worker import exclusions
    archive_args = ['runuser', '-u', source.user, '--', '/usr/bin/tar', '-C', str(source.root), '-c']
    archive_args.extend('--exclude=./' + item for item in exclusions())
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'COMPANION_CLONE_TASK': json.dumps(task)}
    with tempfile.TemporaryFile() as errors:
        sender = subprocess.Popen(archive_args + ['.'], stdout=subprocess.PIPE, stderr=errors)
        try:
            receiver = subprocess.run(['/usr/sbin/runuser', '-u', target.user, '--', '/usr/bin/python3', '-m', 'companion.clone_worker'],
                                      stdin=sender.stdout, capture_output=True, timeout=1800, env=environment, cwd=RUNTIME)
            sender.stdout.close()
            if receiver.returncode:
                sender.terminate()
                error = Path('/var/lib/cloudpanel-companion-jobs/last-clone-error.txt')
                error.write_bytes(receiver.stderr[:65536])
                error.chmod(0o600)
                raise RuntimeError('Isolated clone receiver failed; inspect private diagnostic')
            if sender.wait(timeout=30) != 0:
                raise RuntimeError('Source archive stream failed')
        finally:
            if sender.poll() is None:
                sender.terminate()
            sender.wait(timeout=10)
    return json.loads(receiver.stdout)


# The forms in which a URL's "//host" is stored, as PCRE: plain (http://, https:// and
# protocol-relative), JSON-escaped (\/\/, Elementor data and SEO image metadata),
# JSON-escaped twice, and URL-encoded (%2F%2F, as in redirect_to parameters).
URL_HOST_PREFIXES = ('//', r'\\/\\/', r'\\\\\\/\\\\\\/', '%2[Ff]%2[Ff]')


def host_rewrite(old, new):
    """WP-CLI `search-replace --regex` arguments moving every stored URL form of `old` to `new`.

    The host must end there: `old.example.com` is not part of `old.example.com.au`,
    `old.example.community` or `sub.old.example.com`. Emails and file paths, which
    have no `//` before the host, are records and stay as they are.
    """
    for host in (old, new):
        if not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', host):
            raise ValueError('Explicit lowercase hostnames required')
    pattern = '(' + '|'.join(URL_HOST_PREFIXES) + ')' + old.replace('.', r'\.') + r'(?![A-Za-z0-9-]|\.[A-Za-z0-9])'
    return pattern, '${1}' + new


def import_database(source, target, args, receipt, dbpassword, work_root=None):
    dbuser = target.database

    def phase(value):
        receipt['phase'] = value
        (args.state / 'receipt.json').write_text(json.dumps(receipt, indent=2))

    # Source export is executed using its existing database identity. Target
    # import uses only the new database identity, never database administrator.
    dump = args.state / 'database.sql'
    with dump.open('wb') as stream:
        result = subprocess.run(site_wp(source) + ['db', 'export', '-', '--single-transaction', '--skip-lock-tables'],
                                stdout=stream, stderr=subprocess.PIPE, timeout=600)
        if result.returncode:
            diagnostic = args.state / 'database-export-error.txt'
            diagnostic.write_bytes(result.stderr[:65536])
            diagnostic.chmod(0o600)
            raise RuntimeError('Source database export failed')
    with dump.open('rb') as stream:
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'COMPANION_IMPORT_CREDENTIALS':
                       json.dumps({'database': target.database, 'user': dbuser, 'password': dbpassword})}
        result = subprocess.run(['/usr/sbin/runuser', '-u', target.user, '--', '/usr/bin/python3', '-m', 'companion.import_worker'],
                                stdin=stream, capture_output=True, timeout=650, env=environment, cwd=RUNTIME)
        if result.returncode:
            raise RuntimeError('Staging database import failed')
    phase('database-imported')
    wp = site_wp(target, work_root) + ['--skip-plugins', '--skip-themes']
    search, replacement = host_rewrite(source.host, target.host)
    command(wp + ['search-replace', search, replacement, '--regex', '--regex-delimiter=#',
                  '--all-tables-with-prefix', '--skip-columns=guid', '--precise'], timeout=600)
    command(wp + ['option', 'update', 'blog_public', '0'])
    # Import/search-replace changes WordPress data, not Nginx configuration.
    # Routing is validated by its installer and the subsequent real PHP check;
    # a data workflow must not require global access to unrelated Nginx logs.
    dump.unlink()
    phase('clone-complete-acceptance-pending')
    return receipt


if __name__ == '__main__':
    print(json.dumps(main()))
