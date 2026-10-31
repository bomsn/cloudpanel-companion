"""Unprivileged clone preparation for an already isolated staging identity.

Provisioning and database import are separate privileged orchestration steps.
This worker only writes files its own Unix identity can write. It never accepts
commands, shell fragments or a source database connection from web input.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile
from pathlib import PurePosixPath
from .staging import Site, validate_pair


def php_string(value):
    return "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"


def exclusions():
    return ['wp-config.php', '.user.ini', 'php.ini', '.htaccess', '.git',
            'wp-content/cache', 'wp-content/debug.log', 'wp-content/object-cache.php',
            'wp-content/advanced-cache.php', 'wp-content/db.php', '.companion-*', 'companion-health-*.php', 'companion-release-*.php', 'companion-origin-*.php']


def receive_archive(stream, destination):
    """Extract a bounded regular-file stream with no links or special files."""
    total, count = 0, 0
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            relative = member.name.removeprefix('./')
            if relative in ('', '.'):
                continue
            parts = PurePosixPath(relative).parts
            if (member.issym() or member.islnk() or not (member.isfile() or member.isdir()) or
                    '\\' in relative or relative.startswith('/') or '..' in parts):
                raise ValueError('Source contains a link, special file or unsafe path; review it before cloning')
            count += 1
            total += member.size
            if count > 500000 or total > 64 * 1024 ** 3:
                raise ValueError('Clone exceeds supported file-count or size limits')
            path = destination.joinpath(*parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o755)
            else:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                incoming = archive.extractfile(member)
                with path.open('xb') as output:
                    shutil.copyfileobj(incoming, output, length=1024 * 1024)
                path.chmod(0o644)


def prepare(task):
    source, target = Site(**task['source']), Site(**task['target'])
    validate_pair(source, target)
    import pwd
    if os.geteuid() == 0 or pwd.getpwuid(os.geteuid()).pw_name != target.user:
        raise ValueError('The staging site identity must execute the clone worker')
    if target.root.resolve() != target.root or not target.root.is_dir():
        raise ValueError('Staging root must be an existing explicit directory')
    prepared_only = task.get('prepare_only') is True
    if (target.root / 'wp-config.php').exists() and not prepared_only:
        raise ValueError('Existing staging content requires an explicit refresh workflow')
    generations = Path('/home') / target.user / '.companion-generations'
    generations.mkdir(mode=0o700, exist_ok=True)
    if generations.resolve() != generations or generations.stat().st_uid != os.geteuid():
        raise ValueError('Invalid private generations directory')
    generation = generations / ('.companion-clone-' + secrets.token_hex(12))
    generation.mkdir(mode=0o700)
    retain = False
    try:
        receive_archive(sys.stdin.buffer, generation)
        mu = generation / 'wp-content/mu-plugins'
        mu.mkdir(parents=True, exist_ok=True)
        assets = Path(__file__).resolve().parent.parent / 'assets'
        shutil.copyfile(assets / 'staging-guard.php', mu / '000-companion-staging.php')
        shutil.copyfile(assets / 'staging-policy.php', mu / 'staging-policy.php')
        shutil.copyfile(assets / 'staging-relay.php', mu / 'staging-relay.php')
        definitions = {'DB_NAME': target.database, 'DB_USER': task['database_user'],
                       'DB_PASSWORD': task['database_password'], 'DB_HOST': 'localhost',
                       'DB_CHARSET': 'utf8mb4', 'DB_COLLATE': '',
                       'WP_HOME': 'https://' + target.host, 'WP_SITEURL': 'https://' + target.host,
                       'WP_ENVIRONMENT_TYPE': 'staging',
                       'CLOUDPANEL_COMPANION_STAGING_POLICY': '/etc/cloudpanel-companion/sites/' + target.user + '.json',
                       'CLOUDPANEL_COMPANION_STAGING_RELAY': '/run/cloudpanel-companion-relay/' + target.user + '/transport.sock'}
        for key in ('AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
                    'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'):
            definitions[key] = secrets.token_urlsafe(64)
        prefix = task['table_prefix']
        import re
        if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', prefix):
            raise ValueError('Invalid table prefix')
        config = '<?php\n' + '\n'.join('define(' + php_string(key) + ', ' + php_string(value) + ');'
                                       for key, value in definitions.items())
        config += "\ndefine('DISABLE_WP_CRON', true);\ndefine('CLOUDPANEL_COMPANION_STAGING', true);\n"
        config += "define('DISALLOW_FILE_EDIT', true);\ndefine('WP_DEBUG_DISPLAY', false);\n"
        config += '$table_prefix = ' + php_string(prefix) + ';\n'
        config += "/* That's all, stop editing! Happy publishing. */\n"
        config += "if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }\nrequire_once ABSPATH . 'wp-settings.php';\n"
        (generation / 'wp-config.php').write_text(config)
        (generation / 'wp-config.php').chmod(0o600)
        health_file = task.get('health_file')
        if health_file:
            if not re.fullmatch(r'companion-health-[a-f0-9]{32}\.php', health_file):
                raise ValueError('Invalid health endpoint')
            shutil.copyfile(assets / 'application-health.php', generation / health_file)
        if prepared_only:
            print(json.dumps({'phase': 'generation-prepared', 'generation': str(generation)}))
            retain = True
            return
        # The public target is still empty and password protected. Copy only
        # after the complete guarded generation has been prepared successfully.
        if any(target.root.iterdir()):
            raise ValueError('Target root must be empty before clone installation')
        for entry in generation.iterdir():
            entry.rename(target.root / entry.name)
        print(json.dumps({'phase': 'guarded-files-installed', 'host': target.host}))
    finally:
        if not retain:
            shutil.rmtree(generation)


if __name__ == '__main__':
    raw = os.environ.pop('COMPANION_CLONE_TASK')
    if len(raw) > 65536:
        raise SystemExit('Clone task too large')
    prepare(json.loads(raw))
