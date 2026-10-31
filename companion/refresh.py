"""Refresh staging using a new private files/database generation.

The current staging database is never imported over. Switching and rollback
exchange directories atomically as the staging Unix identity. The previous
directory and database remain available for explicit operator recovery.
"""
import argparse
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import subprocess
import time
from .monitor import private_json
from .operations import Operations, write_private
from .provision import command, transfer, import_database, site_wp
from .staging import Site, validate_pair


def application_health(site):
    if not re.fullmatch(r'companion-health-[a-f0-9]{32}\.php', site['health_file']):
        raise ValueError('Invalid registered application health endpoint')
    response = command(['/usr/bin/curl', '--silent', '--show-error', '--fail', '--max-time', '5',
                        '--retry', '2', '--retry-delay', '1', '--retry-all-errors', '--retry-max-time', '8',
                        '--resolve', site['host'] + ':443:127.0.0.1',
                        'https://' + site['host'] + '/' + site['health_file']], timeout=20)
    if len(response) > 4096:
        raise ValueError('Invalid application health response')
    data = json.loads(response)
    if data.get('ready') is not True or data.get('staging') is not True:
        raise ValueError('Staging PHP/database health is not ready')
    if data.get('timestamp_validation') is not True or not 0 <= data.get('revalidate_seconds', 99) <= 5:
        raise ValueError('Staging requires timestamp validation with a bounded revalidation interval')
    return data


def stop_staging_requests(user, host, php_version):
    """Stop the paused pool's original workers; refuse queued requests.

    FPM may immediately create an idle replacement. Waiting for an entirely
    empty pool confuses those new workers with an old in-flight request. PID
    descriptors pin the original processes without risking PID reuse.
    """
    import select
    import stat
    uid = pwd.getpwnam(user).pw_uid
    if os.geteuid() != uid:
        if os.geteuid() != 0:
            raise ValueError('Only the registered website owner can stop its PHP requests')
        # The operations service retains identity-switching capabilities, not
        # a global ability to kill other users' processes. Signal as the site
        # owner so the service and standalone operator paths have one contract.
        result = subprocess.run(['/usr/sbin/runuser', '-u', user, '--', '/usr/bin/python3',
            '-m', 'companion.stop_requests', '--user', user, '--host', host, '--php', php_version],
            cwd='/opt/cloudpanel-companion', capture_output=True, timeout=15,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
        if result.returncode:
            raise ValueError('Website-owner PHP quiescence failed; inspect the native pool and queue')
        return
    if php_version not in ('8.2', '8.3', '8.4') or not re.fullmatch(r'[a-z0-9.-]+', host):
        raise ValueError('Invalid registered PHP pool')
    pool = Path('/etc/php') / php_version / 'fpm/pool.d' / (host + '.conf')
    descriptor = os.open(pool, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('PHP pool must be operator-owned')
        configuration = stream.read(65537)
    users = re.findall(r'^user\s*=\s*(\S+)\s*$', configuration, re.M)
    ports = re.findall(r'^listen\s*=\s*127\.0\.0\.1:([0-9]+)\s*$', configuration, re.M)
    if users != [user] or len(ports) != 1 or not 1024 <= int(ports[0]) <= 65535:
        raise ValueError('Native PHP pool identity or listener changed')

    def no_queue():
        result = command(['/usr/bin/ss', '-H', '-ltn', 'sport = :' + ports[0]], timeout=5)
        listeners = result.decode().splitlines()
        if len(listeners) != 1 or listeners[0].split()[1] != '0':
            raise ValueError('Staging PHP has queued requests; version switch refused')

    no_queue()
    expected = ('php-fpm: pool ' + host).encode()
    originals = []
    try:
        for process in Path('/proc').iterdir():
            if not process.name.isdigit():
                continue
            descriptor = None
            try:
                descriptor = os.pidfd_open(int(process.name))
                if process.stat().st_uid != uid:
                    continue
                if (process / 'cmdline').read_bytes().split(b'\0', 1)[0] != expected:
                    continue
                originals.append(descriptor)
                descriptor = None
            except (OSError, ProcessLookupError):
                continue
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        for descriptor in originals:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
            except ProcessLookupError:
                pass
        pending, deadline = list(originals), time.monotonic() + 5
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Original staging PHP workers did not stop; version switch refused')
            completed, _, _ = select.select(pending, [], [], remaining)
            pending = [descriptor for descriptor in pending if descriptor not in completed]
        no_queue()
    finally:
        for descriptor in originals:
            os.close(descriptor)


def refresh(specification, registry, site_id, state):
    if os.geteuid() != 0:
        raise ValueError('Refresh requires an operator-controlled root invocation')
    os.umask(0o077)
    spec = private_json(specification)
    registered = private_json(registry)
    site = registered['sites'][site_id]
    source, original_target = Site(**spec['source']), Site(**spec['target'])
    validate_pair(source, original_target)
    if (site['host'] != original_target.host or site['user'] != original_target.user or
            site['source_host'] != source.host or state.exists() or
            state.resolve() != state or not state.is_relative_to('/var/lib/cloudpanel-companion-jobs')):
        raise ValueError('Refresh must bind a new private job to the registered staging site')
    if original_target.root.resolve() != original_target.root:
        raise ValueError('Staging root cannot contain symlinks')
    locks = Path('/var/lib/cloudpanel-companion-jobs/locks')
    locks.mkdir(mode=0o700, exist_ok=True)
    lock = os.open(locks / (original_target.user + '.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        before = application_health(site)
        isolation = 'companion-isolation-' + original_target.user + '.service'
        command(['/usr/bin/systemctl', 'is-active', isolation])
        size = int(command(['/usr/sbin/runuser', '-u', source.user, '--', '/usr/bin/du', '-sb', str(source.root)]).split()[0])
        # The coordinator does not need a capability to read other users' homes.
        # Ask the staging owner for filesystem capacity at its actual mount.
        disk = json.loads(command(['/usr/sbin/runuser', '-u', original_target.user, '--', '/usr/bin/python3',
            '-c', 'import json,shutil,sys; d=shutil.disk_usage(sys.argv[1]); print(json.dumps({"free":d.free,"total":d.total}))',
            str(original_target.root)]))
        if disk['free'] < size * 2 + max(1024 ** 3, disk['total'] // 20):
            raise ValueError('Insufficient free space for a new generation and recovery reserve')
        state.mkdir(mode=0o700)
        receipt = {'source': source.host, 'target': original_target.host, 'phase': 'prepared',
                   'old_database_identity': before['database_identity'], 'health_before': before,
                   'original_policy': Operations(registered).action({'site': site_id, 'operation': 'status'})}

        def phase(value):
            receipt['phase'] = value
            write_private(state / 'receipt.json', json.dumps(receipt, indent=2))

        phase('prepared')
        database = original_target.user.replace('-', '')[:18] + 'r' + secrets.token_hex(6)
        target = Site(original_target.host, original_target.user, database, original_target.php_version)
        password = secrets.token_urlsafe(30)
        write_private(state / 'database.json', json.dumps({'user': database, 'password': password}))
        command(['clpctl', 'db:add', '--domainName=' + target.host, '--databaseName=' + database,
                 '--databaseUserName=' + database, '--databaseUserPassword=' + password])
        phase('new-database-created')
        prefix = command(site_wp(source) + ['config', 'get', 'table_prefix', '--type=variable']).decode().strip()
        task = {'source': asdict(source), 'target': asdict(target), 'database_user': database,
                'database_password': password, 'table_prefix': prefix, 'prepare_only': True,
                'health_file': site['health_file']}
        prepared = transfer(source, target, task)
        generation = Path(prepared['generation'])
        if (generation.parent != Path('/home') / target.user / '.companion-generations' or
                not re.fullmatch(r'\.companion-clone-[a-f0-9]{24}', generation.name)):
            raise ValueError('Clone worker returned an unexpected generation')
        receipt['recovery_generation'] = str(generation)
        receipt['new_database_identity'] = hashlib.sha256(database.encode()).hexdigest()
        phase('generation-prepared')
        class Arguments:
            pass
        arguments = Arguments()
        arguments.state = state
        import_database(source, target, arguments, receipt, password, work_root=generation)
        phase('generation-ready')
        operations = Operations(registered)
        original_policy = operations.action({'site': site_id, 'operation': 'status'})
        exchange = ['/usr/sbin/runuser', '-u', target.user, '--', '/usr/bin/python3', '-m', 'companion.exchange',
                    '--user', target.user, '--host', target.host, '--generation', str(generation)]
        switched, safe_to_resume = False, False
        operations.action({'site': site_id, 'operation': 'pause', 'enabled': True, 'actor': 'system:staging-refresh'}, internal=True)
        try:
            stop_staging_requests(target.user, target.host, target.php_version)
            phase('exchange-intent')
            command(exchange)
            switched = True
            phase('generation-switched')
            time.sleep(before['revalidate_seconds'] + 1)
            after = application_health(site)
            if after['database_identity'] != receipt['new_database_identity']:
                raise ValueError('Web PHP did not load the new staging database generation')
            safe_to_resume = True
            phase('completed')
        except Exception:
            if switched:
                stop_staging_requests(target.user, target.host, target.php_version)
                command(exchange)
                time.sleep(before['revalidate_seconds'] + 1)
                restored = application_health(site)
                safe_to_resume = restored['database_identity'] == before['database_identity']
                phase('rolled-back' if safe_to_resume else 'recovery-needs-review')
            raise
        finally:
            if safe_to_resume or not switched:
                operations.action({'site': site_id, 'operation': 'pause', 'enabled': original_policy['paused'],
                                   'actor': 'system:staging-refresh'}, internal=True)
        return receipt
    finally:
        os.close(lock)


def recover_interrupted(registry, site_id, state):
    """Resolve interrupted refresh by database identity, never blind directory swapping."""
    registered = private_json(registry)
    site = registered['sites'][site_id]
    receipt = private_json(state / 'receipt.json')
    if receipt['target'] != site['host']:
        raise ValueError('Interrupted job belongs to another site')
    if receipt['phase'] in ('completed', 'rolled-back'):
        return receipt
    if 'original_policy' not in receipt:
        raise ValueError('Interrupted job predates recovery qualification; inspect it manually')
    operations = Operations(registered)
    operations.action({'site': site_id, 'operation': 'pause', 'enabled': True,
                       'actor': 'system:interrupted-refresh'}, internal=True)
    spec = private_json(Path(site['specification']))
    target = Site(**spec['target'])
    if target.user != site['user'] or target.host != site['host']:
        raise ValueError('Recovery specification no longer matches the registered staging identity')
    database = command(site_wp(target) + ['config', 'get', 'DB_NAME']).decode().strip()
    identity = hashlib.sha256(database.encode()).hexdigest()
    if identity == receipt.get('new_database_identity'):
        version = private_json(Path(site['specification']))['target']['php_version']
        stop_staging_requests(site['user'], site['host'], version)
        command(['/usr/sbin/runuser', '-u', site['user'], '--', '/usr/bin/python3', '-m', 'companion.exchange',
                 '--user', site['user'], '--host', site['host'], '--generation', receipt['recovery_generation']])
    elif identity != receipt['old_database_identity']:
        raise ValueError('Current staging generation is unknown; it remains paused for inspection')
    time.sleep(receipt['health_before']['revalidate_seconds'] + 1)
    restored = application_health(site)
    if restored['database_identity'] != receipt['old_database_identity']:
        raise ValueError('Interrupted staging recovery could not confirm the previous database')
    receipt['phase'] = 'rolled-back'
    receipt['recovered_after_interruption'] = True
    write_private(state / 'receipt.json', json.dumps(receipt, indent=2))
    operations.action({'site': site_id, 'operation': 'pause', 'enabled': receipt['original_policy']['paused'],
                       'actor': 'system:interrupted-refresh'}, internal=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--specification', type=Path, required=True)
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--site', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--confirm-staging-refresh', action='store_true', required=True)
    args = parser.parse_args()
    print(json.dumps(refresh(args.specification, args.registry, args.site, args.state)))
