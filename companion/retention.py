"""Retire only staging generations attested by private operator job receipts.

Never derive a privileged database deletion from a site's editable wp-config.
Active/unknown jobs are retained. Current health and the retained recovery
versions protect every database that can still be used by those versions.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
from .monitor import private_json
from .operations import write_private
from .refresh import application_health
from .staging import Site, validate_pair


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def generation_name(path, user):
    root = Path('/home') / user / '.companion-generations'
    path = Path(path)
    if path.parent != root or not re.fullmatch(r'\.companion-clone-[a-f0-9]{24}', path.name):
        raise ValueError('Unregistered recovery generation')
    return path.name


def job_created(state):
    """Creation order from the job's immutable name, never its directory mtime.

    Writing retirement progress into a receipt changes the directory mtime,
    which previously reordered jobs and could expose the newest recovery
    generation to retirement. Names without a recorded nanosecond timestamp
    sort as newest so they stay protected.
    """
    match = re.search(r'(?:^|-)(\d{19})(?:-|$)', Path(state).name)
    return int(match.group(1)) if match else sys.maxsize


def remove_generation(user, name):
    """Execute the destructive filesystem step as the isolated staging owner."""
    account = pwd.getpwnam(user)
    if os.geteuid() == 0 or account.pw_uid != os.geteuid():
        raise ValueError('Generation removal requires the staging Unix identity')
    directory = Path('/home') / user / '.companion-generations'
    generation_name(directory / name, user)
    if directory.resolve() != directory or directory.stat().st_uid != os.geteuid():
        raise ValueError('Invalid generations directory')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('Recovery generation changed')
        shutil.rmtree(name, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)


def plan(receipts, current_identity, initial_database, user, keep=2):
    if type(keep) is not int or not 1 <= keep <= 10:
        raise ValueError('Retain between one and ten recovery versions per outcome')
    known = {sha(initial_database): initial_database}
    for item in receipts:
        database = item.get('database')
        if database:
            if database != initial_database and not re.fullmatch(re.escape(user.replace('-', '')[:18]) + r'r[a-f0-9]{12}', database):
                if item['receipt'].get('phase') in ('completed', 'rolled-back') and item['receipt'].get('recovery_generation'):
                    raise ValueError('Job database does not match the staging identity')
                # A failed pre-provisioning record may contain a rejected name.
                # It cannot authorize deletion and remains available for review.
                continue
            known[sha(database)] = database
    candidates, protected = [], {current_identity}
    for phase in ('completed', 'rolled-back'):
        finished = sorted((item for item in receipts if item['receipt'].get('phase') == phase and
                           item['receipt'].get('recovery_generation') and not item['receipt'].get('retired_at')),
                          key=lambda item: item['created'], reverse=True)
        for index, item in enumerate(finished):
            receipt = item['receipt']
            identity = receipt['old_database_identity'] if phase == 'completed' else receipt['new_database_identity']
            generation_name(receipt['recovery_generation'], user)
            if index < keep:
                protected.add(identity)
            else:
                candidates.append((item, identity))
    # Unfinished/unknown states need explicit review, not guessed cleanup.
    for item in receipts:
        if item['receipt'].get('phase') not in ('completed', 'rolled-back'):
            for key in ('old_database_identity', 'new_database_identity'):
                if key in item['receipt']:
                    protected.add(item['receipt'][key])
    result = []
    for item, identity in candidates:
        database = known.get(identity)
        if database is None or identity in protected:
            continue
        result.append({'state': str(item['state']), 'generation': item['receipt']['recovery_generation'],
                       'database': database, 'database_identity': identity})
    return result


def retire(registry_path, site_id, keep=2, apply=False):
    if os.geteuid() != 0:
        raise ValueError('Retention requires the operator-owned registry')
    registered = private_json(registry_path)
    site = registered['sites'][site_id]
    spec = private_json(Path(site['specification']))
    source, target = Site(**spec['source']), Site(**spec['target'])
    validate_pair(source, target)
    if site['user'] != target.user or site['host'] != target.host or site['source_host'] != source.host:
        raise ValueError('Registry does not match staging specification')
    lock_path = Path('/var/lib/cloudpanel-companion-jobs/locks') / (target.user + '.lock')
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = application_health(site)
        receipts = []
        root = Path('/var/lib/cloudpanel-companion-jobs')
        for receipt_path in root.rglob('receipt.json'):
            if len(receipts) >= 1000:
                raise ValueError('Review job history before further retention')
            receipt = private_json(receipt_path)
            if receipt.get('target') != target.host:
                continue
            state = receipt_path.parent
            data = state / 'database.json'
            database = private_json(data).get('user') if data.exists() else None
            receipts.append({'state': state, 'receipt': receipt, 'database': database,
                             'created': job_created(state)})
        selected = plan(receipts, before['database_identity'], target.database, target.user, keep)
        for item in selected:
            if item['database'] == source.database:
                raise ValueError('Source database cannot be retired')
            if not apply:
                continue
            if application_health(site)['database_identity'] == item['database_identity']:
                raise ValueError('Database became active; retention stopped')
            receipt_path = Path(item['state']) / 'receipt.json'
            receipt = private_json(receipt_path)
            receipt['retirement_started_at'] = int(time.time())
            write_private(receipt_path, json.dumps(receipt, indent=2))
            subprocess.run(['/usr/sbin/runuser', '-u', target.user, '--', '/usr/bin/python3', '-m',
                            'companion.retention', '--remove-user', target.user,
                            '--generation', generation_name(item['generation'], target.user)],
                           check=True, capture_output=True, timeout=180,
                           cwd='/opt/cloudpanel-companion')
            deletion = subprocess.run(['clpctl', 'db:delete', '--databaseName=' + item['database']],
                                      input=b'yes\n', capture_output=True, timeout=60)
            absent = ('Database "' + item['database'] + '" does not exist.').encode()
            if deletion.returncode and absent not in deletion.stdout + deletion.stderr:
                raise RuntimeError('Native staging database retirement failed; review receipt')
            receipt['retired_at'] = int(time.time())
            write_private(receipt_path, json.dumps(receipt, indent=2))
        return {'site': site_id, 'apply': apply, 'keep_per_outcome': keep,
                'candidates': [{key: value for key, value in item.items() if key != 'database_identity'} for item in selected],
                'healthy_after': application_health(site)['database_identity'] == before['database_identity']}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', type=Path)
    parser.add_argument('--site')
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--keep', type=int, default=2)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--remove-user')
    parser.add_argument('--generation')
    arguments = parser.parse_args()
    if arguments.remove_user:
        remove_generation(arguments.remove_user, arguments.generation)
    elif arguments.registry and arguments.site:
        print(json.dumps(retire(arguments.registry, arguments.site, arguments.keep, arguments.apply), indent=2))
    elif arguments.registry and arguments.all:
        registry = private_json(arguments.registry)
        results = []
        for site in registry['sites']:
            try:
                results.append(retire(arguments.registry, site, arguments.keep, arguments.apply))
            except BlockingIOError:
                results.append({'site': site, 'skipped': 'A staging workflow holds its lock'})
        print(json.dumps(results, indent=2))
    else:
        parser.error('Supply a registry/site or an unprivileged generation removal')


if __name__ == '__main__':
    main()
