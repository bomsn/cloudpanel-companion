"""Read-only, serialized comparison of registered website and staging code."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from .code_compare import differences
from .monitor import private_json
from .operations import write_private
from .staging import Site, validate_pair

ROOT = Path('/var/lib/cloudpanel-companion-jobs/gui-compare')


class Comparison:
    def __init__(self, registry_path, site_id):
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', site_id):
            raise ValueError('Invalid registered website')
        registered = private_json(registry_path)['sites'][site_id]
        spec = private_json(Path(registered['specification']))
        self.website, self.staging = Site(**spec['source']), Site(**spec['target'])
        validate_pair(self.website, self.staging)
        if (self.website.host != registered['source_host'] or self.staging.host != registered['host'] or
                self.staging.user != registered['user']):
            raise ValueError('Code comparison does not match the registered pair')
        self.parent = ROOT / site_id
        self.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def state_path(self, value):
        path = Path(value)
        if (path.parent != self.parent or not re.fullmatch(r'[0-9]{10,30}-[a-f0-9]{16}', path.name) or
                path.is_symlink() or path.resolve() != path):
            raise ValueError('Invalid private comparison state')
        return path

    def current(self):
        pointer = self.parent / 'latest.json'
        if not pointer.exists():
            return None, None
        state = self.state_path(private_json(pointer)['state'])
        return state, private_json(state / 'summary.json', max_bytes=1024 * 1024)

    def snapshot(self):
        return self.current()[1]

    def invalidate(self):
        pointer = self.parent / 'latest.json'
        if pointer.exists():
            private_json(pointer)
            pointer.unlink()
            descriptor = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def detail(self, folder, page=1, generation=None):
        if not isinstance(folder, str) or not re.fullmatch(r'[a-f0-9]{64}', folder) or type(page) is not int or not 1 <= page <= 500:
            raise ValueError('Choose a folder from the completed check')
        state, summary = self.current()
        if state is None or generation != state.name:
            raise ValueError('That comparison is no longer current. Check changes again.')
        selected = next((item for item in summary['folders'] if item['id'] == folder), None) if summary else None
        if selected is None:
            raise ValueError('That comparison is no longer current. Check changes again.')
        detail = private_json(state / (folder + '.json'), max_bytes=32 * 1024 * 1024)
        start = (page - 1) * 200
        return {'folder': selected, 'generation': state.name, 'rows': detail['rows'][start:start + 200], 'page': page,
                'pages': max(1, (len(detail['rows']) + 199) // 200), 'excluded': detail['excluded'][:50]}

    def inventory(self, site):
        result = subprocess.run(['runuser', '-u', site.user, '--', '/usr/bin/python3', '-m', 'companion.code_compare'],
                                input=json.dumps({'root': str(site.root)}).encode() + b'\n',
                                capture_output=True, timeout=90, cwd='/opt/cloudpanel-companion',
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
        if result.returncode or len(result.stdout) > 32 * 1024 * 1024:
            raise ValueError('Some code could not be checked safely. No files changed; check again after any edits finish.')
        return json.loads(result.stdout)

    def retire(self, current):
        """Retain three completed checks; comparison metadata is not recovery data."""
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('Safe comparison retention requires descriptor-based removal')
        states = []
        for path in self.parent.iterdir():
            if re.fullmatch(r'[0-9]{10,30}-[a-f0-9]{16}', path.name) and path.is_dir() and not path.is_symlink():
                self.state_path(path)
                if path.stat().st_uid == 0:
                    states.append(path)
        states.sort(key=lambda path: int(path.name.split('-')[0]), reverse=True)
        for path in states[3:]:
            if path != current:
                shutil.rmtree(path)
                log = path.with_name(path.name + '.log')
                if log.is_file() and not log.is_symlink() and log.stat().st_uid == 0:
                    log.unlink()

    def run(self, state):
        state = self.state_path(state)
        state.mkdir(mode=0o700)
        def phase(value):
            write_private(state / 'receipt.json', json.dumps({'phase': value}))
        try:
            phase('scanning-website')
            website = self.inventory(self.website)
            phase('scanning-staging')
            staging = self.inventory(self.staging)
            phase('comparing-code')
            folders, details = differences(website, staging)
            for identity, detail in details.items():
                write_private(state / (identity + '.json'), json.dumps(detail))
            summary = {'generation': state.name, 'checked_at': int(time.time()), 'website_host': self.website.host, 'staging_host': self.staging.host,
                       'folders': folders, 'changed_folders': sum(folder['changed'] > 0 for folder in folders),
                       'changed_files': sum(folder['changed'] for folder in folders),
                       'website_only': sum(folder['website_only'] for folder in folders),
                       'excluded': sum(folder['excluded'] for folder in folders),
                       'checked_files': website['file_count'] + staging['file_count']}
            write_private(state / 'summary.json', json.dumps(summary))
            write_private(self.parent / 'latest.json', json.dumps({'state': str(state)}))
            phase('completed')
        except Exception:
            phase('comparison-failed')
            raise
        self.retire(state)
        return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--site', required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('The registered coordinator runs as the operator')
    Comparison(args.registry, args.site).run(args.state)


if __name__ == '__main__':
    main()
