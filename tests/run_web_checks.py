"""Run web boundary tests with disposable state, never production accounts."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time


def main():
    with tempfile.TemporaryDirectory(prefix='companion-web-tests-') as directory:
        root = Path(directory)
        socket = root / 'redis.sock'
        config = root / 'web.json'
        config.write_text(json.dumps({
            'secret_key': secrets.token_urlsafe(64),
            'host': 'ops.example.com', 'state_directory': directory,
            'security_cache_url': 'unix://' + str(socket),
            'snapshot_path': str(root / 'snapshot.json'),
            'panel_url': 'https://panel.example.com',
            'site_url': 'https://site.example.com', 'site_name': 'Test site',
        }))
        config.chmod(0o600)
        environment = dict(os.environ, COMPANION_WEB_CONFIG=str(config),
                           DJANGO_SETTINGS_MODULE='companion_web.settings')
        process = subprocess.Popen(['redis-server', '--port', '0', '--unixsocket', str(socket),
                                    '--unixsocketperm', '700', '--save', '', '--appendonly', 'no'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if socket.exists():
                    break
                if process.poll() is not None:
                    raise RuntimeError('Disposable Redis failed to start')
                time.sleep(0.05)
            else:
                raise RuntimeError('Disposable Redis did not become ready')
            subprocess.run([sys.executable, '-m', 'django', 'collectstatic', '--noinput', '--verbosity', '0'],
                           env=environment, check=True)
            return subprocess.run([sys.executable, '-m', 'django', 'test',
                                   'companion_web.tests', '--verbosity', '2'],
                                  env=environment).returncode
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == '__main__':
    raise SystemExit(main())
