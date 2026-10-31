"""Exercise preview/apply/recovery against real PHP responses on loopback.

Run on Linux as a non-root test identity. Creates and removes only its own
temporary directories and PHP child. No WordPress/customer data is involved.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from companion.deploy_cli import health


def main():
    if os.geteuid() == 0:
        raise SystemExit('Use a non-root test identity')
    php = shutil.which('php8.3') or shutil.which('php')
    with tempfile.TemporaryDirectory(prefix='companion-deploy-http-') as directory:
        root = Path(directory).resolve()
        source, target, state = (root / name for name in ('source', 'target', 'state'))
        relative = 'wp-content/themes/example/functions.php'
        for path in (source, target):
            (path / relative).parent.mkdir(parents=True)
            (path / relative).write_text('<?php echo "original-version";')
        state.mkdir(mode=0o700)
        (target / 'index.php').write_text('<?php require __DIR__ . "/' + relative + '";')
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            port = available.getsockname()[1]
        server = subprocess.Popen([php, '-n', '-S', f'127.0.0.1:{port}', '-t', str(target)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = f'http://127.0.0.1:{port}/'
        command = [sys.executable, '-m', 'companion.deploy_cli']
        results = {}
        try:
            for _ in range(50):
                if health(url, 'original-version'):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('PHP fixture did not start')
            results['original_http_response'] = True

            def plan():
                return subprocess.run(command + ['preview', '--source', str(source), '--target',
                                      str(target), relative], check=True, capture_output=True).stdout

            arguments = ['apply', '--source', str(source), '--target', str(target), '--state', str(state),
                         '--php', php, '--health-url', url, '--health-text', 'new-version']
            (source / relative).write_text('<?php echo "new-version";')
            deployed = subprocess.run(command + arguments, input=plan(), capture_output=True, check=True)
            receipt = Path(json.loads(deployed.stdout)['receipt'])
            results['approved_code_changes_actual_http_response'] = health(url, 'new-version')
            recovered = subprocess.run(command + ['recover', '--target', str(target), '--state', str(state),
                                      '--health-url', url, '--health-text', 'original-version',
                                      receipt.parent.name], capture_output=True, check=True)
            results['explicit_rollback_restores_actual_http_response'] = (
                json.loads(recovered.stdout)['status'] == 'rolled-back' and health(url, 'original-version'))
            (source / relative).write_text('<?php http_response_code(500); echo "broken-version";')
            failed = subprocess.run(command + arguments, input=plan(), capture_output=True)
            results['http_500_triggers_automatic_recovery'] = failed.returncode != 0 and health(url, 'original-version')
            results['recovery_artifacts_outside_webroot'] = not state.is_relative_to(target)
            if not all(results.values()):
                raise RuntimeError(results)
            print(json.dumps(results, indent=2))
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == '__main__':
    main()
