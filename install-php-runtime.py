"""Install the website's OPcache settings and the nightly OPcache upkeep (companion/php_runtime.py).

Run as root after install-monitor.py: the upkeep reads OPcache through the website
pool's diagnostic that monitoring installs. A change is applied with a graceful reload
only after `php-fpm -tt` accepts it and confirms CloudPanel's process_control_timeout,
so running requests finish; otherwise the previous file is put back. Running it again
changes only what is out of date.
"""
import argparse
import os
from pathlib import Path
import subprocess
from companion import php_runtime
from companion.maintenance import component_install
from companion.operations import write_private
from companion.php_pool import VERSIONS


def run(*arguments):
    subprocess.run(arguments, check=True)


def install(args):
    source = Path(__file__).resolve().parent
    if not php_runtime.TELEMETRY.is_file():
        raise ValueError('Install monitoring with install-monitor.py first; the upkeep reads its PHP diagnostic')
    settings = php_runtime.files(args.php)
    current = {path: path.read_text() if path.exists() else None for path in settings}
    for path, old in current.items():
        if path.is_symlink() or (old is not None and not old.startswith(php_runtime.OWNED_PREFIX)):
            raise ValueError(f'{path} was not written by the Companion; review it, then remove it and run this again')
    previous = {path: current[path] for path, content in settings.items() if current[path] != content}
    for path in previous:
        write_private(path, settings[path], 0o644)
    if previous:
        refusal = php_runtime.reload_refusal(args.php)
        if refusal:
            for path, old in previous.items():
                if old is None:
                    path.unlink()
                else:
                    write_private(path, old, 0o644)
            raise ValueError(refusal + '\nThe previous settings were restored.')
        # The settings and an empty OPcache apply from here; running requests finish first.
        run('systemctl', 'reload', 'php' + args.php + '-fpm')
    for unit in php_runtime.UNITS:
        content = (source / 'assets' / unit).read_text()
        target = php_runtime.SYSTEMD / unit
        if not target.is_file() or target.read_text() != content:
            write_private(target, content, 0o644)
    wanted = php_runtime.schedule(args.upkeep_time)
    if wanted:
        php_runtime.SCHEDULE.parent.mkdir(mode=0o755, exist_ok=True)
        write_private(php_runtime.SCHEDULE, wanted, 0o644)
    else:
        php_runtime.SCHEDULE.unlink(missing_ok=True)
    run('systemd-analyze', 'verify', *(str(php_runtime.SYSTEMD / unit) for unit in php_runtime.UNITS))
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'companion-opcache-upkeep.timer')
    print(f'PHP {args.php} OPcache settings installed. The nightly OPcache check runs at {args.upkeep_time} server time.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--php', choices=VERSIONS, required=True)
    parser.add_argument('--upkeep-time', default=php_runtime.UPKEEP_TIME, help='HH:MM, server time (default %(default)s)')
    arguments = parser.parse_args()
    php_runtime.schedule(arguments.upkeep_time)
    if os.geteuid() != 0:
        raise SystemExit('Run as the server operator')
    with component_install(Path(__file__).resolve().parent):
        install(arguments)
