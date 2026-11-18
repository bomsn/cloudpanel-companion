"""The website's OPcache settings the Companion owns, and the nightly OPcache upkeep.

OPcache keeps compiled PHP in shared memory. A changed or updated file is compiled
again and its old copy only marked wasted; PHP frees that memory by restarting OPcache
only once memory is full and more than opcache.max_wasted_percentage (5% by default,
left alone) is wasted, at whatever time of day that happens. Every night, at a quiet
hour, companion-opcache-upkeep reads the website pool's OPcache through the same
diagnostic the history collector uses and, when 10% or more is wasted or the cache is
full, reloads PHP-FPM gracefully: workers finish their requests (up to
process_control_timeout) and OPcache starts empty. Otherwise it changes nothing. It
skips the night while a Companion workflow (refresh, release, staging cleanup) runs.

The settings are PHP_INI_SYSTEM values, so neither CloudPanel's per-site PHP settings
nor a pool can set them; they live in one ini drop-in. process_control_timeout is
CloudPanel's: its PHP packages ship pool.d/global.conf with 10 seconds, so it is in
effect before the Companion's first reload. Every reload here first checks with
`php-fpm -tt` that PHP-FPM accepts its configuration and that this timeout is not 0,
where a reload would stop the requests in progress.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import time
from .monitor import private_json
from .operations import write_export
from .php_pool import VERSIONS

HEADER = '; Managed by CloudPanel Companion.'
# The ini drop-in was written by the application safeguards before setup owned it.
OWNED_PREFIX = '; Managed by CloudPanel Companion'
SETTINGS = (
    ('opcache.memory_consumption', '768'),
    # CloudPanel's default 8 MB is full after one WooCommerce/Elementor page load (about
    # 28 MB measured after three pages); a full buffer stores duplicates in every worker.
    ('opcache.interned_strings_buffer', '64'),
    # A WooCommerce site caches about 15,000 scripts; CloudPanel's 1,000,000 slots cost memory for nothing.
    ('opcache.max_accelerated_files', '100000'),
    # file_exists()/is_file() on cached scripts answer from OPcache. Timestamp validation
    # stays on, so a deleted or changed file is noticed within opcache.revalidate_freq.
    ('opcache.enable_file_override', '1'),
)
WASTE_LIMIT = 10
UPKEEP_TIME = '04:30'
UNITS = ('companion-opcache-upkeep.service', 'companion-opcache-upkeep.timer')
SYSTEMD = Path('/etc/systemd/system')
SCHEDULE = SYSTEMD / 'companion-opcache-upkeep.timer.d' / 'schedule.conf'
TELEMETRY = Path('/etc/cloudpanel-companion/telemetry.json')
# Beside the history export, which the interface already reads.
RECORD = Path('/var/lib/cloudpanel-companion-telemetry-observations/opcache-upkeep.json')
# Each registered workflow (refresh, release, staging cleanup) holds its site's lock here while it runs.
JOB_LOCKS = Path('/var/lib/cloudpanel-companion-jobs/locks')


def performance_ini(php):
    return Path('/etc/php') / php / 'fpm/conf.d/99-companion-performance.ini'


def fpm_binary(php):
    return '/usr/sbin/php-fpm' + php


def files(php):
    if php not in VERSIONS:
        raise ValueError('Unsupported PHP version')
    return {performance_ini(php): HEADER + '\n' + ''.join(f'{key}={value}\n' for key, value in SETTINGS)}


def schedule(at):
    """The timer drop-in for a time other than the default, or None."""
    if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', at):
        raise ValueError('Use a 24-hour HH:MM time')
    if at == UPKEEP_TIME:
        return None
    return HEADER.replace(';', '#', 1) + f'\n[Timer]\nOnCalendar=\nOnCalendar=*-*-* {at}:00\n'


def graceful_timeout(output):
    """process_control_timeout in seconds, as `php-fpm -tt` reports it, or None."""
    found = re.search(r'NOTICE:\s+process_control_timeout = (\d+)s\s*$', output, re.M)
    return int(found[1]) if found else None


def reload_refusal(php):
    """Why PHP-FPM must not be reloaded now, or None when its configuration passes and a reload is graceful.

    PHP-FPM's reload does not test the configuration first: a file it refuses stops PHP.
    """
    try:
        test = subprocess.run([fpm_binary(php), '-tt'], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        return f'php-fpm -tt could not run: {error}'
    output = test.stderr + test.stdout
    if test.returncode:
        return 'PHP-FPM refused its configuration:\n' + output[-1500:]
    if not graceful_timeout(output):
        return (f'process_control_timeout is 0 or unset, so a reload would stop the requests in progress. CloudPanel '
                f'sets it to 10s in /etc/php/{php}/fpm/pool.d/global.conf; restore that file.')
    return None


@contextlib.contextmanager
def workflows_idle(locks=JOB_LOCKS):
    """Hold every registered workflow's lock while PHP-FPM reloads; BlockingIOError while one runs.

    A reload during a release or refresh can slow its health checks into a failure and a
    needless recovery. A workflow starting meanwhile stops at its lock, before any change.
    """
    with contextlib.ExitStack() as held:
        for path in sorted(locks.glob('*.lock')) if locks.is_dir() else ():
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            held.callback(os.close, descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def installed(php, at):
    def current(path, content):
        try:
            return path.read_text() == content
        except OSError:
            return False
    wanted = schedule(at)
    return (all(current(path, content) for path, content in files(php).items())
            and all((SYSTEMD / unit).is_file() for unit in UNITS)
            and (current(SCHEDULE, wanted) if wanted else not SCHEDULE.exists()))


def due(status):
    return status['opcache_full'] or status['opcache_wasted_percent'] >= WASTE_LIMIT


def upkeep(config=TELEMETRY, record=RECORD, now=None, locks=JOB_LOCKS):
    """Read the website pool's OPcache and reload PHP-FPM gracefully when it needs it; record what was done."""
    from .telemetry import opcache_sample
    if os.geteuid() != 0:
        raise ValueError('The operator installs and runs server collectors')
    now = int(time.time()) if now is None else now
    settings = private_json(config)
    try:
        previous = json.loads(record.read_text())
    except (OSError, ValueError):
        previous = {}
    result = {'checked_at': now, 'waste_limit': WASTE_LIMIT,
              'last_reload': previous.get('last_reload') if isinstance(previous, dict) else None}
    try:
        status = opcache_sample(settings)
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        result['action'] = 'unavailable'
    else:
        result.update(status)
        result['action'] = 'not-needed'
        if due(status):
            try:
                with workflows_idle(locks):
                    refusal = reload_refusal(settings['php'])
                    if refusal:
                        result.update(action='refused', reason=refusal[-300:])
                    else:
                        reloaded = subprocess.run(['/usr/bin/systemctl', 'reload', 'php' + settings['php'] + '-fpm.service'],
                                                  capture_output=True, timeout=60)
                        result['action'] = 'reload-failed' if reloaded.returncode else 'reloaded'
                        if not reloaded.returncode:
                            result['last_reload'] = now
            except BlockingIOError:
                # Still due tomorrow night if it needs it then.
                result['action'] = 'workflow-running'
    write_export(record, json.dumps(result))
    return result


if __name__ == '__main__':
    print(json.dumps(upkeep()))
