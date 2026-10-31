"""Shared installer contracts for fixed, operator-owned service resources."""
import os
from pathlib import Path
import pwd
import shutil
import subprocess


def monitor_export(source):
    """Wire the endpoint exporter once, including on a fresh installation."""
    try:
        monitor = pwd.getpwnam('companion-monitor')
    except KeyError:
        subprocess.run(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin',
                        'companion-monitor'], check=True)
        monitor = pwd.getpwnam('companion-monitor')
    if monitor.pw_shell != '/usr/sbin/nologin' or monitor.pw_uid >= 1000:
        raise ValueError('Monitoring needs its dedicated non-interactive system identity')
    web = pwd.getpwnam('companion-web')
    observations = Path('/var/lib/cloudpanel-companion-observations')
    if observations.is_symlink() or observations.resolve() != observations:
        raise ValueError('Observation directory cannot be a link')
    observations.mkdir(mode=0o2750, exist_ok=True)
    os.chown(observations, monitor.pw_uid, web.pw_gid)
    os.chmod(observations, 0o2750)
    dropins = Path('/etc/systemd/system/companion-monitor.service.d')
    dropins.mkdir(mode=0o755, exist_ok=True)
    shutil.copyfile(source / 'assets/monitor-web-export.conf', dropins / 'web-export.conf')
