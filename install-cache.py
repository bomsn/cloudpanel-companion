"""Install one operator-owned cache controller over CloudPanel's packaged Varnish.

Does not enable public caching on ordinary staging. Registers explicit sites,
installs the WordPress companion as the site owner, and records original Nginx
configuration before routing. Run on the disposable lab before a live release.
"""
import argparse
import hashlib
import grp
import io
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import tarfile
import time
from companion.cache_config import render
from companion.monitor import private_json
from companion.operations import write_private
from companion.network import table_name


def run(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=180, **kwargs)
    if result.returncode:
        raise RuntimeError(Path(arguments[0]).name + ' failed: ' + result.stderr.decode()[-1000:])
    return result.stdout


def clear_failed(*units):
    """Reset only a recorded failure; on a first install the controller unit is not loaded
    yet, and `systemctl reset-failed` refuses units that are not loaded."""
    for unit in units:
        if subprocess.run(['systemctl', 'is-failed', '--quiet', unit]).returncode == 0:
            run(['systemctl', 'reset-failed', unit])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--php', required=True, choices=['8.2', '8.3', '8.4'])
    parser.add_argument('--plugin-source', type=Path, required=True)
    parser.add_argument('--lab-public-cache', action='store_true')
    parser.add_argument('--upgrade', action='store_true', help='replace an installed plugin and server policy in a planned window')
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r'[a-z][a-z0-9-]{1,30}', args.user):
        raise ValueError('Root invocation and a valid registered site user are required')
    if not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', args.host):
        raise ValueError('Use a lowercase explicit hostname')
    from companion.maintenance import component_install
    with component_install(Path(__file__).resolve().parent):
        upgrade(args) if args.upgrade else install(args)


def upgrade(args):
    """Replace an installed plugin and its server policy as one planned change.

    Plain installation refuses different installed code, because streaming files
    over an active plugin can serve half-old, half-new code. This path pauses new
    requests, lets running ones finish, swaps the whole plugin folder, verifies a
    real uncached page and restores the previous folder if anything fails.
    """
    from companion.drain import drain
    from companion.provision import command, site_wp
    from companion.site_trust import curl_trust
    from companion.staging import Site
    account = pwd.getpwnam(args.user)
    site = Path(account.pw_dir) / 'htdocs' / args.host
    plugin = site / 'wp-content/plugins/cache-manager-for-cloudpanel'
    if not plugin.is_dir() or plugin.is_symlink():
        raise ValueError('The plugin is not installed yet; run without --upgrade first')
    live = Site(host=args.host, user=args.user, database='unused', php_version=args.php)
    release = None
    registry = Path('/etc/cloudpanel-companion/operations.json')
    if registry.exists():
        from companion.registered_deployment import Releases
        for site_id, item in private_json(registry)['sites'].items():
            if item['source_host'] == args.host:
                release = Releases(registry, site_id)
    backup = Path(account.pw_dir) / ('.companion-plugin-before-' + str(time.time_ns()))
    as_owner = ['/usr/sbin/runuser', '-u', args.user, '--']
    if release:
        if release.marker.exists():
            raise ValueError('A code release is in progress; finish it first')
        # Native maintenance routing answers new visitors while the swap runs.
        release.marker.write_text('Planned cache plugin upgrade\n')
    try:
        drain(args.user, args.host, args.php)
        command(site_wp(live) + ['plugin', 'deactivate', 'cache-manager-for-cloudpanel'])
        command(as_owner + ['mv', '--', str(plugin), str(backup)])
        try:
            install(args)
            if release:
                release.invalidate()
                if not release.observe():
                    raise RuntimeError('The website did not pass its uncached health check after the upgrade')
            else:
                command(['/usr/bin/curl', '-fsS', '-o', '/dev/null', '--resolve', args.host + ':443:127.0.0.1',
                         *curl_trust(args.host), 'https://' + args.host + '/'], timeout=20)
        except BaseException:
            if plugin.exists():
                command(as_owner + ['mv', '--', str(plugin), str(backup) + '-failed'])
            command(as_owner + ['mv', '--', str(backup), str(plugin)])
            command(site_wp(live) + ['plugin', 'activate', 'cache-manager-for-cloudpanel'])
            command(site_wp(live) + ['cloudpanel-cache', 'purge'])
            print('Upgrade failed; the previous plugin was restored.')
            raise
    except BaseException:
        if not plugin.exists() and backup.exists():
            command(as_owner + ['mv', '--', str(backup), str(plugin)])
            command(site_wp(live) + ['plugin', 'activate', 'cache-manager-for-cloudpanel'])
        raise
    finally:
        if release:
            release.marker.unlink(missing_ok=True)
    print('Cache plugin upgraded. Previous version kept outside the website at ' + str(backup))


def install(args):
    account = pwd.getpwnam(args.user)
    if account.pw_uid < 1000:
        raise ValueError('WordPress must run as a non-system website identity')
    site = Path(account.pw_dir) / 'htdocs' / args.host
    if site.is_symlink() or site.resolve() != site or not (site / 'wp-config.php').is_file():
        raise ValueError('Native CloudPanel WordPress root required')
    wp = ['/usr/sbin/runuser', '-u', args.user, '--', '/usr/bin/php' + args.php, '/usr/bin/wp', '--path=' + str(site)]
    if run(wp + ['option', 'get', 'home']).decode().strip() != 'https://' + args.host:
        raise ValueError('WordPress identity does not match selected host')
    # Provisioning is replayable, but it must never stream a replacement over
    # an active plugin. Existing code changes need a separately planned plugin
    # upgrade, including its server policy; this entry point refuses them early.
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as output:
        for file in args.plugin_source.rglob('*'):
            if file.is_symlink():
                raise ValueError('Plugin release source cannot contain links')
            if file.is_file() and file.suffix in ('.php', '.md', '.vcl', '.txt'):
                output.add(file, arcname=file.relative_to(args.plugin_source).as_posix(), recursive=False)
    installer = '''import hashlib,os,secrets,shutil,subprocess,sys,tarfile
from pathlib import Path
target=Path(sys.argv[1]);candidate=Path.home()/('.companion-plugin-'+secrets.token_hex(12))
candidate.mkdir(mode=0o700)
try:
 total=0
 with tarfile.open(fileobj=sys.stdin.buffer,mode='r|gz') as archive:
  for member in archive:
   if not member.isfile() or member.name.startswith('/') or '..' in Path(member.name).parts or member.size>8*1024*1024:raise ValueError('Invalid plugin archive')
   total+=member.size
   if total>32*1024*1024:raise ValueError('Plugin release exceeds its bound')
   path=candidate/member.name;path.parent.mkdir(parents=True,exist_ok=True)
   with path.open('xb') as stream:stream.write(archive.extractfile(member).read())
   path.chmod(0o644)
   if path.suffix=='.php':subprocess.run(['/usr/bin/php'+sys.argv[2],'-l',str(path)],check=True,capture_output=True)
 def inventory(root):
  if root.is_symlink() or root.resolve()!=root:raise ValueError('Plugin root must remain resolved')
  result={}
  for path in root.rglob('*'):
   if path.is_symlink():raise ValueError('Installed plugin must not contain links')
   if path.is_file() and path.suffix in ('.php','.vcl'):
    if path.stat().st_size>8*1024*1024:raise ValueError('Installed plugin file exceeds its bound')
    result[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
  return result
 if target.is_symlink():raise ValueError('Installed plugin root cannot be a link')
 if target.exists():
  if inventory(target)!=inventory(candidate):raise ValueError('Installed plugin code differs. Use a planned plugin and server-policy upgrade; provisioning will not overwrite it.')
 else:
  if target.parent.resolve()!=target.parent:raise ValueError('Plugin parent must remain resolved')
  candidate.chmod(0o755);candidate.rename(target)
finally:
 if candidate.exists():shutil.rmtree(candidate)
'''
    run(['/usr/sbin/runuser', '-u', args.user, '--', '/usr/bin/python3', '-c', installer,
         str(site / 'wp-content/plugins/cache-manager-for-cloudpanel'), args.php], input=archive.getvalue())
    if args.lab_public_cache:
        existing_lab_unit = Path('/etc/systemd/system/companion-cache-lab-isolation.service')
        if existing_lab_unit.exists() and ('--uid ' + str(account.pw_uid) + ' --allow-local-port 6083') not in existing_lab_unit.read_text():
            raise ValueError('The disposable cache exception already belongs to another isolated website')
        guarded = run(wp + ['eval', 'echo defined("CLOUDPANEL_COMPANION_STAGING") && CLOUDPANEL_COMPANION_STAGING === true && wp_get_environment_type() === "staging" ? "guarded" : "unsafe";']).decode().strip()
        if guarded != 'guarded':
            raise ValueError('The explicit lab exception requires an already guarded staging copy')
        run(['/usr/sbin/nft', 'list', 'table', 'inet', table_name(account.pw_uid)])
    vhost = Path('/etc/nginx/sites-enabled') / (args.host + '.conf')
    if vhost.is_symlink() or not vhost.is_file() or vhost.stat().st_uid != 0:
        raise ValueError('Explicit root-owned native vhost required')
    original = vhost.read_text()
    from companion.nginx_templates import (UPSTREAM_IDLE_SECONDS, UPSTREAMS, cache_routing, cache_upstreams,
                                           disable_native_controller, frontend_cache_route, require_fresh_file_checks)
    # Refuse an unexpected native vhost or file-caching Nginx before changing anything.
    disable_native_controller(original)
    require_fresh_file_checks(run(['nginx', '-T']).decode(errors='replace'))
    root = Path(__file__).resolve().parent
    os.umask(0o077)
    state = Path('/etc/cloudpanel-companion')
    state.mkdir(mode=0o700, exist_ok=True)
    registry_path = state / 'cache-sites.json'
    configuration = private_json(registry_path) if registry_path.exists() else {'backend_port': 8080, 'sites': []}
    item = next((entry for entry in configuration['sites'] if entry['host'] == args.host), None)
    if item is None:
        item = {'host': args.host, 'purge_key': secrets.token_hex(32)}
        configuration['sites'].append(item)
    policy = (args.plugin_source / 'server/cache-policy.vcl').read_text()
    render(configuration, policy)
    try:
        control = pwd.getpwnam('companion-cache')
        if control.pw_shell not in ('/usr/sbin/nologin', '/bin/false'):
            raise ValueError('Cache identity must not have an interactive shell')
    except KeyError:
        run(['useradd', '--system', '--gid', 'varnish', '--no-create-home', '--shell', '/usr/sbin/nologin', 'companion-cache'])
        control = pwd.getpwnam('companion-cache')
    for name, mode in [('/var/lib/cache-manager-control', 0o750), ('/var/lib/cache-manager-control/state', 0o700)]:
        path = Path(name)
        if path.is_symlink():
            raise ValueError('Cache state cannot be a symlink')
        path.mkdir(mode=mode, exist_ok=True)
        os.chown(path, control.pw_uid, grp.getgrnam('varnish').gr_gid)
        path.chmod(mode)
    instance = Path('/var/lib/varnish/companion')
    instance.mkdir(mode=0o755, exist_ok=True)
    if instance.is_symlink() or instance.stat().st_uid != 0:
        raise ValueError('Varnish instance directory must be root-owned')
    instance.chmod(0o755)
    os.chown(instance, 0, grp.getgrnam('varnish').gr_gid)
    secret = state / 'cache-admin.secret'
    if not secret.exists():
        write_private(secret, secrets.token_hex(32) + '\n')
    write_private(registry_path, json.dumps(configuration))
    shutil.copyfile(args.plugin_source / 'server/cache-policy.vcl', '/opt/cloudpanel-companion/assets/cache-policy.vcl')
    Path('/opt/cloudpanel-companion/assets/cache-policy.vcl').chmod(0o644)
    shutil.copyfile(root / 'assets/cache-manager-control.service', '/etc/systemd/system/cache-manager-control.service')
    bootstrap = state / 'cache-bootstrap.vcl'
    write_private(bootstrap, 'vcl 4.1;\nbackend default { .host = "127.0.0.1"; .port = "8080"; }\nsub vcl_recv { return (pass); }\n', 0o644)
    dropin = Path('/etc/systemd/system/varnish.service.d')
    dropin.mkdir(exist_ok=True)
    write_private(dropin / 'companion.conf', '''[Service]
ExecStart=
ExecStart=/usr/sbin/varnishd -a 127.0.0.1:6081 -T 127.0.0.1:6082 -S /etc/cloudpanel-companion/cache-admin.secret -n /var/lib/varnish/companion -f /etc/cloudpanel-companion/cache-bootstrap.vcl -P /run/varnish/varnishd.pid -p http_resp_hdr_len=40000 -p timeout_idle=''' + str(UPSTREAM_IDLE_SECONDS + 15) + ''' -s malloc,256m
ExecReload=
ExecReload=/usr/bin/python3 -m companion.cache_reload
WorkingDirectory=/opt/cloudpanel-companion
''', 0o644)
    def constant(name, value, raw=False):
        run(wp + ['config', 'set', name, value, '--quiet', *(['--raw'] if raw else []),
                  "--anchor=require_once ABSPATH . 'wp-settings.php';"])
    constant('CACHE_MANAGER_FOR_CLOUDPANEL_ENABLED', 'true', True)
    constant('CACHE_MANAGER_FOR_CLOUDPANEL_PORT', '6083', True)
    constant('CACHE_MANAGER_FOR_CLOUDPANEL_PURGE_KEY', item['purge_key'])
    marker = '/run/cache-manager-control/ready/' + hashlib.sha256(args.host.encode()).hexdigest() + '.ready'
    constant('CACHE_MANAGER_FOR_CLOUDPANEL_READY', marker)
    if args.lab_public_cache:
        constant('CLOUDPANEL_COMPANION_CACHE_ACCEPTANCE', 'true', True)
        for asset, name in [('staging-guard.php', '000-companion-staging.php'), ('staging-policy.php', 'staging-policy.php'), ('staging-relay.php', 'staging-relay.php')]:
            run(['/usr/sbin/runuser', '-u', args.user, '--', '/usr/bin/tee', str(site / 'wp-content/mu-plugins' / name)], input=(root / 'assets' / asset).read_bytes())
        unit = Path('/etc/systemd/system/companion-cache-lab-isolation.service')
        write_private(unit, '''[Unit]
Description=Disposable cache lab network isolation
Before=php''' + args.php + '''-fpm.service
After=ufw.service network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/cloudpanel-companion
ExecStart=/usr/bin/python3 -m companion.isolation --uid ''' + str(account.pw_uid) + ''' --allow-local-port 6083
[Install]
WantedBy=multi-user.target
''', 0o644)
        dependency = Path('/etc/systemd/system') / ('php' + args.php + '-fpm.service.d')
        dependency.mkdir(mode=0o755, exist_ok=True)
        write_private(dependency / 'companion-cache-lab.conf',
                      '[Unit]\nRequires=companion-cache-lab-isolation.service\nAfter=companion-cache-lab-isolation.service\n', 0o644)
    run(['systemd-analyze', 'verify', '/etc/systemd/system/cache-manager-control.service'])
    run(['systemctl', 'daemon-reload'])
    if args.lab_public_cache:
        run(['systemctl', 'enable', 'companion-cache-lab-isolation.service'])
        run(['systemctl', 'restart', 'companion-cache-lab-isolation.service'])
    clear_failed('varnish.service', 'cache-manager-control.service')
    run(['systemctl', 'enable', 'cache-manager-control.service', 'varnish.service'])
    run(['systemctl', 'restart', 'varnish.service'])
    run(['systemctl', 'restart', 'cache-manager-control.service'])
    run(wp + ['plugin', 'activate', 'cache-manager-for-cloudpanel'])
    run(wp + ['cloudpanel-cache', 'purge'])
    backup = state / ('vhost-before-cache-' + args.host + '.conf')
    if not backup.exists():
        write_private(backup, original)
    # The upstream groups first: the routing names them.
    upstreams_before = UPSTREAMS.read_text() if UPSTREAMS.exists() else None
    write_private(UPSTREAMS, cache_upstreams(6081, configuration['backend_port']), 0o644)
    include = state / ('cache-routing-' + args.host + '.conf')
    routing_before = include.read_text() if include.exists() else None
    write_private(include, cache_routing(args.host, marker), 0o644)
    # Nginx must traverse this directory without being able to list its secrets.
    state.chmod(0o711)
    candidate = original
    if str(include) not in candidate:
        needle = '  server_name ' + args.host + ';'
        candidate = candidate.replace(needle, needle + '\n  include ' + str(include) + ';', 1)
        candidate = candidate.replace('$proxy_add_x_forwarded_for', '$remote_addr')
    candidate = frontend_cache_route(candidate)
    # The same PHP override the stored-template routing carries, so the page cache
    # works before the operator has saved that routing in CloudPanel's Vhost editor.
    candidate = disable_native_controller(candidate)
    if candidate != original:
        write_private(vhost, candidate, 0o644)
    try:
        run(['nginx', '-t'])
    except Exception:
        write_private(vhost, original, 0o644)
        for path, before in ((include, routing_before), (UPSTREAMS, upstreams_before)):
            if before is None:
                path.unlink(missing_ok=True)
            else:
                write_private(path, before, 0o644)
        raise
    run(['systemctl', 'reload', 'nginx'])
    print('Local cache installed; public/private and service-failure acceptance still required.')


if __name__ == '__main__':
    main()
