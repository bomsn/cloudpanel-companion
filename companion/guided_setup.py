"""Guided installation: one entry point that runs the component installers in order.

Each step knows how to tell whether it is already done, so running setup again
continues where it stopped and never repeats finished work. The step order is the
one qualified on the lab server, with Monitoring moved after the components whose
services it watches. Component installers keep their own safety
checks; this module only collects answers once and calls them with the right
arguments. It reads CloudPanel's database read-only and never writes to it.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = Path('/etc/cloudpanel-companion')
ANSWERS = CONFIG / 'setup.json'
VENV = Path('/opt/cloudpanel-companion-venv')
PANEL_DB = 'file:/home/clp/htdocs/app/data/db.sq3?mode=ro'
OUTPUT = Path('/root/companion-setup')
NGINX_SITES = Path('/etc/nginx/sites-enabled')
# The cache controller's per-site markers: present only while that site's policy is active.
CACHE_READY = Path('/run/cache-manager-control/ready')
HOST = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}'
USER = r'[a-z][a-z0-9-]{2,30}'


def say(text=''):
    print(text, flush=True)


def shown(argument):
    """A command argument as printed: generated passwords never reach the terminal or its logs."""
    name, separator, value = str(argument).partition('=')
    return name + '=<hidden>' if separator and 'password' in name.lower() else str(argument)


def run(*arguments, **kwargs):
    say('  $ ' + ' '.join(shown(item) for item in arguments))
    subprocess.run([str(item) for item in arguments], check=True, **kwargs)


def quiet(*arguments):
    return subprocess.run([str(item) for item in arguments], capture_output=True, text=True)


def active(unit):
    return quiet('systemctl', 'is-active', unit).stdout.strip() == 'active'


def private(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def panel_site(host):
    """Native CloudPanel site record, read-only, or None when it does not exist."""
    try:
        with sqlite3.connect(PANEL_DB, uri=True) as db:
            row = db.execute('SELECT site.type, site.user, site.vhost_template, site.certificate_id, certificate.type '
                             'FROM site LEFT JOIN certificate ON certificate.id = site.certificate_id '
                             'WHERE site.domain_name = ?', (host,)).fetchone()
    except sqlite3.Error:
        return None
    return dict(zip(('type', 'user', 'vhost', 'certificate', 'certificate_type'), row)) if row else None


# CloudPanel's certificate types, stored as text: '1' the self-signed certificate it gives
# every new site, '2' Let's Encrypt, '3' imported (SSL/TLS tab or clpctl site:install:certificate).
SELF_SIGNED = '1'
IMPORTED = '3'


def trusted_certificate(host):
    site = panel_site(host)
    return bool(site and site['certificate'] and str(site['certificate_type']) != SELF_SIGNED)


def origin_ca(answers):
    return answers.get('cloudflare_origin_ca') == 'yes'


def site_certificate(answers):
    """The website has the certificate its checks trust: an imported one for Cloudflare Origin CA."""
    if not origin_ca(answers):
        return trusted_certificate(answers['site_host'])
    site = panel_site(answers['site_host'])
    return bool(site and site['certificate'] and str(site['certificate_type']) == IMPORTED)


def staging_certificate(answers):
    say('  Requesting a certificate. DNS for ' + answers['staging_host'] + ' must already point to this server.')
    run('clpctl', 'lets-encrypt:install:certificate', '--domainName=' + answers['staging_host'])


# Answers -----------------------------------------------------------------------

QUESTIONS = [
    ('site_host', 'Website address managed by CloudPanel (e.g. shop.example.com)', HOST),
    ('site_user', 'Its CloudPanel site user', USER),
    ('php', 'Its PHP version (8.2, 8.3 or 8.4)', r'8\.[234]'),
    ('cloudflare_origin_ca', "Is the website's certificate a Cloudflare Origin CA certificate? (yes/no)", r'yes|no'),
    ('ops_host', 'Address for the Companion interface (e.g. ops.example.com)', HOST),
    ('panel_host', 'Address you use for CloudPanel itself (e.g. panel.example.com)', HOST),
    ('staging', 'Set up a password-protected staging copy? (yes/no)', r'yes|no'),
    ('staging_host', 'Staging address (e.g. stg.example.com)', HOST),
    ('staging_user', 'New Unix user for staging (must not exist yet)', USER),
    ('page_cache', 'Install the Varnish page cache with Cache Manager for CloudPanel? (yes/no)', r'yes|no'),
    ('cache_plugin', 'Folder containing the cache-manager-for-cloudpanel plugin', r'/.+'),
    ('object_cache', 'Install a private Redis object cache for WordPress? (yes/no)', r'yes|no'),
    ('slack', 'Send monitoring alerts to a Slack channel? (yes/no)', r'yes|no'),
]


def ask(answers):
    say('A few questions first. Answers are saved to ' + str(ANSWERS) + ' and reused next time.')
    for key, question, pattern in QUESTIONS:
        if key.startswith('staging_') and answers.get('staging') != 'yes':
            continue
        if key == 'cache_plugin' and answers.get('page_cache') != 'yes':
            continue
        default = answers.get(key)
        if key == 'cache_plugin' and not default:
            default = str(ROOT.parent / 'cache-manager-for-cloudpanel')
        while True:
            value = input(f'{question}{" [" + default + "]" if default else ""}: ').strip().lower() or default or ''
            if key == 'cache_plugin':
                value = str(Path(value).resolve())
            if re.fullmatch(pattern, value):
                answers[key] = value
                break
            say('  That does not look right, please try again.')
    return answers


def load_answers(reconfigure):
    answers = private(ANSWERS) or {}
    if reconfigure or not all(answers.get(key) for key in ('site_host', 'site_user', 'php', 'ops_host', 'panel_host')):
        answers = ask(answers)
        CONFIG.mkdir(mode=0o755, exist_ok=True)
        ANSWERS.write_text(json.dumps(answers, indent=2))
        ANSWERS.chmod(0o600)
    return answers


def staging_spec(answers):
    path = CONFIG / ('staging-' + answers['staging_user'] + '.json')
    database = re.sub(r'[^a-z0-9]', '', answers['staging_user'])[:32]
    source = panel_site(answers['site_host'])
    spec = {'source': {'host': answers['site_host'], 'user': answers['site_user'],
                       'database': site_database(answers), 'php_version': answers['php']},
            'target': {'host': answers['staging_host'], 'user': answers['staging_user'],
                       'database': database, 'php_version': answers['php']}}
    if source is None:
        raise SystemExit('The website is not a CloudPanel site on this server.')
    return path, spec


def site_database(answers):
    result = quiet('runuser', '-u', answers['site_user'], '--', 'wp', '--path=/home/' + answers['site_user'] +
                   '/htdocs/' + answers['site_host'], 'config', 'get', 'DB_NAME')
    if result.returncode:
        raise SystemExit('Could not read the website database name with WP-CLI as ' + answers['site_user'] + '.')
    return result.stdout.strip()


def registered_site(answers):
    registry = private(CONFIG / 'operations.json') or {'sites': {}}
    for site_id, item in registry['sites'].items():
        if item['source_host'] == answers['site_host']:
            return site_id, item
    return None, None


def site_id(answers):
    return re.sub(r'[^a-z0-9]', '', answers['site_user'])[:16] or 'site'


# Steps ---------------------------------------------------------------------------
# Each step: (title, applies(answers), done(answers), do(answers)).

def check_server(answers):
    problems = []
    if shutil.which('clpctl') is None:
        problems.append('CloudPanel is not installed (clpctl not found).')
    release = Path('/etc/os-release').read_text() if Path('/etc/os-release').exists() else ''
    if 'VERSION_ID="24.04"' not in release:
        problems.append('Ubuntu 24.04 is the tested system; this server reports something else.')
    site = panel_site(answers['site_host'])
    if not site or site['type'] != 'php' or site['user'] != answers['site_user']:
        problems.append(f'{answers["site_host"]} is not a CloudPanel PHP site owned by {answers["site_user"]}.')
    if not Path(f'/etc/php/{answers["php"]}/fpm/pool.d/{answers["site_host"]}.conf').exists():
        problems.append(f'No PHP {answers["php"]} pool found for {answers["site_host"]}.')
    if answers.get('page_cache') == 'yes' and not Path(answers['cache_plugin'], 'cache-manager-for-cloudpanel.php').exists():
        problems.append('Cache Manager for CloudPanel was not found at ' + answers['cache_plugin'] + '.')
    if problems:
        raise SystemExit('Please fix these first:\n  - ' + '\n  - '.join(problems))
    say('  Server looks ready.')


def site_trust_applies(answers):
    """Chosen now, or chosen before and still installed (answering no removes it)."""
    from companion.site_trust import site_ca_file
    return origin_ca(answers) or site_ca_file(answers['site_host']) is not None


def site_trust_ready(answers):
    from companion.site_trust import CLOUDFLARE_ORIGIN_CA, site_ca_file
    installed = site_ca_file(answers['site_host'])
    if not origin_ca(answers):
        return installed is None
    # Compared with this checkout's roots, so an update that ships new ones installs them.
    return installed is not None and Path(installed).read_bytes() == CLOUDFLARE_ORIGIN_CA.read_bytes()


def install_site_trust(answers):
    from companion import site_trust
    if origin_ca(answers):
        site_trust.install(answers['site_host'], site_trust.CLOUDFLARE_ORIGIN_CA)
    else:
        site_trust.remove(answers['site_host'])


def python_ready(answers):
    return (VENV / 'bin' / 'python').exists() and quiet(VENV / 'bin' / 'python', '-c', 'import django, allauth, gunicorn, redis').returncode == 0


def install_python(answers):
    if quiet('python3', '-c', 'import ensurepip').returncode:
        # Ubuntu's needrestart otherwise opens a full-screen dialog in a terminal and
        # can offer to restart services; setup must neither stall nor restart the website.
        run('apt-get', 'install', '-y', 'python3-venv',
            env=dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l', NEEDRESTART_SUSPEND='1'))
    if not (VENV / 'bin' / 'python').exists():
        run('python3', '-m', 'venv', VENV)
    run(VENV / 'bin' / 'pip', 'install', '--quiet', '--disable-pip-version-check', '-r', ROOT / 'requirements.txt')


def interface_ready(answers):
    """Installed, running and at this checkout's version (after `git pull` it updates the runtime)."""
    if not ((CONFIG / 'web.json').exists() and active('companion-security-cache.service')):
        return False
    from companion.package_install import require_package
    try:
        require_package(ROOT)
    except ValueError:
        return False
    return True


def install_interface(answers):
    run('python3', ROOT / 'install-web.py', '--host', answers['ops_host'], '--site-host', answers['site_host'],
        '--panel-host', answers['panel_host'], '--link-monitor')


def ops_site_ready(answers):
    site = panel_site(answers['ops_host'])
    return bool(site and site['type'] == 'reverse-proxy' and trusted_certificate(answers['ops_host']))


# The interface's own socket (assets/companion-web.service). Only the interface's
# service account can create it, so no other local user can ever take the place of
# the upstream that receives operator logins.
INTERFACE_UPSTREAM = 'http://unix:/run/cloudpanel-companion-web/app.sock'


def route_interface(answers):
    """Serve the interface through its owned routing in the generated Nginx file now.

    The stored-template paste only makes this persistent; until it is saved, the
    generated file already carries the same routing (and a regeneration from the
    stored template still points at the interface's socket, never a free port).
    """
    from companion.nginx_templates import interface_routing
    from companion.operations import write_private
    path = NGINX_SITES / (answers['ops_host'] + '.conf')
    current = path.read_text()
    wanted = interface_routing(current)
    if wanted == current:
        return
    write_private(path, wanted, 0o644)
    if quiet('nginx', '-t').returncode:
        write_private(path, current, 0o644)
        raise SystemExit('  The interface routing did not pass `nginx -t`; the previous file was restored.')
    run('systemctl', 'reload', 'nginx')


def create_ops_site(answers):
    if not panel_site(answers['ops_host']):
        user = re.sub(r'[^a-z0-9]', '', answers['site_user'])[:20] + 'ops'
        import secrets
        run('clpctl', 'site:add:reverse-proxy', '--domainName=' + answers['ops_host'],
            '--reverseProxyUrl=' + INTERFACE_UPSTREAM, '--siteUser=' + user,
            '--siteUserPassword=' + secrets.token_urlsafe(40), stdout=subprocess.DEVNULL)
        # The interface site never needs a login shell or SFTP access.
        run('usermod', '--lock', user)
    route_interface(answers)
    say('  Requesting a certificate. DNS for ' + answers['ops_host'] + ' must already point to this server.')
    run('clpctl', 'lets-encrypt:install:certificate', '--domainName=' + answers['ops_host'])


def interface_paste(answers):
    # Sites created before the routing was applied at creation get it here too.
    route_interface(answers)
    return paste(answers['ops_host'], ops_vhost(answers))


def vhost_step(host, transform):
    """Return (done, wanted) for a native stored vhost and its required version."""
    site = panel_site(host)
    if not site:
        return False, None
    current = site['vhost'].replace('\r\n', '\n')
    wanted = transform(current)
    return wanted == current, wanted


def ops_vhost(answers):
    from companion.nginx_templates import interface_template
    return vhost_step(answers['ops_host'], interface_template)


def website_routing(answers):
    """Which Companion includes the website's stored vhost needs: (cache, releases, security, telemetry)."""
    security = CONFIG / 'sites' / (answers.get('site_user', '') + '-security.conf')
    return (answers.get('page_cache') == 'yes', staging_on(answers), bool(answers.get('site_user')) and security.exists(),
            (CONFIG / 'telemetry-public.conf').exists())


def site_vhost(answers):
    from companion.nginx_templates import integration
    cache, releases, security, telemetry = website_routing(answers)
    if not (cache or releases or security or telemetry):
        return True, None
    return vhost_step(answers['site_host'], lambda text: integration(text, answers['site_user'], answers['site_host'],
                                                                     security=security, cache=cache, releases=releases,
                                                                     telemetry=telemetry))


def staging_vhost(answers):
    """Staging's stored vhost gains the security include once the safeguards created it."""
    from companion.nginx_templates import integration
    if not (CONFIG / 'sites' / (answers['staging_user'] + '-security.conf')).exists():
        return True, None
    return vhost_step(answers['staging_host'], lambda text: integration(text, answers['staging_user'],
                                                                        answers['staging_host'], staging=True, security=True))


def paste(host, check):
    """Save the vhost text CloudPanel must store and return the operator's instructions.

    CloudPanel has no command for changing a site's stored vhost, so this is done in
    its Vhost editor. The installers apply the same routing to the generated Nginx
    files themselves, so no later step waits for it: setup carries on and lists the
    pending pastes again at the end. Without the save, CloudPanel would drop the
    routing the next time it regenerates that site's Nginx file.
    """
    done, wanted = check
    if done:
        return None
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    target = OUTPUT / (host + '.vhost')
    target.write_text(wanted)
    target.chmod(0o600)
    return (f'Open CloudPanel, go to Sites, open {host}, then the Vhost tab.\n'
            f'Replace all the text with the contents of {target}\n'
            f'(view it with: cat {target}) and click Save.')


def operator_ready(answers):
    try:
        with sqlite3.connect('file:/var/lib/cloudpanel-companion-web/accounts.sqlite3?mode=ro', uri=True) as db:
            return db.execute('SELECT COUNT(*) FROM auth_user WHERE is_staff = 1 AND is_active = 1').fetchone()[0] > 0
    except sqlite3.Error:
        return False


def add_operator(username=None):
    username = username or input('Operator username: ').strip()
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,40}', username):
        raise SystemExit('Use 3 to 40 letters, digits, dots, dashes or underscores.')
    while True:
        password = getpass.getpass('Password (at least 14 characters): ')
        if len(password) >= 14 and password == getpass.getpass('Repeat password: '):
            break
        say('  Passwords did not match or were too short.')
    code = '''import json, os, sys
os.environ["COMPANION_WEB_CONFIG"] = os.environ["CREDENTIALS_DIRECTORY"] + "/web.json"
import django
django.setup()
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
data = json.load(sys.stdin)
User = get_user_model()
if User.objects.filter(username=data["username"]).exists():
    raise SystemExit("That operator already exists.")
user = User(username=data["username"], is_staff=True)
validate_password(data["password"], user)
user.set_password(data["password"])
user.save()
'''
    # Run as the interface's own account with its private configuration, the same
    # way the service runs, so the password never appears on a command line.
    subprocess.run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--uid=companion-web', '--gid=companion-web',
                    '--working-directory=/opt/cloudpanel-companion',
                    '--property=LoadCredential=web.json:' + str(CONFIG / 'web.json'),
                    '--setenv=DJANGO_SETTINGS_MODULE=companion_web.settings', str(VENV / 'bin' / 'python'), '-c', code],
                   input=json.dumps({'username': username, 'password': password}), text=True, check=True)
    say(f'  Operator {username} created. At first sign-in they set up an authenticator app.')


def slack_ready(answers):
    return (CONFIG / 'slack.json').exists()


def configure_slack(answers):
    from companion.delivery import validate_webhook
    say('  Create an incoming webhook in Slack (Apps > Incoming Webhooks) and paste its URL.')
    while True:
        url = getpass.getpass('  Slack webhook URL (hidden): ').strip()
        try:
            validate_webhook(url)
            break
        except ValueError as error:
            say('  ' + str(error))
    path = CONFIG / 'slack.json'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump({'slack_webhook': url}, stream)


def watched_units(answers):
    """The services of the installed parts that the service watch must cover."""
    units = []
    if staging_on(answers):
        units += ['companion-operations.service', 'companion-relay@' + answers['staging_user'] + '.service']
    if answers.get('page_cache') == 'yes':
        units += ['varnish.service', 'cache-manager-control.service']
    if answers.get('object_cache') == 'yes':
        units.append('companion-redis-' + answers['site_user'] + '.service')
    return units


def monitoring_ready(answers):
    """Installed, watching every installed part's service, and the website checks passing
    with the website's current certificate trust.

    Monitoring runs after the other components, so their services exist when it lists
    them; an install made in the earlier order is completed on the next run.
    """
    if not ((CONFIG / 'monitor.json').exists() and active('companion-monitor.timer')):
        return False
    watched = {unit.get('name') for unit in (private(CONFIG / 'system-watch.json') or {}).get('units', [])}
    if not set(watched_units(answers)) <= watched:
        return False
    from companion.monitor_setup import origin_trust_pending
    from companion.site_trust import site_ca_file
    if origin_trust_pending(private(CONFIG / 'monitor.json') or {}, answers['site_host'],
                            site_ca_file(answers['site_host']) is not None):
        return False
    if staging_on(answers):
        item = registered_site(answers)[1]
        if not (item and item.get('source_health_file') and application_check(answers, item['source_health_file'])):
            return False
    return True


def install_monitoring(answers):
    # --configure-targets adds the registered staging copy's application and database check.
    run('python3', ROOT / 'install-monitor.py', '--site-host', answers['site_host'], '--site-user', answers['site_user'],
        '--php', answers['php'], '--enable-recovery', '--configure-targets')


def application_check(answers, health_file):
    """The website's registered application and database check, run now."""
    from companion.health import Target, probe
    url = 'https://' + answers['site_host'] + '/' + health_file
    targets = [item for item in (private(CONFIG / 'monitor.json') or {}).get('targets', []) if item.get('url') == url]
    return bool(targets) and all(probe(Target(**item)).healthy for item in targets)


def staging_ready(answers):
    """Registered with both health endpoints and its services running.

    The website's application check that registration creates is verified by the
    Monitoring step, which needs the website's own certificate; staging itself does
    not, so a migrated site gets its staging copy before its DNS moves.
    """
    _, item = registered_site(answers)
    if not (item and item.get('health_file') and item.get('source_health_file')):
        return False
    return active('companion-operations.service') and active('companion-isolation-' + answers['staging_user'] + '.service')


# Provisioning phases it can safely continue from after an interruption.
PROVISION_RESUME = {'private-empty-site-created': '--resume-empty-site',
                    'separate-database-created': '--resume-database-created',
                    'guarded-files-installed': '--resume-files-installed'}
PROVISION_DONE = 'clone-complete-acceptance-pending'


def provision_staging(answers, path):
    """Create the staging copy, or continue an interrupted one from its recorded phase."""
    state = Path('/var/lib/cloudpanel-companion-jobs') / ('provision-' + answers['staging_user'])
    receipt = private(state / 'receipt.json')
    phase = receipt.get('phase') if receipt else None
    if phase == PROVISION_DONE or (phase is None and Path('/home', answers['staging_user']).exists()):
        # Finished here, or provisioned by the operator with `python3 -m companion.provision`.
        return
    arguments = ['python3', '-m', 'companion.provision', '--specification', path, '--state', state]
    if phase in PROVISION_RESUME:
        say(f'  Continuing the interrupted staging copy (stopped at "{phase}").')
        arguments.append(PROVISION_RESUME[phase])
    elif phase == 'prepared':
        say('  Continuing the staging copy that stopped before its site was created.')
    elif phase:
        raise SystemExit(f'  The staging copy stopped at "{phase}" and cannot be continued automatically.\n'
                         f'  Inspect {state} and the {answers["staging_user"]} site before running setup again.')
    else:
        Path('/var/lib/cloudpanel-companion-jobs').mkdir(mode=0o700, exist_ok=True)
    say('  Copying the website to staging. This can take a while for large sites.')
    run(*arguments, cwd=ROOT)


def install_staging(answers):
    path, spec = staging_spec(answers)
    if not path.exists():
        path.write_text(json.dumps(spec, indent=2))
        path.chmod(0o600)
    provision_staging(answers, path)
    run('python3', ROOT / 'install-operations.py', '--specification', path, '--site', site_id(answers))


def relay_ready(answers):
    return active('companion-relay@' + answers['staging_user'] + '.service')


def install_relay(answers):
    run('python3', ROOT / 'install-relay.py', '--registry', CONFIG / 'operations.json', '--site', registered_site(answers)[0])


def releases_ready(answers):
    """Release routing live and the uncached rendered-page check passing.

    install-deployment.py records its check before running it, so a failed check
    leaves the registry entry behind; only a passing check counts as done.
    """
    item = registered_site(answers)[1]
    if not (item and item.get('deploy_health_file') and active('companion-operations.service')):
        return False
    include = CONFIG / 'sites' / (answers['site_user'] + '-deployment.conf')
    try:
        generated = (NGINX_SITES / (answers['site_host'] + '.conf')).read_text()
    except OSError:
        return False
    if not include.is_file() or generated.count('include ' + str(include) + ';') != 1:
        return False
    from companion.registered_deployment import release_check
    try:
        return release_check(answers['site_host'], item['deploy_health_file'])
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return False


def install_releases(answers):
    run('python3', ROOT / 'install-deployment.py', '--registry', CONFIG / 'operations.json', '--site', registered_site(answers)[0])


def cache_ready(answers):
    sites = private(CONFIG / 'cache-sites.json') or {}
    routing = CONFIG / ('cache-routing-' + answers['site_host'] + '.conf')
    try:
        generated = (NGINX_SITES / (answers['site_host'] + '.conf')).read_text()
    except OSError:
        generated = ''
    # install-cache.py registers the site and starts the controller before its last step,
    # the website routing; a run that stopped in between is not finished. The ready
    # marker is the controller's own proof that the site's cache policy is active.
    import hashlib
    from companion.nginx_templates import CACHE_ROUTE, CACHE_UPSTREAM, UPSTREAMS
    marker = CACHE_READY / (hashlib.sha256(answers['site_host'].encode()).hexdigest() + '.ready')
    try:
        # Routing from before connection reuse is completed by running install-cache.py again.
        reuse = CACHE_UPSTREAM in routing.read_text() and CACHE_UPSTREAM in (NGINX_SITES / UPSTREAMS.name).read_text()
    except OSError:
        reuse = False
    return (answers['site_host'] in json.dumps(sites) and active('cache-manager-control.service')
            and active('varnish.service') and marker.is_file() and reuse
            and 'include ' + str(routing) + ';' in generated and CACHE_ROUTE in generated)


def install_cache(answers):
    run('python3', ROOT / 'install-cache.py', '--host', answers['site_host'], '--user', answers['site_user'],
        '--php', answers['php'], '--plugin-source', answers['cache_plugin'])


def object_cache_ready(answers):
    return ((CONFIG / ('object-cache-' + answers['site_user'] + '.json')).exists()
            and active('companion-redis-' + answers['site_user'] + '.service'))


def install_object_cache(answers):
    run('python3', ROOT / 'install-object-cache.py', '--host', answers['site_host'], '--user', answers['site_user'],
        '--php', answers['php'])


def staging_on(answers):
    return answers.get('staging') == 'yes'


STEPS = [
    ('Check the server', lambda a: True, lambda a: False, check_server),
    # Before every other step whose checks request the website over HTTPS.
    ('Trust for the website\'s Cloudflare Origin CA certificate', site_trust_applies, site_trust_ready, install_site_trust),
    ('Python environment for the interface', lambda a: True, python_ready, install_python),
    ('Companion interface services', lambda a: True, interface_ready, install_interface),
    ('HTTPS address for the interface', lambda a: True, ops_site_ready, create_ops_site),
    ('Interface routing in CloudPanel', lambda a: True, lambda a: ops_vhost(a)[0], interface_paste),
    ('First operator account', lambda a: True, operator_ready, lambda a: add_operator()),
    ('Slack alerts', lambda a: a.get('slack') == 'yes', slack_ready, configure_slack),
    ('Staging copy and controls', staging_on, staging_ready, install_staging),
    ('HTTPS certificate for staging', staging_on, lambda a: trusted_certificate(a['staging_host']), staging_certificate),
    ('Staging test relay (email capture, approved requests)', staging_on, relay_ready, install_relay),
    ('Code releases from staging', staging_on, releases_ready, install_releases),
    ('Page cache', lambda a: a.get('page_cache') == 'yes', cache_ready, install_cache),
    ('Object cache', lambda a: a.get('object_cache') == 'yes', object_cache_ready, install_object_cache),
    # After every component, so the service watch lists all of their services.
    ('Monitoring', lambda a: True, monitoring_ready, install_monitoring),
    ('Website routing in CloudPanel', lambda a: any(website_routing(a)), lambda a: site_vhost(a)[0],
     lambda a: paste(a['site_host'], site_vhost(a))),
    ('Staging routing in CloudPanel', staging_on, lambda a: staging_vhost(a)[0],
     lambda a: paste(a['staging_host'], staging_vhost(a))),
]

# Steps whose own checks request the website over HTTPS with certificate verification
# (or route traffic that those checks prove). A site moved from another host only gets
# its CloudPanel certificate once its DNS points here, so until then setup does every
# other step and leaves these waiting; running it again afterwards finishes them.
# The Origin CA trust waits too: release checks read it at once, so installing it
# before the imported certificate would fail a release against the old certificate.
NEEDS_SITE_CERTIFICATE = {'Trust for the website\'s Cloudflare Origin CA certificate', 'Code releases from staging',
                          'Page cache', 'Monitoring', 'Website routing in CloudPanel'}


def waits_for_certificate(title, answers):
    return title in NEEDS_SITE_CERTIFICATE and not site_certificate(answers)


def status(answers):
    say(f'Companion setup for {answers["site_host"]}')
    for title, applies, done, _ in STEPS[1:]:
        if not applies(answers):
            state = 'skipped'
        elif done(answers):
            state = 'done'
        else:
            state = 'waiting' if waits_for_certificate(title, answers) else 'to do'
        say(f'  [{state:^7}] {title}')
    if any(waits_for_certificate(title, answers) for title, *_ in STEPS):
        say(f'  "waiting": needs the HTTPS certificate of {answers["site_host"]} (see the end of setup).')


def indented(text, prefix='    '):
    return '\n'.join(prefix + line for line in text.splitlines())


def setup(answers):
    total = len(STEPS)
    pending, waiting = [], []
    for number, (title, applies, done, do) in enumerate(STEPS, 1):
        if not applies(answers):
            continue
        if done(answers):
            say(f'[{number}/{total}] {title}: already done')
            continue
        if waits_for_certificate(title, answers):
            say(f'[{number}/{total}] {title}: waits for the website\'s HTTPS certificate')
            waiting.append(title)
            continue
        say(f'[{number}/{total}] {title}')
        # A step that returns instructions is one the operator finishes in CloudPanel.
        instructions = do(answers)
        if instructions:
            say('  To do in CloudPanel (setup carries on; it is listed again at the end):')
            say(indented(instructions))
            pending.append((title, instructions))
            continue
        if number > 1 and not done(answers):
            raise SystemExit(f'  "{title}" did not complete. Fix the message above and run setup again.')
    if pending:
        say(f'\nSetup finished, except for {len(pending)} step{"s" if len(pending) > 1 else ""} '
            'to do in CloudPanel\'s website:')
        for number, (title, instructions) in enumerate(pending, 1):
            say(f'\n  {number}. {title}')
            say(indented(instructions, '     '))
        say('\nAfter saving, `sudo bash install.sh status` shows each of them as done.')
    if waiting and origin_ca(answers):
        say(f'\nWaiting for the Cloudflare Origin CA certificate of {answers["site_host"]}: {", ".join(waiting)}.\n'
            'Create it on Cloudflare\'s Origin Server page, import it in CloudPanel (the site\'s SSL/TLS tab,\n'
            'Actions > Import Certificate, or `clpctl site:install:certificate`) and run `sudo bash install.sh` again.')
    elif waiting:
        say(f'\nWaiting for the HTTPS certificate of {answers["site_host"]}: {", ".join(waiting)}.\n'
            'Once the website\'s DNS points to this server, issue it the CloudPanel way (CloudPanel then renews it):\n'
            f'  clpctl lets-encrypt:install:certificate --domainName={answers["site_host"]}\n'
            'and run `sudo bash install.sh` again.')
    elif not pending:
        say('\nSetup complete.')
    say(f'''Open https://{answers["ops_host"]}/ and sign in.

Still to do outside the Companion:
  - Off-server backups: install Rclone Automated Backups and test a restore.
  - An external uptime monitor (this server cannot report its own outage).
  - Optional safeguards: see docs/security-safeguards.md (check first, then apply in a quiet window).''')


def cleanup_staging(answers):
    """Remove superseded staging copies only after the operator has seen the list."""
    from companion.retention import retire
    site, _ = registered_site(answers)
    if site is None:
        raise SystemExit('No staging copy is registered for ' + answers['site_host'] + '.')
    registry = CONFIG / 'operations.json'
    candidates = retire(registry, site)['candidates']
    if not candidates:
        return say('Nothing to remove. The current staging copy and the latest recovery copies are kept.')
    say('These old staging copies (files and database) can be removed. The current copy and the')
    say('two latest successful and two latest rolled-back copies are always kept:')
    for item in candidates:
        size = quiet('du', '-sh', item['generation']).stdout.split('\t')[0] or '?'
        say(f'  {size:>6}  {item["generation"]}  (database {item["database"]})')
    if input('Remove them? Type "remove" to confirm: ').strip() != 'remove':
        return say('Nothing removed.')
    removed = retire(registry, site, apply=True)
    say(f'Removed {len(removed["candidates"])} old staging cop{"y" if len(removed["candidates"]) == 1 else "ies"}.')


def main():
    parser = argparse.ArgumentParser(prog='install.sh', description='Install or continue installing CloudPanel Companion.')
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('status', help='show which steps are done')
    sub.add_parser('cleanup-staging', help='list and remove old staging copies kept for recovery')
    operator = sub.add_parser('add-operator', help='create another operator login')
    operator.add_argument('username', nargs='?')
    parser.add_argument('--reconfigure', action='store_true', help='answer the setup questions again')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo: sudo bash install.sh')
    os.chdir(ROOT)
    if args.command == 'add-operator':
        return add_operator(args.username)
    answers = load_answers(args.reconfigure)
    if args.command == 'status':
        return status(answers)
    if args.command == 'cleanup-staging':
        return cleanup_staging(answers)
    setup(answers)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(f'\nA step failed (exit code {error.returncode}). Read the message above, fix it, then run setup again.')
    except KeyboardInterrupt:
        raise SystemExit('\nStopped. Run setup again to continue.')
