"""Generate persistent native CloudPanel templates, preserving placeholders.

Saving a generated Nginx file does not update CloudPanel's stored vhost. Apply
this template through its native Vhost editor, or select the registered custom
template when creating a site. Never replace the panel's database directly.
"""
import argparse
from pathlib import Path
import re
import sys


PHP_OVERRIDE = '    fastcgi_param PHP_ADMIN_VALUE "auto_prepend_file=none";'


def disable_native_controller(generated):
    """Add the PHP override to a generated vhost the way the stored template does.

    The override stops CloudPanel's own Varnish controller (auto_prepend_file), so the
    Companion's page cache is the only cache owner. CloudPanel expands {{php_settings}}
    into a multi-line PHP_VALUE string in the generated file, so the stored-template
    anchor does not exist there.
    """
    if PHP_OVERRIDE in generated:
        return generated
    directives = re.findall(r'^    fastcgi_param PHP_VALUE "[^"]*";\n', generated, flags=re.M)
    if len(directives) != 1:
        raise ValueError('Native PHP-settings directive changed; no Nginx change made')
    return generated.replace(directives[0], directives[0] + PHP_OVERRIDE + '\n', 1)


def require_fresh_file_checks(configuration):
    """Refuse a server whose Nginx caches file lookups (`configuration` is `nginx -T` output).

    The page-cache and release includes switch routing with `if (-f marker)`, which
    must see a marker the moment it appears or disappears. Nginx checks the file on
    every request unless `open_file_cache` is enabled, and CloudPanel does not enable
    it. The includes therefore carry no directive of their own, so their number and
    install order can never produce the duplicate directive Nginx rejects.
    """
    for line in configuration.splitlines():
        directive = line.split('#', 1)[0].strip()
        if directive.startswith('open_file_cache ') and directive[len('open_file_cache '):].rstrip(';').strip() != 'off':
            raise ValueError('Nginx caches file lookups (' + directive + '); the maintenance and page-cache '
                             'routing need open_file_cache off. Remove it from the Nginx configuration first.')


INTERFACE_INCLUDE = '  include /etc/cloudpanel-companion/companion-web-proxy.conf;'


def interface_template(original):
    """Preserve native TLS/domain settings and store the owned UI routing once."""
    # CloudPanel stores text saved from its browser editor with CRLF endings.
    original = original.replace('\r\n', '\n')
    if original.count('{{root}}') != 1 or original.count('{{ssl_certificate}}') != 1:
        raise ValueError('Use the native reverse-proxy template for the operations site')
    if INTERFACE_INCLUDE in original:
        if original.count(INTERFACE_INCLUDE) != 1:
            raise ValueError('Duplicate operations routing')
        return original
    anchor = '  location @reverse_proxy {'
    if original.count(anchor) != 1 or '{{reverse_proxy_url}}' not in original:
        raise ValueError('Native reverse-proxy template changed; inspect it')
    return original.split(anchor, 1)[0] + INTERFACE_INCLUDE + '\n  {{settings}}\n  include /etc/nginx/global_settings;\n}\n'


def interface_routing(generated):
    """The interface routing in a generated reverse-proxy file, as CloudPanel renders it.

    Gives the generated Nginx file what the stored interface template produces
    (`interface_template`, with CloudPanel's {{settings}} text kept), so the interface
    is served through its owned routing from the moment its site exists. Saving the
    stored template in CloudPanel's Vhost editor then only makes it persistent.
    """
    if INTERFACE_INCLUDE in generated:
        if generated.count(INTERFACE_INCLUDE) != 1:
            raise ValueError('Duplicate operations routing')
        return generated
    match = re.fullmatch(r'(.*?\n)  location @reverse_proxy \{\n(?:    [^\n]*\n)*  \}\n\n  (.*?)\n\n'
                         r'  include /etc/nginx/global_settings;\n.*', generated, flags=re.S)
    if not match or generated.count('  location @reverse_proxy {') != 1 or generated.count('server {') != 1:
        raise ValueError('Native reverse-proxy file changed; inspect it')
    return match[1] + INTERFACE_INCLUDE + '\n  ' + match[2] + '\n  include /etc/nginx/global_settings;\n}\n'


TELEMETRY_INCLUDE = '  include /etc/cloudpanel-companion/telemetry-public.conf;'

# The website's public block reaches the page cache (or, while the cache is not ready,
# its PHP backend) over long-lived connections from these HTTP-level upstream groups
# (CloudPanel loads sites-enabled at HTTP scope). With a new loopback connection per
# request, each close left the cache's end waiting in LAST-ACK, and a later request
# whose connection reused that port waited about a minute (replay 2 load test: 59
# requests/s instead of 9,700 at 10 concurrent cached requests, timeouts at 100).
UPSTREAMS = Path('/etc/nginx/sites-enabled/000-companion-cache-upstreams.conf')
CACHE_UPSTREAM, ORIGIN_UPSTREAM = 'companion_cache_varnish', 'companion_cache_origin'
# Idle connections close after a minute, from the Nginx side; Varnish's own idle limit
# is set above it (install-cache.py, timeout_idle) so it never closes one Nginx may reuse.
UPSTREAM_IDLE_SECONDS = 60
PROXY_TO_CACHE = '  location / {\n    proxy_pass http://$companion_cache_backend;'
CACHE_ROUTE = PROXY_TO_CACHE + '\n    proxy_http_version 1.1;\n    proxy_set_header Connection "";'


def cache_upstreams(cache_port, origin_port):
    return ''.join('upstream ' + name + ' {\n    server 127.0.0.1:' + str(port) + ';\n    keepalive 256;\n'
                   '    keepalive_requests 100000;\n    keepalive_timeout ' + str(UPSTREAM_IDLE_SECONDS) + 's;\n}\n'
                   for name, port in ((CACHE_UPSTREAM, cache_port), (ORIGIN_UPSTREAM, origin_port)))


def cache_routing(host, marker):
    """The per-site include that picks the page cache only while its policy is ready."""
    return ('set $companion_cache_backend ' + ORIGIN_UPSTREAM + ';\n'
            'if (-f ' + marker + ') { set $companion_cache_backend ' + CACHE_UPSTREAM + '; }\n'
            'if ($host != "' + host + '") { set $companion_cache_backend ' + ORIGIN_UPSTREAM + '; }\n')


def frontend_cache_route(generated):
    """A generated website file's frontend location routed to the cache, with connection reuse."""
    if CACHE_ROUTE in generated:
        return generated
    if PROXY_TO_CACHE in generated:
        return generated.replace(PROXY_TO_CACHE, CACHE_ROUTE, 1)
    block = '  location / {\n    proxy_pass http://127.0.0.1:8080;'
    if generated.count(block) != 1:
        raise ValueError('Unexpected native frontend route; no Nginx change made')
    return generated.replace(block, CACHE_ROUTE, 1)


def integration(original, user, host, staging=False, security=False, cache=True, releases=True, telemetry=False):
    """The stored vhost with the Companion includes for the parts installed on the site.

    `cache` adds the page-cache routing and frontend route, `releases` the release
    maintenance include (installed only with a staging copy), `security` the
    safeguards include, `telemetry` monitoring's request log on the public server
    block (the first one), and `staging` the staging access include instead.
    """
    original = original.replace('\r\n', '\n')
    if not re.fullmatch(r'[a-z][a-z0-9-]{2,30}', user) or not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', host):
        raise ValueError('Explicit site identity required')
    if original.count('  {{root}}') != 2 or '{{php_settings}}' not in original:
        raise ValueError('Use the native stored template, not a generated Nginx file')
    # Upgrade only the Companion's own old inline protection. Other user-supplied
    # HTTP authentication must be reviewed rather than silently removed.
    result = re.sub(r'^  auth_basic "Private staging";\n', '', original, flags=re.M)
    result = re.sub(r'^  auth_basic_user_file /etc/cloudpanel-companion/[a-z0-9_-]+[.]htpasswd;\n', '', result, flags=re.M)
    if staging:
        include = '  include /etc/cloudpanel-companion/sites/' + user + '-access.conf;'
        if include not in result:
            result = result.replace('  {{root}}', '  {{root}}\n' + include)
        if result.count(include) != 2:
            raise ValueError('Staging must retain two native access includes')
    else:
        routing = '  include /etc/cloudpanel-companion/cache-routing-' + host + '.conf;'
        deployment = '  include /etc/cloudpanel-companion/sites/' + user + '-deployment.conf;'
        if cache and routing not in result:
            result = result.replace('  {{root}}', '  {{root}}\n' + routing, 1)
        # Nginx refuses a saved template whose include file does not exist, so the
        # release include is present only when releases are installed (and an
        # earlier text that carried it without them is corrected).
        if not releases:
            result = result.replace(deployment + '\n', '')
        elif deployment not in result:
            result = result.replace(routing, routing + '\n' + deployment, 1) if cache else \
                result.replace('  {{root}}', '  {{root}}\n' + deployment, 1)
        block = '  location / {\n    proxy_pass http://127.0.0.1:8080;'
        placeholder = '  location / {\n    {{varnish_proxy_pass}}'
        route = CACHE_ROUTE
        if cache and route not in result:
            if PROXY_TO_CACHE in result:   # routing saved before connection reuse
                result = result.replace(PROXY_TO_CACHE, route, 1)
            elif result.count(block) + result.count(placeholder) == 1:
                result = result.replace(block, route).replace(placeholder, route)
            else:
                raise ValueError('Native frontend cache route changed; review it')
        # The request log records the cache result and the time to the first byte from
        # the backend, which only the public block (in front of the cache) sees.
        # Like the release include, it is present only while its file exists.
        if not telemetry:
            result = result.replace(TELEMETRY_INCLUDE + '\n', '')
        elif TELEMETRY_INCLUDE not in result:
            result = result.replace('  {{root}}', '  {{root}}\n' + TELEMETRY_INCLUDE, 1)
        if (result.count(routing) != (1 if cache else 0) or result.count(deployment) != (1 if releases else 0) or
                result.count(route) != (1 if cache else 0) or result.count(TELEMETRY_INCLUDE) != (1 if telemetry else 0)):
            raise ValueError('Unexpected duplicate website integration')
    anchor = '    fastcgi_param PHP_VALUE "{{php_settings}}";'
    override = PHP_OVERRIDE
    if result.count(anchor) != 1:
        raise ValueError('Native PHP-settings placeholder changed')
    # The override stops CloudPanel's own Varnish controller where the Companion's
    # page cache (or staging, which must never use it) takes its place.
    if (staging or cache) and override not in result:
        result = result.replace(anchor, anchor + '\n' + override)
    if security:
        safeguard = '  include /etc/cloudpanel-companion/sites/' + user + '-security.conf;'
        if safeguard not in result:
            result = result.replace('  {{root}}', '  {{root}}\n' + safeguard)
        if result.count(safeguard) != 2:
            raise ValueError('Both frontend and PHP backend require the registered security include')
    return result.replace('$proxy_add_x_forwarded_for', '$remote_addr')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--staging', action='store_true')
    parser.add_argument('--security', action='store_true')
    parser.add_argument('--cache', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--releases', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--telemetry', action='store_true')
    parser.add_argument('--input', type=Path, required=True)
    args = parser.parse_args()
    original = sys.stdin.read() if str(args.input) == '-' else args.input.read_text()
    sys.stdout.write(integration(original, args.user, args.host, args.staging, args.security, args.cache, args.releases,
                                 args.telemetry))


if __name__ == '__main__':
    main()
