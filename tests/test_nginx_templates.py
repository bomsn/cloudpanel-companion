from pathlib import Path
import unittest
from companion.nginx_templates import (PHP_OVERRIDE, disable_native_controller, integration, interface_routing,
                                       interface_template, require_fresh_file_checks)


# A reverse-proxy file as `clpctl site:add:reverse-proxy` generates it (CloudPanel 2.5.4,
# recorded on the rehearsal server), and the file CloudPanel generates from the stored
# interface template once it is saved.
OPS_HEAD = '''server {
  listen 80;
  listen [::]:80;
  listen 443 quic;
  listen 443 ssl;
  listen [::]:443 quic;
  listen [::]:443 ssl;
  http2 on;
  http3 off;
  ssl_certificate_key /etc/nginx/ssl-certificates/ops.example.com.key;
  ssl_certificate /etc/nginx/ssl-certificates/ops.example.com.crt;
  server_name ops.example.com;
  root /home/shopops/htdocs/ops.example.com;

  access_log /home/shopops/logs/nginx/access.log main;
  error_log /home/shopops/logs/nginx/error.log;

  if ($scheme != "https") {
    rewrite ^ https://$host$request_uri permanent;
  }

'''
OPS_GENERATED = OPS_HEAD + '''  location @reverse_proxy {
    proxy_pass http://unix:/run/cloudpanel-companion-web/app.sock;
    proxy_http_version 1.1;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Server $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_ssl_server_name on;
    proxy_ssl_name $host;
    proxy_pass_request_headers on;
    proxy_max_temp_file_size 0;
    proxy_connect_timeout 900;
    proxy_send_timeout 900;
    proxy_read_timeout 900;
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;
    proxy_temp_file_write_size 256k;
  }

<SETTINGS>

  include /etc/nginx/global_settings;

  add_header Cache-Control no-transform;

  index index.html;

  location ^~ /.well-known {
    auth_basic off;
    allow all;
    try_files $uri @reverse_proxy;
  }

  location / {
    try_files $uri @reverse_proxy;
  }
}
'''.replace('<SETTINGS>', '  ')  # CloudPanel's empty {{settings}} leaves a line of two spaces
OPS_SAVED = OPS_HEAD + '''  include /etc/cloudpanel-companion/companion-web-proxy.conf;
<SETTINGS>
  include /etc/nginx/global_settings;
}
'''.replace('<SETTINGS>', '  ')


BASE = '''server {
  {{root}}
  auth_basic "Private staging";
  auth_basic_user_file /etc/cloudpanel-companion/lab.htpasswd;
  location / {
    proxy_pass http://127.0.0.1:8080;
  }
}
server {
  {{root}}
    fastcgi_param PHP_VALUE "{{php_settings}}";
}
'''

# A main-domain WordPress site's stored vhost as CloudPanel 2.5 keeps it (the www
# redirect, the public block and the 8080 PHP backend), shortened to what the
# integration reads, and a staging site's after its creation (staging.protected_template).
LISTEN_PUBLIC = '''  listen 80;
  listen [::]:80;
  listen 443 quic;
  listen 443 ssl;
  listen [::]:443 quic;
  listen [::]:443 ssl;
  http2 on;
  http3 off;
  {{ssl_certificate_key}}
  {{ssl_certificate}}
'''
PROXY_HEADERS = '''    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
'''
PUBLIC_BODY = r'''
  {{nginx_access_log}}
  {{nginx_error_log}}

  if ($scheme != "https") {
    rewrite ^ https://$host$request_uri permanent;
  }

  {{settings}}

  location ~/\.git {
    deny all;
  }

  location ~/(wp-admin/|wp-login.php) {
''' + PROXY_HEADERS + '''    proxy_pass http://127.0.0.1:8080;
    proxy_read_timeout 7200;
  }

  location / {
    <FRONTEND>
''' + PROXY_HEADERS + r'''    proxy_hide_header X-Varnish;
  }

  location ~* ^.+\.(css|js|jpg|jpeg|png|svg|woff2)$ {
    expires max;
    access_log off;
  }

  if (-f $request_filename) {
    break;
  }
}

server {
  listen 8080;
  listen [::]:8080;
  server_name <NAMES>;
  {{root}}
<BACKEND>
  include /etc/nginx/global_settings;

  try_files $uri $uri/ /index.php?$args;
  index index.php index.html;

  location ~ \.php$ {
    include fastcgi_params;
    fastcgi_pass 127.0.0.1:{{php_fpm_port}};
    fastcgi_param PHP_VALUE "{{php_settings}}";
  }
}
'''
WEBSITE_STORED = ('server {\n' + LISTEN_PUBLIC + '  server_name www.example.com;\n'
                  '  return 301 https://example.com$request_uri;\n}\n\n'
                  'server {\n' + LISTEN_PUBLIC + '  server_name example.com www1.example.com;\n  {{root}}\n'
                  + PUBLIC_BODY.replace('<FRONTEND>', '{{varnish_proxy_pass}}').replace('<NAMES>', 'example.com www1.example.com')
                  .replace('<BACKEND>', ''))
STAGING_ACCESS = '''  include /etc/cloudpanel-companion/sites/shopstg-access.conf;
  add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
  location = /wp-cron.php { return 403; }
'''
STAGING_STORED = ('server {\n' + LISTEN_PUBLIC + '  server_name stg.example.com;\n  {{root}}\n' + STAGING_ACCESS
                  + PUBLIC_BODY.replace('<FRONTEND>', 'proxy_pass http://127.0.0.1:8080;').replace('<NAMES>', 'stg.example.com')
                  .replace('<BACKEND>', STAGING_ACCESS))


class NativeTemplateTests(unittest.TestCase):
    def test_interface_keeps_native_tls_and_persistent_owned_routing(self):
        original = 'server {\n  {{ssl_certificate}}\n  {{root}}\n  location @reverse_proxy {\n    proxy_pass {{reverse_proxy_url}};\n  }\n}\n'
        result = interface_template(original)
        self.assertIn('{{ssl_certificate}}', result)
        self.assertIn('include /etc/cloudpanel-companion/companion-web-proxy.conf;', result)
        self.assertNotIn('reverse_proxy_url', result)
        self.assertEqual(interface_template(result), result)

    def test_browser_saved_crlf_templates_are_recognised(self):
        # CloudPanel's web editor stores CRLF; an already integrated site must
        # read as unchanged instead of failing the native-route check.
        integrated = integration(BASE, 'shop', 'shop.example.com')
        self.assertEqual(integration(integrated.replace('\n', '\r\n'), 'shop', 'shop.example.com'), integrated)
        native = 'server {\n  {{ssl_certificate}}\n  {{root}}\n  location @reverse_proxy {\n    proxy_pass {{reverse_proxy_url}};\n  }\n}\n'
        crlf = native.replace('\n', '\r\n')
        self.assertIn('companion-web-proxy.conf', interface_template(crlf))

    def test_optional_security_is_persistent_in_both_native_servers(self):
        for staging in (True, False):
            result = integration(BASE, 'example', 'example.com', staging, security=True)
            self.assertEqual(result.count('example-security.conf;'), 2)
            self.assertEqual(integration(result, 'example', 'example.com', staging, security=True), result)

    def test_frontend_reaches_the_cache_over_reused_connections(self):
        from companion.nginx_templates import (CACHE_ROUTE, CACHE_UPSTREAM, ORIGIN_UPSTREAM, PROXY_TO_CACHE,
                                               UPSTREAM_IDLE_SECONDS, cache_routing, cache_upstreams,
                                               frontend_cache_route)
        stored = integration(BASE, 'example', 'example.com')
        self.assertEqual(stored.count(CACHE_ROUTE), 1)
        self.assertIn('proxy_set_header Connection "";', stored)
        # A text saved before connection reuse gains it once, in place.
        older = stored.replace(CACHE_ROUTE, PROXY_TO_CACHE)
        self.assertEqual(integration(older, 'example', 'example.com'), stored)
        generated = BASE.replace('{{root}}', 'root /x;')
        once = frontend_cache_route(generated)
        self.assertEqual(once.count(CACHE_ROUTE), 1)
        self.assertEqual(frontend_cache_route(once), once)
        upstreams = cache_upstreams(6081, 8080)
        for name, port in ((CACHE_UPSTREAM, 6081), (ORIGIN_UPSTREAM, 8080)):
            self.assertIn('upstream ' + name + ' {\n    server 127.0.0.1:' + str(port) + ';\n    keepalive 256;', upstreams)
        self.assertIn('keepalive_timeout ' + str(UPSTREAM_IDLE_SECONDS) + 's;', upstreams)
        routing = cache_routing('example.com', '/run/ready/x.ready')
        self.assertIn('set $companion_cache_backend ' + ORIGIN_UPSTREAM + ';', routing)
        self.assertIn('if (-f /run/ready/x.ready) { set $companion_cache_backend ' + CACHE_UPSTREAM + '; }', routing)
        self.assertNotIn('127.0.0.1', routing)
        # Varnish must keep an idle connection longer than Nginx does, so only Nginx closes it.
        source = (Path(__file__).resolve().parents[1] / 'install-cache.py').read_text()
        self.assertIn("-p timeout_idle=''' + str(UPSTREAM_IDLE_SECONDS + 15) + '''", source)

    def test_native_placeholders_and_single_frontend_routes_survive(self):
        result = integration(BASE, 'example', 'example.com')
        self.assertEqual(result.count('{{root}}'), 2)
        self.assertIn('{{php_settings}}', result)
        self.assertEqual(result.count('cache-routing-example.com.conf'), 1)
        self.assertEqual(result.count('example-deployment.conf'), 1)
        self.assertNotIn('auth_basic "Private staging";', result)
        self.assertEqual(integration(result, 'example', 'example.com'), result)

    def test_staging_controls_live_in_persistent_includes(self):
        result = integration(BASE, 'staging', 'stage.example.com', True)
        self.assertEqual(result.count('staging-access.conf'), 2)
        self.assertNotIn('cache-routing-', result)
        self.assertNotIn('auth_basic_user_file', result)
        self.assertEqual(integration(result, 'staging', 'stage.example.com', True), result)

    def test_resolved_or_different_templates_are_rejected(self):
        with self.assertRaises(ValueError):
            integration(BASE.replace('{{root}}', 'root /resolved/path;'), 'example', 'example.com')

    def test_new_staging_is_created_with_its_persistent_controls(self):
        from companion.staging import protected_template
        template = ('  {{root}}\n  {{root}}\n    auth_basic off;\n'
                    '    {{varnish_proxy_pass}}\n'
                    '    fastcgi_param PHP_VALUE "{{php_settings}}";\n'
                    '  location ~ /.well-known {\n    allow all;\n  }')
        result = protected_template(template, '/etc/cloudpanel-companion/sites/staging-access.conf')
        self.assertEqual(result.count('include /etc/cloudpanel-companion/sites/staging-access.conf;'), 2)
        self.assertNotIn('auth_basic "Private staging";', result)
        self.assertIn('proxy_pass http://127.0.0.1:8080;', result)

    def test_generated_vhost_gets_the_stored_template_php_override(self):
        # CloudPanel writes {{php_settings}} out as a multi-line string in the generated file.
        generated = ('server {\n  location ~ \\.php$ {\n    fastcgi_pass 127.0.0.1:18001;\n'
                     '    fastcgi_param PHP_VALUE "\nerror_log=/home/shop/logs/php/error.log;\nmemory_limit=512M;";\n  }\n}\n')
        result = disable_native_controller(generated)
        self.assertIn('memory_limit=512M;";\n' + PHP_OVERRIDE + '\n  }', result)
        self.assertEqual(disable_native_controller(result), result)
        self.assertEqual(integration(BASE, 'shop', 'shop.example.com').count(PHP_OVERRIDE), 1)
        with self.assertRaises(ValueError):
            disable_native_controller(generated.replace('fastcgi_param PHP_VALUE', 'fastcgi_param OTHER'))

    def test_website_includes_carry_no_file_cache_directive(self):
        # Two `open_file_cache off;` in one server block fail `nginx -t`. The includes
        # rely on Nginx's default instead, and installers refuse a server that caches.
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        for installer in ('install-cache.py', 'install-deployment.py'):
            source = (root / installer).read_text()
            self.assertNotIn('open_file_cache', source, installer)
            self.assertIn('require_fresh_file_checks(', source, installer)
        dump = ('# configuration file /etc/nginx/nginx.conf:\nhttp {\n  # open_file_cache max=10;\n}\n'
                '# configuration file /etc/cloudpanel-companion/sites/stg-access.conf:\nopen_file_cache off;\n')
        require_fresh_file_checks(dump)
        for enabled in ('open_file_cache max=1000 inactive=20s;', '    open_file_cache   max=10;  # tuned'):
            with self.assertRaises(ValueError):
                require_fresh_file_checks(dump + enabled + '\n')

    def test_release_include_only_with_releases(self):
        # Without staging there is no release include file; a saved text naming it
        # would make Nginx reject the whole configuration.
        cache_only = integration(BASE, 'shop', 'shop.example.com', cache=True, releases=False)
        self.assertNotIn('shop-deployment.conf', cache_only)
        self.assertEqual(cache_only.count('cache-routing-shop.example.com.conf'), 1)
        self.assertEqual(integration(cache_only, 'shop', 'shop.example.com', cache=True, releases=False), cache_only)
        # An earlier text that carried the include without releases is corrected.
        both = integration(BASE, 'shop', 'shop.example.com')
        self.assertEqual(integration(both, 'shop', 'shop.example.com', cache=True, releases=False), cache_only)
        releases_only = integration(BASE, 'shop', 'shop.example.com', cache=False, releases=True)
        self.assertEqual(releases_only.count('shop-deployment.conf'), 1)
        self.assertNotIn('cache-routing-', releases_only)
        self.assertNotIn('$companion_cache_backend', releases_only)
        self.assertNotIn(PHP_OVERRIDE, releases_only)
        self.assertEqual(integration(releases_only, 'shop', 'shop.example.com', cache=False, releases=True), releases_only)
        # Adding the cache later keeps the include order of a fresh install.
        self.assertEqual(integration(releases_only, 'shop', 'shop.example.com'), both)

    def test_client_address_includes_land_in_every_website_block(self):
        from companion.nginx_templates import BACKEND_TRUST_INCLUDE, PUBLIC_TRUST_INCLUDE, server_blocks
        options = dict(security=True, telemetry=True)
        before = integration(WEBSITE_STORED, 'shop', 'example.com', **options)
        result = integration(WEBSITE_STORED, 'shop', 'example.com', client_address=True, **options)
        redirect, public, backend = server_blocks(result)
        self.assertEqual([kind for kind, _ in (redirect, public, backend)], ['redirect', 'public', 'backend'])
        self.assertIn('  server_name www.example.com;\n' + PUBLIC_TRUST_INCLUDE + '\n  return 301 ', redirect[1])
        self.assertIn('  {{root}}\n' + PUBLIC_TRUST_INCLUDE + '\n  include /etc/cloudpanel-companion/sites/shop-security.conf;\n',
                      public[1])
        self.assertIn('  {{root}}\n' + BACKEND_TRUST_INCLUDE + '\n  include /etc/cloudpanel-companion/sites/shop-security.conf;\n',
                      backend[1])
        for (_, block), wanted, unwanted in ((redirect, 1, 0), (public, 1, 0), (backend, 0, 1)):
            self.assertEqual(block.count(PUBLIC_TRUST_INCLUDE), wanted)
            self.assertEqual(block.count(BACKEND_TRUST_INCLUDE), unwanted)
        # Exactly three lines added to the text without them, which is what a re-paste changes.
        added = [line for line in result.splitlines() if line not in before.splitlines()]
        self.assertEqual(added, [PUBLIC_TRUST_INCLUDE, PUBLIC_TRUST_INCLUDE, BACKEND_TRUST_INCLUDE])
        self.assertEqual(len(result.splitlines()), len(before.splitlines()) + 3)
        # Idempotent, also for CloudPanel's CRLF browser saves and an earlier text without the includes.
        self.assertEqual(integration(result, 'shop', 'example.com', client_address=True, **options), result)
        self.assertEqual(integration(result.replace('\n', '\r\n'), 'shop', 'example.com', client_address=True, **options), result)
        self.assertEqual(integration(before, 'shop', 'example.com', client_address=True, **options), result)
        # Present only while its files exist, like the other includes.
        self.assertEqual(integration(result, 'shop', 'example.com', **options), before)
        # A subdomain site has no www redirect block.
        subdomain = WEBSITE_STORED.split('}\n\n', 1)[1]
        alone = integration(subdomain, 'shop', 'example.com', client_address=True, **options)
        self.assertEqual((alone.count(PUBLIC_TRUST_INCLUDE), alone.count(BACKEND_TRUST_INCLUDE)), (1, 1))
        # Without the page cache the frontend keeps CloudPanel's placeholder, which also forwards $remote_addr.
        uncached = integration(WEBSITE_STORED, 'shop', 'example.com', cache=False, releases=False, client_address=True)
        self.assertIn('{{varnish_proxy_pass}}', uncached)
        self.assertEqual((uncached.count(PUBLIC_TRUST_INCLUDE), uncached.count(BACKEND_TRUST_INCLUDE)), (2, 1))

    def test_client_address_includes_land_in_both_staging_blocks(self):
        from companion.nginx_templates import BACKEND_TRUST_INCLUDE, PUBLIC_TRUST_INCLUDE, server_blocks
        result = integration(STAGING_STORED, 'shopstg', 'stg.example.com', True, security=True, client_address=True)
        public, backend = server_blocks(result)
        self.assertEqual((public[0], backend[0]), ('public', 'backend'))
        self.assertIn('  {{root}}\n' + PUBLIC_TRUST_INCLUDE + '\n', public[1])
        self.assertIn('  {{root}}\n' + BACKEND_TRUST_INCLUDE + '\n', backend[1])
        self.assertNotIn(BACKEND_TRUST_INCLUDE, public[1])
        self.assertNotIn(PUBLIC_TRUST_INCLUDE, backend[1])
        self.assertEqual(result.count('shopstg-access.conf;'), 2)
        self.assertEqual(result.count('shopstg-security.conf;'), 2)
        self.assertNotIn('cache-routing-', result)
        self.assertEqual(integration(result, 'shopstg', 'stg.example.com', True, security=True, client_address=True), result)

    def test_client_address_includes_refuse_duplicates_and_unknown_layouts(self):
        from companion.nginx_templates import BACKEND_TRUST_INCLUDE, PUBLIC_TRUST_INCLUDE
        result = integration(WEBSITE_STORED, 'shop', 'example.com', client_address=True)
        public_root = '  {{root}}\n' + PUBLIC_TRUST_INCLUDE + '\n'
        backend_root = '  {{root}}\n' + BACKEND_TRUST_INCLUDE + '\n'
        changed = {
            'second copy': result.replace(public_root, public_root + PUBLIC_TRUST_INCLUDE + '\n'),
            're-indented copy': result.replace(public_root, '  {{root}}\n  ' + PUBLIC_TRUST_INCLUDE + '\n'),
            'backend rules in the public block': result.replace(public_root, public_root + BACKEND_TRUST_INCLUDE + '\n'),
            'public rules in the backend block': result.replace(backend_root, backend_root + PUBLIC_TRUST_INCLUDE + '\n'),
            'another server block': result + 'server {\n  listen 8081;\n  server_name other.example.com;\n}\n',
            'backend on another port': WEBSITE_STORED.replace('  listen 8080;\n  listen [::]:8080;\n', '  listen 8081;\n'),
            'a second redirect': WEBSITE_STORED.split('\n\n', 1)[0] + '\n\n' + WEBSITE_STORED,
            'text before the first block': '# note\n' + WEBSITE_STORED,
            'a proxied location without X-Real-IP': WEBSITE_STORED.replace(
                PROXY_HEADERS + '    proxy_pass http://127.0.0.1:8080;', PROXY_HEADERS.replace(
                    '    proxy_set_header X-Real-IP $remote_addr;\n', '') + '    proxy_pass http://127.0.0.1:8080;'),
            'a client X-Real-IP passed on': WEBSITE_STORED.replace(
                PROXY_HEADERS + '    proxy_pass http://127.0.0.1:8080;', PROXY_HEADERS.replace(
                    'X-Real-IP $remote_addr', 'X-Real-IP $http_x_real_ip') + '    proxy_pass http://127.0.0.1:8080;'),
            'a proxy outside a location': WEBSITE_STORED.replace('  {{settings}}\n', '  {{settings}}\n  proxy_pass http://127.0.0.1:8080;\n'),
            'a one-line proxied location': WEBSITE_STORED.replace(
                '  {{settings}}\n', '  {{settings}}\n  location /feed { proxy_pass http://127.0.0.1:8080; }\n'),
        }
        for name, text in changed.items():
            with self.subTest(name), self.assertRaises(ValueError):
                integration(text, 'shop', 'example.com', client_address=True)
        # A copy that is not exactly ours is not silently dropped either.
        with self.assertRaises(ValueError):
            integration(changed['re-indented copy'], 'shop', 'example.com')

    def test_generated_interface_file_gets_the_saved_template_routing(self):
        self.assertEqual(interface_routing(OPS_GENERATED), OPS_SAVED)
        self.assertEqual(interface_routing(OPS_SAVED), OPS_SAVED)
        # CloudPanel's {{settings}} text survives, as it does in the saved template.
        custom = OPS_GENERATED.replace('\n  \n\n  include /etc/nginx/global_settings;',
                                       '\n  client_body_timeout 10;\n\n  include /etc/nginx/global_settings;')
        self.assertEqual(interface_routing(custom), OPS_SAVED.replace(
            '\n  \n  include /etc/nginx/global_settings;', '\n  client_body_timeout 10;\n  include /etc/nginx/global_settings;'))
        for changed in (OPS_GENERATED.replace('location @reverse_proxy', 'location @backend'),
                        OPS_GENERATED + OPS_GENERATED):
            with self.assertRaises(ValueError):
                interface_routing(changed)

    def test_site_server_name_covers_subdomains_and_main_domains(self):
        from companion.nginx_templates import site_server_name
        # Server names as CloudPanel 2.5 generates them for a WordPress site: a subdomain
        # site, and a main domain (recorded on a production server, 2 Nov 2026), whose
        # public and 8080 blocks carry a www1 alias after a separate www redirect block.
        subdomain = 'server {\n  server_name shop.example.com;\n}\nserver {\n  listen 8080;\n  server_name shop.example.com;\n}\n'
        main = ('server {\n  server_name www.example.com;\n  return 301 https://example.com$request_uri;\n}\n'
                'server {\n  server_name example.com www1.example.com;\n}\n'
                'server {\n  listen 8080;\n  server_name example.com www1.example.com;\n}\n')
        self.assertEqual(site_server_name(subdomain, 'shop.example.com'), '  server_name shop.example.com;')
        self.assertEqual(site_server_name(main, 'example.com'), '  server_name example.com www1.example.com;')
        for unknown in (main.replace('listen 8080;\n  server_name example.com www1.example.com;', 'listen 8080;'),
                        main.replace('  server_name example.com www1.example.com;\n}\nserver {\n  listen 8080;\n  server_name example.com www1.example.com;',
                                     '  server_name example.com www1.example.com;\n}\nserver {\n  listen 8080;\n  server_name example.com;'),
                        subdomain.replace('shop.example.com;', 'shop.example.com.evil.test;')):
            with self.assertRaises(ValueError):
                site_server_name(unknown, 'example.com' if 'example.com www1' in unknown else 'shop.example.com')
