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
        result = protected_template(template, '/etc/cloudpanel-companion/staging.htpasswd',
                                    '/etc/cloudpanel-companion/sites/staging-access.conf')
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
