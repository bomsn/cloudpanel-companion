import os
import unittest
from pathlib import Path
from companion import guided_setup


class GuidedSetupTests(unittest.TestCase):
    def test_every_step_installer_exists(self):
        root = Path(guided_setup.__file__).resolve().parents[1]
        source = Path(guided_setup.__file__).read_text()
        for script in ('install-web.py', 'install-monitor.py', 'install-operations.py', 'install-relay.py',
                       'install-deployment.py', 'install-cache.py', 'install-object-cache.py'):
            self.assertIn(script, source)
            self.assertTrue((root / script).is_file(), script)
        self.assertTrue((root / 'install.sh').is_file())

    def test_qualified_order_is_kept(self):
        titles = [title for title, *_ in guided_setup.STEPS]
        order = ['Companion interface services', 'HTTPS address for the interface', 'Interface routing in CloudPanel',
                 'First operator account', 'Staging copy and controls', 'Code releases from staging',
                 'Page cache', 'Object cache', 'Monitoring', 'Website routing in CloudPanel']
        self.assertEqual([title for title in titles if title in order], order)

    def test_monitoring_follows_every_component_it_watches(self):
        titles = [title for title, *_ in guided_setup.STEPS]
        for component in ('Staging copy and controls', 'Staging test relay (email capture, approved requests)',
                          'Code releases from staging', 'Page cache', 'Object cache'):
            self.assertLess(titles.index(component), titles.index('Monitoring'), component)

    def test_monitoring_is_done_only_when_it_watches_every_installed_service(self):
        import json
        import tempfile
        from unittest import mock
        answers = {'site_host': 'shop.example.com', 'site_user': 'shop', 'php': '8.3', 'staging': 'yes',
                   'staging_user': 'shopstg', 'page_cache': 'yes', 'object_cache': 'yes'}
        expected = ['companion-operations.service', 'companion-relay@shopstg.service', 'varnish.service',
                    'cache-manager-control.service', 'companion-redis-shop.service']
        self.assertEqual(guided_setup.watched_units(answers), expected)
        item = {'health_file': 'companion-health-x.php', 'source_health_file': 'companion-origin-y.php'}
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder)
            (config / 'monitor.json').write_text('{"targets": []}')
            watch = config / 'system-watch.json'
            with mock.patch.object(guided_setup, 'CONFIG', config), \
                    mock.patch.object(guided_setup, 'active', return_value=True), \
                    mock.patch.object(guided_setup, 'registered_site', return_value=('shop', item)), \
                    mock.patch.object(guided_setup, 'application_check', return_value=True) as check:
                # Installed in the earlier order: the later components' services were never added.
                watch.write_text(json.dumps({'units': [{'name': 'nginx.service'}, {'name': 'varnish.service'}]}))
                self.assertFalse(guided_setup.monitoring_ready(answers))
                watch.write_text(json.dumps({'units': [{'name': name} for name in ['nginx.service', *expected]]}))
                self.assertTrue(guided_setup.monitoring_ready(answers))
                check.assert_called_with(answers, 'companion-origin-y.php')
                check.return_value = False
                self.assertFalse(guided_setup.monitoring_ready(answers))
        # The monitoring installer also adds the registered staging copy's application check.
        with mock.patch.object(guided_setup, 'run') as executed:
            guided_setup.install_monitoring(answers)
        self.assertIn('--configure-targets', [str(item) for item in executed.call_args.args])

    def test_steps_that_need_the_website_certificate_wait_for_it(self):
        import contextlib
        import io
        from unittest import mock
        ran = []
        steps = [(title, lambda a: True, lambda a, title=title: title in ran,
                  lambda a, title=title: ran.append(title)) for title in
                 ('Check the server', 'Staging copy and controls', 'Code releases from staging', 'Page cache',
                  'Object cache', 'Monitoring', 'Website routing in CloudPanel', 'Staging routing in CloudPanel')]
        answers = {'site_host': 'shop.example.com', 'ops_host': 'ops.example.com'}
        printed = io.StringIO()
        # A migrated site before its DNS moves: CloudPanel only has its self-signed certificate.
        with mock.patch.object(guided_setup, 'STEPS', steps), \
                mock.patch.object(guided_setup, 'trusted_certificate', return_value=False), \
                contextlib.redirect_stdout(printed):
            guided_setup.setup(answers)
            guided_setup.status(answers)
        self.assertEqual(ran, ['Check the server', 'Staging copy and controls', 'Object cache', 'Staging routing in CloudPanel'])
        self.assertIn('clpctl lets-encrypt:install:certificate --domainName=shop.example.com', printed.getvalue())
        self.assertNotIn('Setup complete.', printed.getvalue())
        self.assertIn('[waiting] Page cache', printed.getvalue())
        # After CloudPanel issued it, the same run finishes the rest.
        with mock.patch.object(guided_setup, 'STEPS', steps), \
                mock.patch.object(guided_setup, 'trusted_certificate', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as finished:
            guided_setup.setup(answers)
        self.assertEqual(ran[4:], ['Code releases from staging', 'Page cache', 'Monitoring', 'Website routing in CloudPanel'])
        self.assertIn('Setup complete.', finished.getvalue())
        self.assertEqual(guided_setup.NEEDS_SITE_CERTIFICATE - {title for title, *_ in guided_setup.STEPS}, set())

    def test_cloudflare_origin_ca_waits_for_an_imported_certificate(self):
        import contextlib
        import io
        from unittest import mock
        answers = {'site_host': 'shop.example.com', 'ops_host': 'ops.example.com', 'cloudflare_origin_ca': 'yes'}
        site = lambda kind: {'certificate': 7, 'certificate_type': kind}
        # CloudPanel's own type codes: 1 self-signed, 2 Let's Encrypt, 3 imported.
        for kind, ready in (('1', False), ('2', False), ('3', True)):
            with self.subTest(kind=kind), mock.patch.object(guided_setup, 'panel_site', return_value=site(kind)):
                self.assertEqual(guided_setup.site_certificate(answers), ready)
                self.assertEqual(guided_setup.site_certificate({**answers, 'cloudflare_origin_ca': 'no'}), kind != '1')
        steps = [('Check the server', lambda a: True, lambda a: False, lambda a: None),
                 ('Monitoring', lambda a: True, lambda a: False, lambda a: None)]
        with mock.patch.object(guided_setup, 'STEPS', steps), \
                mock.patch.object(guided_setup, 'panel_site', return_value=site('2')), \
                contextlib.redirect_stdout(io.StringIO()) as printed:
            guided_setup.setup(answers)
        self.assertIn('Actions > Import Certificate', printed.getvalue())
        self.assertNotIn('lets-encrypt', printed.getvalue())

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'The installed file must be root-owned')
    def test_origin_ca_answer_installs_and_removes_the_trusted_roots(self):
        import tempfile
        from unittest import mock
        from companion import site_trust
        answers = {'site_host': 'shop.example.com', 'cloudflare_origin_ca': 'no'}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(site_trust, 'CONFIG', Path(folder)):
            self.assertFalse(guided_setup.site_trust_applies(answers))
            answers['cloudflare_origin_ca'] = 'yes'
            self.assertTrue(guided_setup.site_trust_applies(answers))
            self.assertFalse(guided_setup.site_trust_ready(answers))
            guided_setup.install_site_trust(answers)
            self.assertTrue(guided_setup.site_trust_ready(answers))
            # A checkout with different roots replaces the installed ones.
            Path(site_trust.site_ca_file('shop.example.com')).write_text('older roots\n')
            self.assertFalse(guided_setup.site_trust_ready(answers))
            guided_setup.install_site_trust(answers)
            self.assertTrue(guided_setup.site_trust_ready(answers))
            answers['cloudflare_origin_ca'] = 'no'
            self.assertTrue(guided_setup.site_trust_applies(answers))
            self.assertFalse(guided_setup.site_trust_ready(answers))
            guided_setup.install_site_trust(answers)
            self.assertTrue(guided_setup.site_trust_ready(answers))
            self.assertFalse(guided_setup.site_trust_applies(answers))

    def test_origin_ca_trust_waits_for_the_certificate_and_precedes_every_website_check(self):
        titles = [title for title, *_ in guided_setup.STEPS]
        title = 'Trust for the website\'s Cloudflare Origin CA certificate'
        # Release checks read the installed trust at once, so it follows the imported certificate.
        self.assertIn(title, guided_setup.NEEDS_SITE_CERTIFICATE)
        self.assertTrue(all(titles.index(title) < titles.index(other)
                            for other in guided_setup.NEEDS_SITE_CERTIFICATE - {title}))

    def test_optional_components_are_skipped_when_declined(self):
        import tempfile
        from unittest import mock
        answers = {'site_host': 'shop.example.com', 'staging': 'no', 'page_cache': 'no', 'object_cache': 'no'}
        applied = lambda: [title for title, applies, *_ in guided_setup.STEPS if applies(answers)]
        # An empty configuration folder, so the result never depends on the machine running the test.
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(guided_setup, 'CONFIG', Path(folder)):
            self.assertNotIn('Staging copy and controls', applied())
            self.assertNotIn('Page cache', applied())
            self.assertNotIn('Website routing in CloudPanel', applied())
            self.assertIn('Monitoring', applied())
            # Monitoring's request log still needs the website routing saved.
            (Path(folder) / 'telemetry-public.conf').write_text('access_log off;\n')
            self.assertIn('Website routing in CloudPanel', applied())

    def test_pending_vhost_paste_does_not_stop_later_steps(self):
        import contextlib
        import io
        import tempfile
        from unittest import mock
        ran = []
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'companion-setup'
            steps = [
                ('Check the server', lambda a: True, lambda a: False, lambda a: ran.append('check')),
                ('Interface routing in CloudPanel', lambda a: True, lambda a: False,
                 lambda a: guided_setup.paste('ops.example.com', (False, 'stored text\n'))),
                ('Monitoring', lambda a: True, lambda a: 'monitor' in ran, lambda a: ran.append('monitor')),
            ]
            printed = io.StringIO()
            with mock.patch.object(guided_setup, 'STEPS', steps), mock.patch.object(guided_setup, 'OUTPUT', output), \
                    mock.patch.object(guided_setup, 'trusted_certificate', return_value=True), \
                    contextlib.redirect_stdout(printed):
                guided_setup.setup({'ops_host': 'ops.example.com', 'site_host': 'shop.example.com'})
            saved = output / 'ops.example.com.vhost'
            self.assertEqual(saved.read_text(), 'stored text\n')
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        self.assertEqual(ran, ['check', 'monitor'])
        summary = printed.getvalue().split('Setup finished, except for 1 step', 1)[1]
        self.assertIn('Interface routing in CloudPanel', summary)
        self.assertIn('cat ' + str(saved), summary)
        self.assertNotIn('Setup complete.', printed.getvalue())

    def test_saved_vhost_needs_no_paste(self):
        self.assertIsNone(guided_setup.paste('ops.example.com', (True, 'stored text\n')))

    def test_printed_commands_hide_generated_passwords(self):
        import contextlib
        import io
        from unittest import mock
        printed = io.StringIO()
        with mock.patch.object(guided_setup.subprocess, 'run') as executed, contextlib.redirect_stdout(printed):
            guided_setup.run('clpctl', 'site:add:reverse-proxy', '--siteUser=shopops', '--siteUserPassword=Secret-Value-1')
        self.assertNotIn('Secret-Value-1', printed.getvalue())
        self.assertIn('--siteUserPassword=<hidden>\n', printed.getvalue())
        self.assertIn('--siteUser=shopops', printed.getvalue())
        self.assertIn('--siteUserPassword=Secret-Value-1', executed.call_args.args[0])

    def test_package_install_never_prompts_or_restarts_services(self):
        from unittest import mock
        with mock.patch.object(guided_setup, 'quiet', return_value=mock.Mock(returncode=1)), \
                mock.patch.object(guided_setup, 'run') as executed, \
                mock.patch.object(guided_setup.Path, 'exists', return_value=True):
            guided_setup.install_python({})
        apt = executed.call_args_list[0]
        self.assertEqual(apt.args[:2], ('apt-get', 'install'))
        self.assertEqual(apt.kwargs['env']['DEBIAN_FRONTEND'], 'noninteractive')
        self.assertEqual(apt.kwargs['env']['NEEDRESTART_MODE'], 'l')

    def test_changed_checkout_reinstalls_the_shared_runtime(self):
        from unittest import mock
        from companion import package_install
        with mock.patch.object(guided_setup.Path, 'exists', return_value=True), \
                mock.patch.object(guided_setup, 'active', return_value=True):
            with mock.patch.object(package_install, 'require_package', return_value=None):
                self.assertTrue(guided_setup.interface_ready({}))
            with mock.patch.object(package_install, 'require_package', side_effect=ValueError('different')):
                self.assertFalse(guided_setup.interface_ready({}))

    def staging_command(self, receipt, home_exists):
        from unittest import mock
        answers = {'staging_user': 'shopstg'}
        with mock.patch.object(guided_setup, 'private', return_value=receipt), \
                mock.patch.object(guided_setup.Path, 'exists', return_value=home_exists), \
                mock.patch.object(guided_setup.Path, 'mkdir'), \
                mock.patch.object(guided_setup, 'run') as executed:
            guided_setup.provision_staging(answers, Path('/etc/cloudpanel-companion/staging-shopstg.json'))
        return [str(item) for item in executed.call_args.args] if executed.called else None

    def test_interrupted_staging_copy_continues_from_its_phase(self):
        fresh = self.staging_command(None, False)
        self.assertEqual(fresh[:3], ['python3', '-m', 'companion.provision'])
        self.assertFalse([item for item in fresh if item.startswith('--resume')])
        for phase, flag in guided_setup.PROVISION_RESUME.items():
            self.assertEqual(self.staging_command({'phase': phase}, True)[-1], flag)
        self.assertIsNone(self.staging_command({'phase': guided_setup.PROVISION_DONE}, True))
        # A site the operator provisioned by hand (no setup receipt) is left alone.
        self.assertIsNone(self.staging_command(None, True))
        with self.assertRaises(SystemExit):
            self.staging_command({'phase': 'database-imported'}, True)

    def test_resume_flags_exist_in_provisioning(self):
        source = (Path(guided_setup.__file__).parent / 'provision.py').read_text()
        for flag in guided_setup.PROVISION_RESUME.values():
            self.assertIn("'" + flag + "'", source)
        self.assertIn("'" + guided_setup.PROVISION_DONE + "'", source)

    def test_page_cache_is_done_only_once_its_routing_is_live(self):
        import tempfile
        from unittest import mock
        answers = {'site_host': 'shop.example.com'}
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            config, sites, ready = Path(folder, 'config'), Path(folder, 'sites-enabled'), Path(folder, 'ready')
            config.mkdir()
            sites.mkdir()
            ready.mkdir()
            (config / 'cache-sites.json').write_text('{"sites": [{"host": "shop.example.com"}]}')
            routing = config / 'cache-routing-shop.example.com.conf'
            vhost = sites / 'shop.example.com.conf'
            vhost.write_text('server {\n  server_name shop.example.com;\n}\n')
            marker = ready / (hashlib.sha256(b'shop.example.com').hexdigest() + '.ready')
            marker.touch()
            with mock.patch.object(guided_setup, 'CONFIG', config), \
                    mock.patch.object(guided_setup, 'NGINX_SITES', sites), \
                    mock.patch.object(guided_setup, 'CACHE_READY', ready), \
                    mock.patch.object(guided_setup, 'active', return_value=True):
                # Registered and controller running, but the run stopped before the routing.
                from companion import nginx_templates
                self.assertFalse(guided_setup.cache_ready(answers))
                routing.write_text(nginx_templates.cache_routing('shop.example.com', str(marker)))
                (sites / nginx_templates.UPSTREAMS.name).write_text(nginx_templates.cache_upstreams(6081, 8080))
                self.assertFalse(guided_setup.cache_ready(answers))
                vhost.write_text('server {\n  server_name shop.example.com;\n  include ' + str(routing) + ';\n'
                                 + nginx_templates.CACHE_ROUTE + '\n  }\n}\n')
                self.assertTrue(guided_setup.cache_ready(answers))
                # Routing installed before connection reuse: install-cache.py must run again.
                vhost.write_text(vhost.read_text().replace(nginx_templates.CACHE_ROUTE, nginx_templates.PROXY_TO_CACHE))
                self.assertFalse(guided_setup.cache_ready(answers))
                vhost.write_text(vhost.read_text().replace(nginx_templates.PROXY_TO_CACHE, nginx_templates.CACHE_ROUTE))
                routing.write_text('set $companion_cache_backend "127.0.0.1:8080";\n')
                self.assertFalse(guided_setup.cache_ready(answers))
                routing.write_text(nginx_templates.cache_routing('shop.example.com', str(marker)))
                self.assertTrue(guided_setup.cache_ready(answers))
                # The controller has not activated the site's policy (no ready marker).
                marker.unlink()
                self.assertFalse(guided_setup.cache_ready(answers))
                marker.touch()
                with mock.patch.object(guided_setup, 'active', side_effect=lambda unit: unit != 'varnish.service'):
                    self.assertFalse(guided_setup.cache_ready(answers))

    def test_staging_is_done_only_when_registered_with_its_services(self):
        from unittest import mock
        answers = {'site_host': 'shop.example.com', 'staging_user': 'shopstg'}
        item = {'health_file': 'companion-health-x.php', 'source_health_file': 'companion-origin-y.php'}
        with mock.patch.object(guided_setup, 'registered_site', return_value=('shop', item)), \
                mock.patch.object(guided_setup, 'active', return_value=True), \
                mock.patch.object(guided_setup, 'application_check', return_value=False) as check:
            # The website's own HTTPS check belongs to Monitoring, which waits for its certificate.
            self.assertTrue(guided_setup.staging_ready(answers))
            check.assert_not_called()
            # A run that stopped after registering, before its services started.
            with mock.patch.object(guided_setup, 'active', side_effect=lambda unit: unit != 'companion-isolation-shopstg.service'):
                self.assertFalse(guided_setup.staging_ready(answers))
        with mock.patch.object(guided_setup, 'registered_site', return_value=('shop', {'health_file': 'x'})), \
                mock.patch.object(guided_setup, 'active', return_value=True):
            self.assertFalse(guided_setup.staging_ready(answers))
        with mock.patch.object(guided_setup, 'registered_site', return_value=(None, None)):
            self.assertFalse(guided_setup.staging_ready(answers))

    def test_application_check_probes_the_registered_monitoring_target(self):
        import json
        import tempfile
        from unittest import mock
        from companion import health
        url = 'https://shop.example.com/companion-origin-y.php'
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder)
            (config / 'monitor.json').write_text(json.dumps({'targets': [
                {'name': 'shop: origin HTML', 'url': 'https://shop.example.com/'},
                {'name': 'shop: application', 'url': url, 'connect_host': '127.0.0.1'}]}))
            answers = {'site_host': 'shop.example.com'}
            observed = lambda healthy: health.Observation('shop: application', healthy, 'healthy', 200, 5)
            with mock.patch.object(guided_setup, 'CONFIG', config), \
                    mock.patch.object(health, 'probe', return_value=observed(True)) as probe:
                self.assertTrue(guided_setup.application_check(answers, 'companion-origin-y.php'))
                self.assertEqual([call.args[0].url for call in probe.call_args_list], [url])
                probe.return_value = observed(False)
                self.assertFalse(guided_setup.application_check(answers, 'companion-origin-y.php'))
                # Not configured yet (monitoring targets are the installer's last step).
                self.assertFalse(guided_setup.application_check(answers, 'companion-origin-z.php'))

    def test_releases_are_done_only_with_live_routing_and_a_passing_check(self):
        import tempfile
        from unittest import mock
        from companion import registered_deployment
        answers = {'site_host': 'shop.example.com', 'site_user': 'shop'}
        item = {'deploy_health_file': 'companion-release-x.php'}
        with tempfile.TemporaryDirectory() as folder:
            config, sites = Path(folder, 'config'), Path(folder, 'sites-enabled')
            (config / 'sites').mkdir(parents=True)
            sites.mkdir()
            include = config / 'sites' / 'shop-deployment.conf'
            vhost = sites / 'shop.example.com.conf'
            vhost.write_text('server {\n  server_name shop.example.com;\n  include ' + str(include) + ';\n}\n')
            with mock.patch.object(guided_setup, 'CONFIG', config), \
                    mock.patch.object(guided_setup, 'NGINX_SITES', sites), \
                    mock.patch.object(guided_setup, 'registered_site', return_value=('shop', item)), \
                    mock.patch.object(guided_setup, 'active', return_value=True), \
                    mock.patch.object(registered_deployment, 'release_check', return_value=True) as check:
                self.assertFalse(guided_setup.releases_ready(answers))  # include file missing
                include.write_text('set $companion_release_paused 0;\n')
                self.assertTrue(guided_setup.releases_ready(answers))
                check.assert_called_with('shop.example.com', 'companion-release-x.php')
                # install-deployment.py records its check before running it; a failed
                # check (or a failed request) must not count as done.
                check.return_value = False
                self.assertFalse(guided_setup.releases_ready(answers))
                check.side_effect = RuntimeError('curl failed')
                self.assertFalse(guided_setup.releases_ready(answers))

    def test_object_cache_is_done_only_while_its_service_runs(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'object-cache-shop.json').write_text('{}')
            with mock.patch.object(guided_setup, 'CONFIG', Path(folder)), \
                    mock.patch.object(guided_setup, 'active', side_effect=lambda unit: unit == 'companion-redis-shop.service'):
                self.assertTrue(guided_setup.object_cache_ready({'site_user': 'shop'}))
            with mock.patch.object(guided_setup, 'CONFIG', Path(folder)), \
                    mock.patch.object(guided_setup, 'active', return_value=False):
                self.assertFalse(guided_setup.object_cache_ready({'site_user': 'shop'}))

    def test_website_routing_includes_releases_only_with_staging(self):
        import tempfile
        from unittest import mock
        stored = ('server {\n  {{root}}\n  location / {\n    proxy_pass http://127.0.0.1:8080;\n  }\n}\n'
                  'server {\n  {{root}}\n    fastcgi_param PHP_VALUE "{{php_settings}}";\n}\n')
        base = {'site_host': 'shop.example.com', 'site_user': 'shop'}
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(guided_setup, 'CONFIG', Path(folder)), \
                mock.patch.object(guided_setup, 'panel_site', return_value={'vhost': stored}):
            _, wanted = guided_setup.site_vhost({**base, 'page_cache': 'yes', 'staging': 'no'})
            self.assertIn('cache-routing-shop.example.com.conf', wanted)
            self.assertNotIn('shop-deployment.conf', wanted)
            _, wanted = guided_setup.site_vhost({**base, 'page_cache': 'yes', 'staging': 'yes'})
            self.assertIn('shop-deployment.conf', wanted)
            # Releases without the page cache still need their routing saved.
            _, wanted = guided_setup.site_vhost({**base, 'page_cache': 'no', 'staging': 'yes'})
            self.assertIn('shop-deployment.conf', wanted)
            self.assertNotIn('cache-routing-', wanted)
            self.assertEqual(guided_setup.site_vhost({**base, 'page_cache': 'no', 'staging': 'no'}), (True, None))
            applies = dict((title, applies) for title, applies, *_ in guided_setup.STEPS)['Website routing in CloudPanel']
            self.assertTrue(applies({**base, 'page_cache': 'no', 'staging': 'yes'}))
            self.assertFalse(applies({**base, 'page_cache': 'no', 'staging': 'no'}))
            # Monitoring's request log joins the public block once monitoring wrote its include.
            self.assertNotIn('telemetry-public.conf', guided_setup.site_vhost({**base, 'page_cache': 'yes', 'staging': 'yes'})[1])
            (Path(folder) / 'telemetry-public.conf').write_text('access_log off;\n')
            _, wanted = guided_setup.site_vhost({**base, 'page_cache': 'yes', 'staging': 'yes'})
            public, backend = wanted.split('}\nserver {', 1)
            self.assertEqual(public.count('include /etc/cloudpanel-companion/telemetry-public.conf;'), 1)
            self.assertNotIn('telemetry-public.conf', backend)
            from companion.nginx_templates import integration
            self.assertEqual(integration(wanted, 'shop', 'shop.example.com', cache=True, releases=True, telemetry=True), wanted)
            self.assertNotIn('telemetry-public.conf', integration(wanted, 'shop', 'shop.example.com', telemetry=False))

    def test_interface_site_never_routes_to_an_unowned_upstream(self):
        import tempfile
        from unittest import mock
        from test_nginx_templates import OPS_GENERATED, OPS_SAVED
        root = Path(guided_setup.__file__).resolve().parents[1]
        socket = guided_setup.INTERFACE_UPSTREAM.removeprefix('http://unix:')
        # The upstream is the interface's own socket, which only its service account creates.
        self.assertIn('--bind unix:' + socket + ' ', (root / 'assets/companion-web.service').read_text())
        self.assertIn('proxy_pass ' + guided_setup.INTERFACE_UPSTREAM + ';', (root / 'assets/companion-web-proxy.conf').read_text())
        self.assertNotIn('127.0.0.1:18950', Path(guided_setup.__file__).read_text())
        events = []
        with tempfile.TemporaryDirectory() as folder:
            sites = Path(folder)
            generated = sites / 'ops.example.com.conf'
            def execute(*arguments, **kwargs):
                events.append(arguments)
                if arguments[:2] == ('clpctl', 'site:add:reverse-proxy'):
                    generated.write_text(OPS_GENERATED)
                elif arguments[:2] == ('clpctl', 'lets-encrypt:install:certificate'):
                    events.append(('routing at certificate time', generated.read_text()))
            with mock.patch.object(guided_setup, 'NGINX_SITES', sites), \
                    mock.patch.object(guided_setup, 'panel_site', return_value=None), \
                    mock.patch.object(guided_setup, 'run', side_effect=execute), \
                    mock.patch.object(guided_setup, 'quiet', return_value=mock.Mock(returncode=0)):
                guided_setup.create_ops_site({'ops_host': 'ops.example.com', 'site_user': 'shop'})
                self.assertEqual(generated.read_text(), OPS_SAVED)
        self.assertIn('--reverseProxyUrl=' + guided_setup.INTERFACE_UPSTREAM, events[0])
        self.assertIn(('systemctl', 'reload', 'nginx'), events)
        self.assertIn(('routing at certificate time', OPS_SAVED), events)

    def test_interface_routing_is_restored_when_nginx_rejects_it(self):
        import tempfile
        from unittest import mock
        from test_nginx_templates import OPS_GENERATED
        with tempfile.TemporaryDirectory() as folder:
            generated = Path(folder) / 'ops.example.com.conf'
            generated.write_text(OPS_GENERATED)
            with mock.patch.object(guided_setup, 'NGINX_SITES', Path(folder)), \
                    mock.patch.object(guided_setup, 'run') as executed, \
                    mock.patch.object(guided_setup, 'quiet', return_value=mock.Mock(returncode=1)):
                with self.assertRaises(SystemExit):
                    guided_setup.route_interface({'ops_host': 'ops.example.com'})
            self.assertEqual(generated.read_text(), OPS_GENERATED)
            executed.assert_not_called()

    def test_staging_paste_appears_once_its_security_file_exists(self):
        import tempfile
        from unittest import mock
        answers = {'staging_user': 'shopstg', 'staging_host': 'stg.example.com'}
        stored = ('server {\n  {{root}}\n  include /etc/cloudpanel-companion/sites/shopstg-access.conf;\n'
                  '  location / {\n    proxy_pass http://127.0.0.1:8080;\n  }\n}\nserver {\n  {{root}}\n'
                  '  include /etc/cloudpanel-companion/sites/shopstg-access.conf;\n'
                  '    fastcgi_param PHP_VALUE "{{php_settings}}";\n}\n')
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder)
            (config / 'sites').mkdir()
            with mock.patch.object(guided_setup, 'CONFIG', config), \
                    mock.patch.object(guided_setup, 'panel_site', return_value={'vhost': stored}):
                self.assertEqual(guided_setup.staging_vhost(answers), (True, None))
                (config / 'sites' / 'shopstg-security.conf').write_text('# safeguards\n')
                done, wanted = guided_setup.staging_vhost(answers)
        self.assertFalse(done)
        self.assertEqual(wanted.count('include /etc/cloudpanel-companion/sites/shopstg-security.conf;'), 2)
        self.assertEqual(wanted.count('include /etc/cloudpanel-companion/sites/shopstg-access.conf;'), 2)
        self.assertNotIn('cache-routing', wanted)

    def test_self_signed_staging_certificate_is_replaced(self):
        import sqlite3
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'db.sq3'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE site (domain_name, type, user, vhost_template, certificate_id)')
                db.execute('CREATE TABLE certificate (id, type)')
                db.execute("INSERT INTO site VALUES ('stg.example.com', 'php', 'shopstg', '', 5)")
                db.execute("INSERT INTO site VALUES ('ops.example.com', 'reverse-proxy', 'shopops', '', 6)")
                db.executemany('INSERT INTO certificate VALUES (?, ?)', [(5, '1'), (6, '2')])  # CloudPanel stores text
            with mock.patch.object(guided_setup, 'PANEL_DB', 'file:' + str(path) + '?mode=ro'):
                # A new CloudPanel site only has its self-signed default certificate.
                self.assertFalse(guided_setup.trusted_certificate('stg.example.com'))
                self.assertTrue(guided_setup.trusted_certificate('ops.example.com'))
                self.assertTrue(guided_setup.ops_site_ready({'ops_host': 'ops.example.com'}))
                self.assertFalse(guided_setup.trusted_certificate('missing.example.com'))
        titles = [title for title, *_ in guided_setup.STEPS]
        self.assertEqual(titles.index('HTTPS certificate for staging'), titles.index('Staging copy and controls') + 1)

    def test_answers_are_validated(self):
        patterns = {key: pattern for key, _, pattern in guided_setup.QUESTIONS}
        import re
        self.assertTrue(re.fullmatch(patterns['site_host'], 'shop.example.com'))
        self.assertFalse(re.fullmatch(patterns['site_host'], 'https://shop.example.com'))
        self.assertFalse(re.fullmatch(patterns['php'], '7.4'))


if __name__ == '__main__':
    unittest.main()
