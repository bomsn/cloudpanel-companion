"""Django tests run separately with the pinned web dependencies installed."""
import json
import re
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from allauth.mfa.models import Authenticator
from allauth.account.models import EmailAddress
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret, hotp_value, format_hotp_value


class WebBoundaryTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.operator = get_user_model().objects.create_user('operator', password='Long-test-password-123', is_staff=True)
        self.secure = {'secure': True, 'HTTP_HOST': 'ops.example.com'}

    def test_anonymous_cannot_read_dashboard(self):
        response = self.client.get('/', **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)

    def test_sign_in_has_self_only_content_policy_without_inline_exceptions(self):
        response = self.client.get('/accounts/login/', **self.secure)
        policy = response['Content-Security-Policy']
        self.assertIn("script-src 'self'", policy)
        self.assertIn("form-action 'self'", policy)
        self.assertIn("object-src 'none'", policy)
        self.assertNotIn('unsafe-inline', policy)
        self.assertNotIn('unsafe-eval', policy)

    def test_no_passkey_login_or_registration_routes(self):
        response = self.client.get('/accounts/login/', **self.secure)
        self.assertNotContains(response, 'passkey')
        self.assertNotContains(response, 'webauthn')
        self.assertEqual(self.client.get('/accounts/2fa/webauthn/', **self.secure).status_code, 404)

    def test_no_email_reset_or_address_pages(self):
        self.client.force_login(self.operator)
        for path in ('/accounts/password/reset/', '/accounts/password/reset/done/', '/accounts/email/'):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path, **self.secure).status_code, 404)

    def test_monitoring_is_private_and_absent_history_is_honest(self):
        self.assertEqual(self.client.get('/monitoring/', **self.secure).status_code, 302)
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG={'history_path': str(Path(folder) / 'absent.json'),
                                                                                    'site_url': 'https://shop.example.com'}):
            response = self.client.get('/monitoring/', **self.secure)
        self.assertContains(response, 'No monitoring history yet')
        self.assertEqual(response['Cache-Control'], 'private, no-store')

    def test_password_access_json_requires_confirmation_and_csrf(self):
        self.client.force_login(self.operator)
        response = self.client.post('/staging/change/', {'operation': 'protection', 'enabled': 'false'},
                                    HTTP_ACCEPT='application/json', **self.secure)
        self.assertEqual(response.status_code, 403)
        self.assertIn('reauthenticate', response.json())

    def test_disabled_external_fields_preserve_saved_allowlist(self):
        self.client.force_login(self.operator)
        from companion.relay import default_policy
        policy = default_policy()
        policy['mail_recipients'] = ['approved@example.com']
        status = {'external': policy, 'protected_hosts': ['live.example.com'], 'relay_configured': True}
        with patch('companion_web.views.did_recently_reauthenticate', return_value=True), \
                patch('companion_web.operations_client.call', side_effect=[status, {'saved': True}]) as call:
            response = self.client.post('/staging/external/change/', {'mail_recipients': 'invalid hidden value'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(call.call_args.kwargs['policy']['mail_recipients'], ['approved@example.com'])
        self.assertFalse(call.call_args.kwargs['policy']['mail_enabled'])

    def test_anonymous_cannot_read_or_change_staging(self):
        for method, path in [('get', '/staging/'), ('post', '/staging/change/'),
                             ('get', '/staging/external/'), ('post', '/staging/external/change/'), ('get', '/staging/inbox/'),
                             ('get', '/staging/releases/'), ('post', '/staging/releases/change/')]:
            response = getattr(self.client, method)(path, **self.secure)
            self.assertEqual(response.status_code, 302)
            self.assertIn('/accounts/login/', response.url)

    def test_anonymous_cannot_start_or_read_code_comparisons(self):
        for method, path in [('get', '/staging/status/'), ('get', '/staging/releases/status/'), ('get', '/staging/releases/files/'),
                             ('post', '/staging/releases/check/')]:
            response = getattr(self.client, method)(path, **self.secure)
            self.assertEqual(response.status_code, 302)

    def test_comparison_start_needs_csrf_and_get_never_starts_a_job(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        self.assertEqual(client.post('/staging/releases/check/', **self.secure).status_code, 403)
        self.assertEqual(client.get('/staging/releases/check/', **self.secure).status_code, 405)

    def test_compared_code_is_data_and_never_executable_markup(self):
        self.client.force_login(self.operator)
        with patch('companion_web.operations_client.call', return_value={'comparison': {'folders': [{'label': '<script>bad</script>'}]}, 'job': None}):
            response = self.client.get('/staging/releases/status/', **self.secure)
        self.assertEqual(response['Cache-Control'], 'private, no-store')
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertEqual(response.json()['comparison']['folders'][0]['label'], '<script>bad</script>')

    def test_release_history_summaries_do_not_require_embedded_file_details(self):
        self.client.force_login(self.operator)
        record = {'created_at': int(time.time()), 'expires_at': int(time.time()) + 600, 'phase': 'preview',
                  'actor': 'operator', 'changed_count': 2, 'file_count': 2, 'token': 'a' * 32}
        with patch('companion_web.operations_client.call', return_value={'releases': [record], 'job': None}):
            response = self.client.get('/staging/releases/', **self.secure)
        self.assertContains(response, 'Changes in staging')
        self.assertContains(response, 'Ready to review')

    def test_staging_mutations_require_csrf_even_for_an_operator(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        response = client.post('/staging/change/', {'operation': 'pause', 'enabled': 'true'}, **self.secure)
        self.assertEqual(response.status_code, 403)

    def test_sensitive_change_requires_confirmation_without_storing_new_password(self):
        self.client.force_login(self.operator)
        response = self.client.post('/staging/change/', {'operation': 'password', 'password': 'new-staging-secret-123'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/reauthenticate/', response.url)
        self.assertNotIn('account_reauthentication_state', self.client.session)
        self.assertNotIn('new-staging-secret-123', str(dict(self.client.session)))

    def test_code_release_requires_recent_confirmation(self):
        self.client.force_login(self.operator)
        for operation in ('release_apply', 'release_recover'):
            response = self.client.post('/staging/releases/change/', {'operation': operation,
                'token': 'a' * 32, 'confirmed': 'yes'}, **self.secure)
            self.assertEqual(response.status_code, 302)
            self.assertIn('/accounts/reauthenticate/', response.url)
            self.assertNotIn('account_reauthentication_state', self.client.session)

    def test_code_release_post_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        response = client.post('/staging/releases/change/', {'operation': 'release_preview',
            'files': 'wp-content/themes/example/style.css'}, **self.secure)
        self.assertEqual(response.status_code, 403)

    def test_code_release_without_runner_is_honestly_unavailable(self):
        self.client.force_login(self.operator)
        self.assertContains(self.client.get('/staging/releases/', **self.secure), 'Code releases are unavailable')

    def test_public_registration_closed(self):
        response = self.client.get('/accounts/signup/', **self.secure)
        self.assertContains(response, 'closed')

    def test_two_factor_is_optional_for_operators(self):
        # Requirement changed: like CloudPanel, operators may sign in with a
        # password alone; enrolling an authenticator is their choice.
        response = self.client.post('/accounts/login/', {
            'login': 'operator', 'password': 'Long-test-password-123'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(str(self.operator.pk), self.client.session['_auth_user_id'])
        config = {'snapshot_path': '/nonexistent/snapshot.json', 'panel_url': 'https://panel.example.com',
                  'site_url': 'https://site.example.com', 'site_name': 'Shop'}
        with override_settings(CONFIG=config):
            response = self.client.get('/', **self.secure)
        self.assertEqual(response.status_code, 200)
        security = self.client.get('/accounts/2fa/', **self.secure)
        self.assertContains(security, 'Enable two-factor authentication')
        self.assertContains(security, 'href="/accounts/2fa/totp/activate/"')

    def test_operator_can_enable_two_factor_after_confirming_access(self):
        self.client.force_login(self.operator)
        response = self.client.get('/accounts/2fa/totp/activate/', **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/reauthenticate/', response.url)
        self.client.post('/accounts/reauthenticate/', {'password': 'Long-test-password-123'}, **self.secure)
        page = self.client.get('/accounts/2fa/totp/activate/', **self.secure)
        self.assertContains(page, 'Connect your authenticator app')
        secret = page.content.decode().split('id="authenticator_secret">', 1)[1].split('<', 1)[0]
        code = format_hotp_value(hotp_value(secret, int(time.time()) // 30))
        response = self.client.post('/accounts/2fa/totp/activate/', {'code': code}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Authenticator.objects.filter(user=self.operator, type='totp').exists())
        self.assertContains(self.client.get('/accounts/2fa/', **self.secure), 'Disable two-factor authentication')

    def test_disabling_two_factor_requires_confirmed_access(self):
        TOTP.activate(self.operator, generate_totp_secret())
        self.client.force_login(self.operator)
        response = self.client.get('/accounts/2fa/totp/deactivate/', **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('reauthenticate', response.url)
        response = self.client.post('/accounts/2fa/totp/deactivate/', **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('reauthenticate', response.url)
        self.assertTrue(Authenticator.objects.filter(user=self.operator, type='totp').exists())

    def test_enrolled_operator_may_confirm_access_with_a_code(self):
        TOTP.activate(self.operator, generate_totp_secret())
        self.client.force_login(self.operator)
        response = self.client.get('/accounts/reauthenticate/?next=/staging/', **self.secure)
        self.assertContains(response, '/accounts/2fa/reauthenticate/')

    def test_non_operator_is_denied(self):
        user = get_user_model().objects.create_user('visitor', password='Long-test-password-123')
        self.client.force_login(user)
        self.assertEqual(self.client.get('/', **self.secure).status_code, 403)
        self.assertEqual(self.client.get('/accounts/2fa/', **self.secure).status_code, 403)
        # The denial page offers sign-out, which must work for that account.
        self.client.post('/accounts/logout/', **self.secure)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_dashboard_requires_fresh_real_observations(self):
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'snapshot.json'
            config = {'snapshot_path': str(path), 'panel_url': 'https://panel.example.com',
                      'site_url': 'https://site.example.com', 'site_name': '<script>unsafe</script>'}
            with override_settings(CONFIG=config):
                response = self.client.get('/', **self.secure)
                self.assertContains(response, 'Server checks have not reported recently')
                self.assertNotContains(response, '<script>unsafe</script>')
                path.write_text(json.dumps({'observed_at': time.time(), 'checks': [
                    {'name': 'Homepage', 'healthy': True, 'category': 'http', 'status': 200, 'certificate_days': 30}]}))
                response = self.client.get('/', **self.secure)
                self.assertContains(response, '30 days remaining')
                self.assertContains(response, 'Responding')
                self.assertEqual(response['Cache-Control'], 'private, no-store')
                self.assertEqual(response['X-Frame-Options'], 'DENY')
                path.write_text(json.dumps({'observed_at': time.time() - 300, 'checks': []}))
                self.assertContains(self.client.get('/', **self.secure), 'Server checks have not reported recently')

    def test_overview_lists_services_and_missed_backups(self):
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder:
            system = Path(folder) / 'system.json'
            config = {'snapshot_path': str(Path(folder) / 'snapshot.json'), 'system_snapshot_path': str(system),
                      'panel_url': 'https://panel.example.com', 'site_url': 'https://site.example.com', 'site_name': 'Shop'}
            with override_settings(CONFIG=config):
                system.write_text(json.dumps({'observed_at': time.time(), 'backup_grace': 10800, 'services': [
                    {'unit': 'nginx.service', 'name': 'Shop: Nginx', 'state': 'active', 'healthy': True, 'since': 1000,
                     'recovery_enabled': True, 'attempted_recovery': False}], 'backups': []}))
                response = self.client.get('/', **self.secure)
                # Each service row has its product mark and links to its group on Monitoring.
                self.assertContains(response, '<a class="service-name" href="/monitoring/#services-web">')
                self.assertRegex(response.content.decode(), r'#nginx"></use></svg>\s*<span>NGINX</span></a>')
                self.assertNotContains(response, 'Shop: Nginx')
                self.assertContains(response, 'Running')
                self.assertContains(response, 'No scheduled backups found')
                system.write_text(json.dumps({'observed_at': time.time(), 'backup_grace': 10800, 'services': [], 'backups': [
                    {'name': 'Backup: shop.example.com full, daily 03:00', 'job': 'a', 'healthy': False, 'state': 'missed',
                     'last_success': 1793502000, 'due_at': 1793588400},
                    {'name': 'Backup: shop.example.com database, daily 04:00', 'job': 'b', 'healthy': True,
                     'state': 'succeeded', 'last_success': 1793592000, 'due_at': 1793592000}]}))
                response = self.client.get('/', **self.secure)
                self.assertContains(response, '1 scheduled backup did not succeed in time')
                self.assertContains(response, 'Backup: shop.example.com full, daily 03:00')
                self.assertContains(response, 'Missed')
                self.assertContains(response, 'Succeeded')
                self.assertContains(response, 'within 3 hours')
        # Without a configured path (installers never wrote one) the interface reads
        # the system watch's fixed export, so services and backups are not blank.
        from companion_web import views
        unit = (Path(views.__file__).resolve().parents[1] / 'assets/companion-system-watch.service').read_text()
        self.assertIn('--output ' + str(views.SYSTEM_SNAPSHOT) + '\n', unit)

    def test_logout_requires_post_and_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        self.assertEqual(client.post('/accounts/logout/', **self.secure).status_code, 403)

    def test_host_and_https_are_enforced(self):
        self.assertEqual(self.client.get('/', secure=True, HTTP_HOST='attacker.example').status_code, 400)
        self.assertEqual(self.client.get('/', HTTP_HOST='ops.example.com').status_code, 301)

    def test_actual_password_login_waits_for_second_factor(self):
        secret = generate_totp_secret()
        TOTP.activate(self.operator, secret)
        EmailAddress.objects.create(user=self.operator, email='operator@example.com', verified=True, primary=True)
        response = self.client.post('/accounts/login/', {
            'login': 'operator', 'password': 'Long-test-password-123'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/2fa/authenticate/', response.url)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertNotEqual(self.client.get('/', **self.secure).status_code, 200)
        code = format_hotp_value(hotp_value(secret, int(time.time()) // 30))
        response = self.client.post('/accounts/2fa/authenticate/', {'code': code}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(str(self.operator.pk), self.client.session['_auth_user_id'])
        self.assertEqual(self.client.get('/', **self.secure).status_code, 200)

    def test_invalid_second_factor_does_not_authenticate(self):
        TOTP.activate(self.operator, generate_totp_secret())
        self.client.post('/accounts/login/', {
            'login': 'operator', 'password': 'Long-test-password-123'}, **self.secure)
        response = self.client.post('/accounts/2fa/authenticate/', {'code': 'not-a-code'}, **self.secure)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_unix_socket_frontend_uses_overwritten_peer_header(self):
        from allauth.account.adapter import get_adapter
        from django.test import RequestFactory
        request = RequestFactory().get('/', REMOTE_ADDR='', HTTP_X_FORWARDED_FOR='192.0.2.25')
        self.assertEqual(get_adapter().get_client_ip(request), '192.0.2.25')

    def test_concurrent_code_validation_accepts_only_once(self):
        from concurrent.futures import ThreadPoolExecutor
        secret = generate_totp_secret()
        factor = TOTP.activate(self.operator, secret)
        code = format_hotp_value(hotp_value(secret, int(time.time()) // 30))
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(lambda _: factor.validate_code(code), range(8)))
        self.assertEqual(sum(results), 1)

    def test_external_enabling_requires_recent_confirmation(self):
        self.client.force_login(self.operator)
        response = self.client.post('/staging/external/change/', {'http_enabled': 'yes', 'http_rules': 'GET https://example.com/test'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/reauthenticate/', response.url)
        self.assertNotIn('account_reauthentication_state', self.client.session)

    def test_emergency_external_stop_needs_no_reconfirmation(self):
        self.client.force_login(self.operator)
        with patch('companion_web.operations_client.call', return_value={'saved': True}) as call:
            response = self.client.post('/staging/external/change/', {'operation': 'external_stop'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/staging/external/')
        call.assert_called_once_with('external_stop', actor='operator')

    def test_external_mutation_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        response = client.post('/staging/external/change/', {'operation': 'external_stop'}, **self.secure)
        self.assertEqual(response.status_code, 403)

    def test_invalid_external_destination_keeps_the_operator_input(self):
        self.client.force_login(self.operator)
        status = {'external': {}, 'protected_hosts': ['live.example.com'], 'relay_configured': True}
        with patch('companion_web.views.did_recently_reauthenticate', return_value=True), \
                patch('companion_web.operations_client.call', return_value=status) as call:
            response = self.client.post('/staging/external/change/', {'http_enabled': 'yes',
                'http_rules': 'GET http://example.com/test', 'mail_recipients': '<script>unsafe</script>'}, **self.secure)
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, 'GET http://example.com/test', status_code=400)
        self.assertContains(response, '&lt;script&gt;unsafe&lt;/script&gt;', status_code=400)
        self.assertNotContains(response, '<script>unsafe</script>', status_code=400)
        call.assert_called_once_with('status')

    def test_destination_without_a_method_is_explained(self):
        self.client.force_login(self.operator)
        status = {'external': {}, 'protected_hosts': ['live.example.com'], 'relay_configured': True}
        with patch('companion_web.views.did_recently_reauthenticate', return_value=True),                 patch('companion_web.operations_client.call', return_value=status):
            response = self.client.post('/staging/external/change/', {'http_enabled': 'yes',
                'http_rules': 'https://example.com/test'}, **self.secure)
        self.assertContains(response, 'List each destination as a method and an HTTPS URL', status_code=400)

    def test_file_check_progress_is_labelled_by_the_server(self):
        self.client.force_login(self.operator)
        job = {'operation': 'compare', 'running': True, 'failed': False, 'blocked': False, 'phase': 'scanning-staging'}
        with patch('companion_web.operations_client.call', return_value={'comparison': None, 'job': job}):
            response = self.client.get('/staging/releases/status/', **self.secure)
        self.assertEqual(response.json()['label'], 'Checking staging files')

    def test_account_pages_use_sentence_case_and_labelled_session_rows(self):
        # A real sign-in, so allauth records the browser session that is listed.
        self.client.post('/accounts/login/', {'login': 'operator', 'password': 'Long-test-password-123'}, **self.secure)
        password = self.client.get('/accounts/password/change/', **self.secure)
        self.assertContains(password, 'Change password')
        self.assertContains(password, 'Current password')
        self.assertNotContains(password, 'Change Password')
        sessions = self.client.get('/accounts/sessions/', **self.secure)
        self.assertContains(sessions, 'class="table responsive"')
        self.assertContains(sessions, 'data-label="IP address"')
        self.assertContains(sessions, 'This browser')
        self.assertNotContains(sessions, 'Sign Out')

    def test_captured_email_is_escaped_in_the_authenticated_inbox(self):
        self.client.force_login(self.operator)
        message = {'id': '12345678900-' + 'a' * 16, 'recipients': ['test@example.com'],
                   'subject': '<script>subject</script>', 'body': '<script>body</script>'}
        with patch('companion_web.operations_client.call', side_effect=[{'messages': [message]}, message]):
            response = self.client.get('/staging/inbox/?message=' + message['id'], **self.secure)
        self.assertContains(response, '&lt;script&gt;body&lt;/script&gt;')
        self.assertNotContains(response, '<script>body</script>')
        self.assertNotContains(response, '<script>subject</script>')
        self.assertEqual(response['Cache-Control'], 'private, no-store')


def monitoring_exports(folder, now):
    """Endpoint, service and history exports in the collectors' shapes, with states needing attention."""
    import sqlite3
    from companion.telemetry import export, request_groups
    folder = Path(folder)
    (folder / 'snapshot.json').write_text(json.dumps({'observed_at': now, 'resources': {
        'cpus': 4, 'load': [0.4, 0.3, 0.2], 'memory_total': 8 * 1024 ** 3, 'memory_available': 5 * 1024 ** 3,
        'swap_used': 0, 'disk_total': 80 * 1024 ** 3, 'disk_free': 30 * 1024 ** 3}, 'checks': [
        {'name': 'shop.example.com: page HTML', 'host': 'shop.example.com', 'healthy': True, 'category': 'healthy',
         'status': 200, 'elapsed_ms': 95, 'certificate_days': 70},
        {'name': 'panel.example.com: certificate', 'host': 'panel.example.com', 'healthy': True,
         'category': 'certificate-expiring', 'status': None, 'elapsed_ms': 9, 'certificate_days': 12}]}))
    (folder / 'system.json').write_text(json.dumps({'observed_at': now, 'backup_grace': 10800, 'backups': [], 'services': [
        {'unit': 'nginx.service', 'name': 'Shop: Nginx', 'state': 'active', 'healthy': True, 'since': now - 86400,
         'recovery_enabled': True, 'attempted_recovery': False},
        {'unit': 'varnish.service', 'name': 'Shop: Page cache', 'state': 'failed', 'healthy': False, 'since': now - 300,
         'recovery_enabled': False, 'attempted_recovery': False},
        {'unit': 'companion-redis-shop.service', 'name': 'Shop: Website object cache', 'state': 'active', 'healthy': True,
         'since': now - 86400, 'recovery_enabled': True, 'attempted_recovery': False},
        {'unit': 'companion-web.service', 'name': 'Shop: Companion interface', 'state': 'active', 'healthy': True,
         'since': now - 86400, 'recovery_enabled': True, 'attempted_recovery': False}], 'scheduled': [
        {'unit': 'companion-telemetry.timer', 'service': 'companion-telemetry.service', 'name': 'Scheduled job: Performance history',
         'enabled': True, 'scheduled': True, 'running': False, 'last_run': now - 40, 'result': 'exit-code',
         'next_run': now + 20, 'healthy': False}],
        'mail': {'available': True, 'count': 18, 'complete': True, 'oldest_at': now - 4 * 86400, 'stuck': True, 'stuck_after': 3600}}))
    rows = [json.dumps({'route': 'product', 'status': 200, 'cache': cache, 'upstream': upstream})
            for cache, upstream in [('HIT', '0.002'), ('HIT', '0.002'), ('MISS', '0.400'), ('BYPASS', '1.200')]]
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE samples(at INTEGER PRIMARY KEY,payload TEXT NOT NULL)')
        db.executemany('INSERT INTO samples VALUES(?,?)', [
            (at, json.dumps({'cpu': 20, 'memory': 40, 'disk_free': 30 * 1024 ** 3 - (at - now + 604800) * 4000,
                             'requests': request_groups(rows)[0]})) for at in range(now - 604800, now + 1, 600)])
        history = export(db, now)
    history['wordpress'] = {'checked_at': now - 600, 'available': True, 'core': {'version': '6.8.1', 'update': None},
                            'plugins': [{'name': 'Example Forms Pro', 'version': '2.1', 'update': '3.2', 'package': False},
                                        {'name': 'Example Shop', 'version': '10.2', 'update': '10.3', 'package': True}],
                            'themes': [], 'updates_checked': now - 7200, 'cron': {'overdue': 0, 'oldest': None, 'hooks': []}}
    (folder / 'history.json').write_text(json.dumps(history))
    return {'snapshot_path': str(folder / 'snapshot.json'), 'system_snapshot_path': str(folder / 'system.json'),
            'history_path': str(folder / 'history.json'), 'panel_url': 'https://panel.example.com',
            'site_url': 'https://shop.example.com', 'site_name': 'Shop'}


class MonitoringPageTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.operator = get_user_model().objects.create_user('operator', password='Long-test-password-123', is_staff=True)
        self.secure = {'secure': True, 'HTTP_HOST': 'ops.example.com'}
        self.client.force_login(self.operator)

    def test_overview_groups_endpoints_by_domain_and_lists_what_needs_attention(self):
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=monitoring_exports(folder, int(time.time()))):
            response = self.client.get('/', **self.secure)
        self.assertContains(response, '<tr class="group-row" id="endpoint-shop.example.com"><th colspan="4" scope="rowgroup">')
        self.assertContains(response, 'shop.example.com<small>Website</small></th>')
        self.assertContains(response, '<td>Page HTML</td>', html=True)
        self.assertNotContains(response, 'shop.example.com: page HTML')
        self.assertContains(response, 'Expires soon')
        for text in ('Varnish Cache: failed.', 'Scheduled job &quot;Performance history&quot;: failed.',
                     'Mail is stuck: 18 messages waiting.', 'The panel.example.com certificate expires in 12 days.',
                     '1 update cannot install', 'Full around'):
            self.assertContains(response, text)
        self.assertContains(response, 'href="/monitoring/#mail-title"')
        # A failed service links to its own group, a certificate to its domain's checks.
        self.assertContains(response, 'href="/monitoring/#services-cache"')
        self.assertContains(response, 'href="#endpoint-panel.example.com"')
        # The Overview groups services like Monitoring: the website's own first, then the server's by kind.
        listed = response.content.decode().split('id="services-title"', 1)[1].split('id="backups-title"', 1)[0]
        headings = [re.search(rf'#{icon}"></use></svg>\s*{re.escape(title)}</th>', listed)
                    for icon, title in (('globe', 'shop.example.com<small>Website</small>'), ('server', 'Web server and PHP'),
                                        ('zap', 'Caches'), ('layers', 'Companion services'), ('timer', 'Scheduled jobs'))]
        self.assertTrue(all(headings))
        self.assertEqual([match.start() for match in headings], sorted(match.start() for match in headings))
        for icon, name in (('redis', 'Redis'), ('nginx', 'NGINX'), ('zap', 'Varnish Cache'), ('layout-dashboard', 'Web interface'),
                           ('timer', 'Performance history')):
            self.assertRegex(listed, rf'#{icon}"></use></svg>\s*<span>{name}</span></a>')
        self.assertNotContains(response, 'Shop: ')
        # The count is the rendered list's length; available updates stay out of the alarm.
        alert = response.content.decode().split('<div class="alert alert-danger" role="alert">', 1)[1].split('</div></div>', 1)[0]
        self.assertIn('<strong>5 things need attention</strong>', alert)
        self.assertEqual(alert.count('<li>'), 5)
        self.assertNotIn('update available', alert)
        notes = response.content.decode().split('<div class="notes"><span>Also worth a look</span><ul>', 1)[1].split('</ul></div>', 1)[0]
        self.assertEqual(notes.count('<li>'), 1)
        self.assertIn('<a href="/monitoring/#wordpress-updates">', notes)
        self.assertIn('1 WordPress update available.</a></li>', notes)

    def test_monitoring_explains_services_jobs_mail_and_page_types_plainly(self):
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=monitoring_exports(folder, int(time.time()))):
            response = self.client.get('/monitoring/', **self.secure)
        for text in ('Receives every visitor request and serves the websites.', 'Varnish Cache', 'Performance history',
                     'Records server and request history every minute', 'Mail is stuck', '18', 'Licence or download missing',
                     'Example Forms Pro', 'Typical response', 'Slowest 5%', 'Served from cache', 'Average', 'Peak',
                     'Estimated full', 'Around '):
            self.assertContains(response, text)
        # One row per page type, half its requests from cache, and no estimate jargon or raw interval table.
        self.assertContains(response, '<rect class="meter-fill" width="50" height="6"/>', html=True)
        # Each service group is an anchor the Overview links to.
        self.assertContains(response, '<tbody id="services-cache">')
        self.assertContains(response, '<tbody id="services-site">')
        self.assertRegex(response.content.decode(), r'#redis"></use></svg>\s*<span>Redis<small>')
        self.assertNotContains(response, 'Shop: ')
        self.assertContains(response, 'id="scheduled-jobs"')
        for gone in ('p95', 'Measured chart values', 'HIT</span>', 'Automatic recovery applies only'):
            self.assertNotContains(response, gone)

    def test_opcache_waste_and_the_last_upkeep_are_shown(self):
        now = int(time.time())
        with tempfile.TemporaryDirectory() as folder:
            config = monitoring_exports(folder, now)
            history = json.loads(Path(config['history_path']).read_text())
            history['latest'] = {**(history['latest'] or {}), 'opcache_free': 40 * 1024 ** 2, 'opcache_wasted': 211 * 1024 ** 2,
                                 'opcache_wasted_percent': 27.47, 'opcache_full': False, 'opcache_scripts': 14570, 'opcache_restarts': 0}
            Path(config['history_path']).write_text(json.dumps(history))
            record = Path(folder) / 'opcache-upkeep.json'
            record.write_text(json.dumps({'checked_at': now - 3600, 'action': 'reloaded', 'last_reload': now - 3600,
                                          'opcache_wasted_percent': 27.47, 'waste_limit': 10}))
            with override_settings(CONFIG={**config, 'upkeep_path': str(record)}):
                response = self.client.get('/monitoring/', **self.secure)
            for text in ('OPcache wasted', '27.5%', '211.0\xa0MB held by replaced scripts', 'OPcache scripts', '14,570',
                         'PHP-FPM reloaded', 'at 27.5% wasted', 'Last reload'):
                self.assertContains(response, text)
            with override_settings(CONFIG=config):
                self.assertContains(self.client.get('/monitoring/', **self.secure), 'Not run yet')

    def test_locked_staging_controls_are_masked_with_one_unlock_action(self):
        status = {'host': 'stg.example.com', 'source_host': 'shop.example.com', 'paused': False, 'protected': True, 'job': None}
        with patch('companion_web.operations_client.call', return_value=status):
            locked = self.client.get('/staging/', **self.secure)
            with patch('companion_web.views.did_recently_reauthenticate', return_value=True):
                unlocked = self.client.get('/staging/', **self.secure)
            status['protected'] = False
            public = self.client.get('/staging/', **self.secure)
            # A stuck workflow disables the controls; confirming access would not make them usable.
            status['job'] = {'operation': 'refresh', 'running': False, 'failed': True, 'blocked': True, 'phase': 'recovery-needs-review'}
            blocked = self.client.get('/staging/', **self.secure)
        self.assertNotContains(locked, 'Protected changes are locked')
        self.assertEqual(locked.content.decode().count(' inert>'), 2)
        # Both masked cards share one unlock, offered once.
        self.assertContains(locked, 'href="/accounts/reauthenticate/?next=%2Fstaging%2F"', count=1)
        self.assertContains(locked, 'Unlock to change<span class="visually-hidden"> staging access, its password or the copy</span>')
        # The read-only facts stay outside the mask.
        self.assertContains(locked, 'Visitors sign in with the username staging.')
        self.assertNotContains(unlocked, ' inert>')
        self.assertNotContains(unlocked, 'is-locked')
        # Turning protection on needs no confirmation, so only the refresh is masked for a public copy.
        self.assertEqual(public.content.decode().count(' inert>'), 1)
        self.assertNotContains(blocked, 'is-locked')

    def test_running_refresh_shows_its_steps_and_reports_the_current_one(self):
        job = {'operation': 'refresh', 'running': True, 'failed': False, 'blocked': False, 'phase': 'database-imported'}
        status = {'host': 'stg.example.com', 'source_host': 'shop.example.com', 'paused': False, 'protected': True, 'job': job}
        with patch('companion_web.operations_client.call', return_value=status):
            page = self.client.get('/staging/', **self.secure)
            update = self.client.get('/staging/status/', **self.secure).json()
        self.assertContains(page, '<h2 id="job-title" data-job-label role="status">Updating staging URLs</h2>', html=True)
        self.assertContains(page, 'data-state="done"', count=3)
        self.assertContains(page, 'data-state="current" aria-current="step"', count=1)
        self.assertEqual((update['label'], update['step']), ('Updating staging URLs', 3))
        job['operation'] = 'compare'
        with patch('companion_web.operations_client.call', return_value={'job': job}):
            self.assertIsNone(self.client.get('/staging/status/', **self.secure).json()['step'])

    def test_locked_release_actions_are_masked(self):
        record = {'created_at': int(time.time()), 'expires_at': int(time.time()) + 600, 'phase': 'completed',
                  'actor': 'operator', 'changed_count': 2, 'file_count': 2, 'token': 'b' * 32}
        with patch('companion_web.operations_client.call', return_value={'releases': [record], 'job': None}):
            response = self.client.get('/staging/releases/', **self.secure)
        self.assertContains(response, 'class="lockable-content" method="post"')
        self.assertContains(response, ' inert>', count=1)
        self.assertContains(response, 'href="/accounts/reauthenticate/?next=%2Fstaging%2Freleases%2F"')
        self.assertNotContains(response, 'Confirm access to restore')


def security_export(now):
    """A collector export built by the collector's own functions, from documentation addresses."""
    import sqlite3
    from companion import security_log
    db = sqlite3.connect(':memory:')
    db.executescript(security_log.SCHEMA)
    alerts = []
    for at, ip, country, user, verified in ((now - 3 * 86400, '198.51.100.20', 'GB', 'admin', True),
                                            (now - 600, '203.0.113.30', 'BR', 'admin', True),
                                            (now - 300, '198.51.100.200', '', '<script>unsafe</script>', False)):
        security_log.record(db, 'cloudpanel', 'signin', at, ip, now, alerts, user=user, country=country,
                            browser_label='Firefox 133 on Windows', method='password', two_factor=True, verified=verified)
    for second in range(60):
        security_log.record(db, 'ssh', 'failed', now - 400 + second, '203.0.113.66', now, alerts, user='root')
    security_log.detect_burst(db, 'ssh', now, alerts)
    security_log.count_visits(db, 'cloudpanel', [{'at': now - 60, 'ip': '198.51.100.20', 'country': 'GB'}])
    # Website probes as the probe guard logs them, a not-found page that reached WordPress and two bans.
    probes = [(now // 86400 * 86400, path, ip, country) for path, ip, country in (
        ('/.env', '203.0.113.90', 'NL'), ('/.env', '203.0.113.90', 'NL'), ('/.git/config', '203.0.113.90', 'NL'),
        ('/backup.sql', '2001:db8::90', ''), ('/.env', '198.51.100.91', 'US'))] + [(now - 2 * 86400, '/terraform.tfstate', '203.0.113.92', 'SG')]
    security_log.tally(db, 'probe_paths', [(at, path, '') for at, path, _, _ in probes])
    security_log.tally(db, 'probe_sources', [(at, ip, country) for at, _, ip, country in probes])
    security_log.tally(db, 'missing_paths', [(now - 100, '/config/aws.json', ''), (now - 90, '/alfa.php', '')])
    security_log.tally(db, 'missing_sources', [(now - 100, '198.51.100.95', ''), (now - 90, '198.51.100.95', '')])
    security_log.record_bans(db, [('203.0.113.90', now - 110, now + 86290)], now)
    security_log.record_bans(db, [('203.0.113.92', now - 2 * 86400, now - 86400)], now - 2 * 86400)
    return security_log.export(db, now, {'protection': {'firewall': 'active', 'ssh_jail': {
        'current': 2, 'total': 40, 'banned': ['203.0.113.66', '203.0.113.67']}, 'ssh_ports': {'ports': [4022], 'uncovered': []},
        'probe_jail': {'current': 1, 'total': 2, 'banned': ['203.0.113.90']}},
        'panel_log': 'connected', 'unavailable': []}, probes=True)


class SecurityTests(TestCase):
    def setUp(self):
        import shutil
        from django.core.cache import cache
        from companion_web import signins
        cache.clear()
        shutil.rmtree(signins.spool_directory(), ignore_errors=True)
        self.operator = get_user_model().objects.create_user('operator', password='Long-test-password-123', is_staff=True)
        self.secure = {'secure': True, 'HTTP_HOST': 'ops.example.com'}
        self.firefox = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0'

    def sign_in(self, ip, country, password='Long-test-password-123'):
        return self.client.post('/accounts/login/', {'login': 'operator', 'password': password},
                                HTTP_X_FORWARDED_FOR=ip, HTTP_X_COMPANION_COUNTRY=country, HTTP_USER_AGENT=self.firefox,
                                **self.secure)

    def spooled(self):
        from companion_web import signins
        folder = signins.spool_directory()
        return [json.loads(path.read_text()) for path in sorted(folder.glob('*.json'))] if folder.exists() else []

    def config(self, folder, export=None):
        path = Path(folder) / 'security.json'
        if export is not None:
            path.write_text(json.dumps(export))
        return {'security_path': str(path), 'host': 'ops.example.com', 'panel_url': 'https://panel.example.com',
                'site_url': 'https://shop.example.com'}

    def test_security_page_is_private(self):
        response = self.client.get('/security/', **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)

    def test_rejected_password_keeps_the_name_and_never_the_password(self):
        from companion_web.models import SignIn
        self.sign_in('198.51.100.20', 'DE', password='Wrong-password-guess-9')
        entry = SignIn.objects.get()
        self.assertEqual((entry.succeeded, entry.username, entry.ip, entry.country, entry.browser, entry.two_factor),
                         (False, 'operator', '198.51.100.20', 'DE', 'Firefox 133 on Windows', False))
        stored = json.dumps(list(SignIn.objects.values()), default=str)
        self.assertNotIn('Wrong-password-guess-9', stored)

    def test_a_name_that_is_no_account_is_never_kept(self):
        from companion_web.models import SignIn
        # A password typed into the name field is exactly such a name.
        self.client.post('/accounts/login/', {'login': 'Long-test-password-123', 'password': 'x'},
                         HTTP_X_FORWARDED_FOR='198.51.100.23', **self.secure)
        self.client.post('/accounts/login/', {'login': 'OPERATOR', 'password': 'Wrong-password-guess-9'},
                         HTTP_X_FORWARDED_FOR='198.51.100.23', **self.secure)
        self.assertEqual(list(SignIn.objects.order_by('id').values_list('succeeded', 'username')), [(False, ''), (False, 'operator')])
        stored = json.dumps(list(SignIn.objects.values()), default=str)
        self.assertNotIn('Long-test-password-123', stored)
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=self.config(folder)):
            response = self.client.get('/security/', **self.secure)
        self.assertContains(response, 'operator<small>+1 with no account name</small>')

    def test_forged_country_values_are_not_stored(self):
        from companion_web.models import SignIn
        self.sign_in('198.51.100.20', 'Germany')
        self.assertEqual(SignIn.objects.get().country, '')

    def test_sign_in_from_a_new_country_is_flagged_and_handed_to_the_collector(self):
        from companion_web import signins
        from companion_web.models import SignIn
        self.assertEqual(self.sign_in('198.51.100.21', 'DE').status_code, 302)
        self.client.post('/accounts/logout/', **self.secure)
        self.sign_in('203.0.113.9', 'FR')
        self.client.post('/accounts/logout/', **self.secure)
        self.sign_in('203.0.113.9', 'FR')
        self.assertEqual([entry.new_source for entry in SignIn.objects.order_by('id')], ['', 'country', ''])
        # Every sign-in is handed over, the new country marked; the spool names fields, never message text.
        alerts = sorted(self.spooled(), key=lambda item: (not item['first'], item['source'] != 'country'))
        common = {'kind': 'signin', 'user': 'operator', 'two_factor': False, 'browser': 'Firefox 133 on Windows'}
        self.assertEqual([{key: value for key, value in alert.items() if key != 'at'} for alert in alerts], [
            {**common, 'source': '', 'first': True, 'ip': '198.51.100.21', 'country': 'DE'},
            {**common, 'source': 'country', 'first': False, 'ip': '203.0.113.9', 'country': 'FR'},
            {**common, 'source': '', 'first': False, 'ip': '203.0.113.9', 'country': 'FR'}])
        # Only the interface's account (and root) may read or add to the spool.
        self.assertEqual(signins.spool_directory().stat().st_mode & 0o077, 0)

    def test_two_factor_steps_are_recorded(self):
        from companion_web.models import SignIn
        secret = generate_totp_secret()
        TOTP.activate(self.operator, secret)
        self.sign_in('198.51.100.22', 'NL')
        self.client.post('/accounts/2fa/authenticate/', {'code': '000000'}, HTTP_X_FORWARDED_FOR='198.51.100.22', **self.secure)
        code = format_hotp_value(hotp_value(secret, int(time.time()) // 30))
        self.client.post('/accounts/2fa/authenticate/', {'code': code}, HTTP_X_FORWARDED_FOR='198.51.100.22', **self.secure)
        self.assertEqual(list(SignIn.objects.order_by('id').values_list('succeeded', 'two_factor')), [(False, True), (True, True)])

    def test_a_failure_burst_is_handed_over_once(self):
        from django.test import RequestFactory
        from companion_web import signins
        from companion_web.models import SignIn
        for number in range(12):
            request = RequestFactory().post('/accounts/login/', HTTP_X_FORWARDED_FOR=f'198.51.100.{number + 1}')
            signins.record(request, 'admin', False, False)
        self.assertEqual(list(SignIn.objects.filter(burst__gt=0).values_list('burst', flat=True)), [10])
        alerts = self.spooled()
        self.assertEqual([(item['kind'], item['count'], item['ip']) for item in alerts], [('burst', 10, '198.51.100.10')])

    def test_failed_attempts_are_grouped_by_source(self):
        from django.test import RequestFactory
        from companion_web import signins
        for name in ('admin', 'root', 'admin', 'test', 'oracle', 'git', 'admin', 'root', 'ubuntu', 'admin', 'root', 'pi'):
            signins.record(RequestFactory().post('/accounts/login/', HTTP_X_FORWARDED_FOR='203.0.113.77',
                                                 HTTP_X_COMPANION_COUNTRY='NL'), name, False, False)
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=self.config(folder)):
            response = self.client.get('/security/', **self.secure)
        self.assertContains(response, '12 in the last 7 days from 1 source, most recent first')
        self.assertContains(response, 'data-label="Attempts" class="numeric">12<small><span class="pill pill-danger" '
                                      'title="Part of 10 failed attempts on this panel within 10 minutes">')
        self.assertContains(response, 'Burst</span></small>')
        self.assertContains(response, 'admin, root, git<small>+4 more</small>')
        self.assertContains(response, '<code class="address">203.0.113.77</code>', count=1)

    def test_entries_past_retention_are_removed_on_the_next_write(self):
        from datetime import timedelta
        from django.test import RequestFactory
        from django.utils import timezone
        from companion_web import signins
        from companion_web.models import SignIn
        SignIn.objects.create(at=timezone.now() - timedelta(days=91), succeeded=False, username='old', ip='198.51.100.1', browser='')
        signins.record(RequestFactory().post('/accounts/login/', HTTP_X_FORWARDED_FOR='198.51.100.2'), 'new', False, False)
        self.assertEqual(list(SignIn.objects.values_list('username', flat=True)), ['new'])

    def test_security_page_shows_every_panel_from_the_export(self):
        self.sign_in('198.51.100.21', 'DE')
        now = int(time.time())
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=self.config(folder, security_export(now))):
            response = self.client.get('/security/', **self.secure)
            self.assertContains(response, 'aria-current="page">')
            self.assertContains(response, 'Needs attention')
            self.assertContains(response, 'signed in from a new country, BR (203.0.113.30)')
            self.assertContains(response, '60 failed attempts within 10 minutes')
            # The panel picker carries each panel's 24-hour counts; the Companion has one sign-in.
            picker = response.content.decode().split('<nav class="panel-picker" aria-label="Panel">', 1)[1].split('</nav>', 1)[0]
            self.assertEqual(picker.count('<a href="?panel='), 4)
            self.assertIn('<strong>5</strong> blocked scans</span><span><strong>1</strong> banned now</span>', picker)
            self.assertIn('<strong>1</strong> sign-in</span>', picker)
            self.assertContains(response, '<figcaption>Failed attempts</figcaption>')
            self.assertContains(response, '198.51.100.21')
            self.assertContains(response, 'Failed attempts by source')
            cloudpanel = self.client.get('/security/?panel=cloudpanel', **self.secure)
            self.assertContains(cloudpanel, 'New country')
            self.assertContains(cloudpanel, 'Unverified')
            self.assertContains(cloudpanel, '&lt;script&gt;unsafe&lt;/script&gt;')
            self.assertNotContains(cloudpanel, '<script>unsafe</script>')
            self.assertContains(cloudpanel, 'Top IP addresses')
            ssh = self.client.get('/security/?panel=ssh', **self.secure)
            self.assertContains(ssh, '<code>203.0.113.67</code>')
            self.assertContains(ssh, 'Fail2ban active')
            self.assertContains(ssh, 'Bans cover SSH port 4022</small>')
            self.assertContains(ssh, 'data-label="Attempts" class="numeric">60<')
            self.assertEqual(ssh['Cache-Control'], 'private, no-store')

    def test_ssh_bans_that_miss_the_ssh_port_are_a_warning(self):
        self.client.force_login(self.operator)
        export = security_export(int(time.time()))
        export['protection']['ssh_ports'] = {'ports': [22, 4022], 'uncovered': [4022]}
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=self.config(folder, export)):
            ssh = self.client.get('/security/?panel=ssh', **self.secure)
            self.assertContains(ssh, 'Bans miss the SSH port')
            self.assertContains(ssh, 'Fail2ban does not ban on port 4022. Run sudo bash install.sh to fix it.')
            self.assertNotContains(ssh, 'Fail2ban active')

    def test_security_page_without_the_collector_is_honest(self):
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=self.config(folder)):
            response = self.client.get('/security/', **self.secure)
            self.assertContains(response, 'CloudPanel, SSH and blocked scan history is unavailable.')
            self.assertNotContains(response, 'Nothing needs attention')
            self.assertContains(response, 'No sign-ins recorded in the last 90 days.')
            self.assertContains(self.client.get('/security/?panel=ssh', **self.secure), 'SSH history is unavailable')

    def test_website_probes_bans_and_patterns_are_shown(self):
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=self.config(folder, security_export(int(time.time())))):
            response = self.client.get('/security/?panel=website', **self.secure)
            page = response.content.decode()
            self.assertContains(response, 'shop.example.com</small>')
            for text in ('Fail2ban active', '<figcaption>Blocked scans per day</figcaption>',
                         '<span><code>/.env</code></span><strong>3</strong>',
                         '<span><code>203.0.113.90</code><small>NL</small></span><strong>3</strong>',
                         '3 scans within an hour ban the address for 24 hours.',
                         'Other missing pages', '<code>/config/aws.json</code>',
                         '<span><code>198.51.100.95</code></span><strong>2</strong>',
                         'Already blocked here', 'Missing page, not blocked',
                         'sudo fail2ban-client status companion-probes'):
                self.assertIn(text, page)
            # The active ban first with its end, then the week's ended one.
            bans = page.split('id="bans-title"', 1)[1].split('</table>', 1)[0]
            self.assertLess(bans.index('203.0.113.90'), bans.index('203.0.113.92'))
            self.assertIn('Active</span>', bans)
            self.assertIn('>Ended<', bans)
            self.assertIn('1 active, 2 started in the last 7 days', page)
            expression = page.split('<textarea id="edge-expression"', 1)[1].split('</textarea>', 1)[0]
            self.assertIn('readonly', expression)
            self.assertIn('(http.request.uri.path contains &quot;/.env&quot;) or (', expression)
            # Nothing on the page reaches Cloudflare: plain text only, no form or script for it.
            self.assertNotIn('api.cloudflare.com', page)
            empty = {**security_export(int(time.time())), 'probes': None}
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=self.config(folder, empty)):
            self.assertContains(self.client.get('/security/?panel=website', **self.secure), 'No blocked scans reported yet')

    def test_disconnected_panel_log_is_explained(self):
        self.client.force_login(self.operator)
        export = {**security_export(int(time.time())), 'panel_log': 'disconnected'}
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG=self.config(folder, export)):
            response = self.client.get('/security/?panel=cloudpanel', **self.secure)
        self.assertContains(response, 'Run sudo bash install.sh to connect it again.')
