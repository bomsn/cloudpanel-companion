"""Django tests run separately with the pinned web dependencies installed."""
import json
import tempfile
import time
from pathlib import Path
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
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

    def test_monitoring_is_private_and_absent_history_is_honest(self):
        self.assertEqual(self.client.get('/monitoring/', **self.secure).status_code, 302)
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder, override_settings(CONFIG={'history_path': str(Path(folder) / 'absent.json')}):
            response = self.client.get('/monitoring/', **self.secure)
        self.assertContains(response, 'No monitoring history available')
        self.assertEqual(response['Cache-Control'], 'private, no-store')

    def test_password_access_json_requires_confirmation_and_csrf(self):
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        response = self.client.post('/staging/change/', {'operation': 'protection', 'enabled': 'false'},
                                    HTTP_ACCEPT='application/json', **self.secure)
        self.assertEqual(response.status_code, 403)
        self.assertIn('reauthenticate', response.json())

    def test_disabled_external_fields_preserve_saved_allowlist(self):
        from unittest.mock import patch
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
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
        from django.test import Client
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        self.assertEqual(client.post('/staging/releases/check/', **self.secure).status_code, 403)
        self.assertEqual(client.get('/staging/releases/check/', **self.secure).status_code, 405)

    def test_compared_code_is_data_and_never_executable_markup(self):
        from unittest.mock import patch
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        with patch('companion_web.operations_client.call', return_value={'comparison': {'folders': [{'label': '<script>bad</script>'}]}, 'job': None}):
            response = self.client.get('/staging/releases/status/', **self.secure)
        self.assertEqual(response['Cache-Control'], 'private, no-store')
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertEqual(response.json()['comparison']['folders'][0]['label'], '<script>bad</script>')

    def test_release_history_summaries_do_not_require_embedded_file_details(self):
        from unittest.mock import patch
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        record = {'created_at': int(time.time()), 'expires_at': int(time.time()) + 600, 'phase': 'preview',
                  'actor': 'operator', 'changed_count': 2, 'file_count': 2, 'token': 'a' * 32}
        with patch('companion_web.operations_client.call', return_value={'releases': [record], 'job': None}):
            response = self.client.get('/staging/releases/', **self.secure)
        self.assertContains(response, 'Changes in staging')
        self.assertContains(response, 'Ready to review')

    def test_staging_mutations_require_csrf_even_for_an_operator(self):
        from django.test import Client
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        response = client.post('/staging/change/', {'operation': 'pause', 'enabled': 'true'}, **self.secure)
        self.assertEqual(response.status_code, 403)

    def test_sensitive_change_requires_confirmation_without_storing_new_password(self):
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        response = self.client.post('/staging/change/', {'operation': 'password', 'password': 'new-staging-secret-123'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/reauthenticate/', response.url)
        self.assertNotIn('account_reauthentication_state', self.client.session)
        self.assertNotIn('new-staging-secret-123', str(dict(self.client.session)))

    def test_code_release_requires_recent_confirmation(self):
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        for operation in ('release_apply', 'release_recover'):
            response = self.client.post('/staging/releases/change/', {'operation': operation,
                'token': 'a' * 32, 'confirmed': 'yes'}, **self.secure)
            self.assertEqual(response.status_code, 302)
            self.assertIn('/accounts/reauthenticate/', response.url)
            self.assertNotIn('account_reauthentication_state', self.client.session)

    def test_code_release_post_requires_csrf(self):
        from django.test import Client
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        response = client.post('/staging/releases/change/', {'operation': 'release_preview',
            'files': 'wp-content/themes/example/style.css'}, **self.secure)
        self.assertEqual(response.status_code, 403)

    def test_code_release_without_runner_is_honestly_unavailable(self):
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        self.assertContains(self.client.get('/staging/releases/', **self.secure), 'Code releases are unavailable')

    def test_public_registration_closed(self):
        response = self.client.get('/accounts/signup/', **self.secure)
        self.assertContains(response, 'closed')

    def test_password_only_operator_must_enrol_mfa(self):
        self.client.force_login(self.operator)
        response = self.client.get('/', **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/2fa/', response.url)

    def test_non_operator_is_denied(self):
        user = get_user_model().objects.create_user('visitor', password='Long-test-password-123')
        self.client.force_login(user)
        self.assertEqual(self.client.get('/', **self.secure).status_code, 403)

    def test_dashboard_requires_fresh_real_observations(self):
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'snapshot.json'
            config = {'snapshot_path': str(path), 'panel_url': 'https://panel.example.com',
                      'site_url': 'https://site.example.com', 'site_name': '<script>unsafe</script>'}
            with override_settings(CONFIG=config):
                response = self.client.get('/', **self.secure)
                self.assertContains(response, 'Current server checks are unavailable')
                self.assertNotContains(response, '<script>unsafe</script>')
                path.write_text(json.dumps({'observed_at': time.time(), 'checks': [
                    {'name': 'Homepage', 'healthy': True, 'category': 'http', 'status': 200, 'certificate_days': 30}]}))
                response = self.client.get('/', **self.secure)
                self.assertContains(response, '30 days remaining')
                self.assertContains(response, 'Responding')
                self.assertEqual(response['Cache-Control'], 'private, no-store')
                self.assertEqual(response['X-Frame-Options'], 'DENY')
                path.write_text(json.dumps({'observed_at': time.time() - 300, 'checks': []}))
                self.assertContains(self.client.get('/', **self.secure), 'Current server checks are unavailable')

    def test_overview_lists_services_and_missed_backups(self):
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        with tempfile.TemporaryDirectory() as folder:
            system = Path(folder) / 'system.json'
            config = {'snapshot_path': str(Path(folder) / 'snapshot.json'), 'system_snapshot_path': str(system),
                      'panel_url': 'https://panel.example.com', 'site_url': 'https://site.example.com', 'site_name': 'Shop'}
            with override_settings(CONFIG=config):
                system.write_text(json.dumps({'observed_at': time.time(), 'backup_grace': 10800,
                    'services': [{'name': 'Shop: Nginx', 'state': 'active', 'recovery_enabled': True}], 'backups': []}))
                response = self.client.get('/', **self.secure)
                self.assertContains(response, 'Shop: Nginx')
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
        from django.test import Client
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
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        response = self.client.post('/staging/external/change/', {'http_enabled': 'yes', 'http_rules': 'GET https://example.com/test'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/reauthenticate/', response.url)
        self.assertNotIn('account_reauthentication_state', self.client.session)

    def test_emergency_external_stop_needs_no_reconfirmation(self):
        from unittest.mock import patch
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        with patch('companion_web.operations_client.call', return_value={'saved': True}) as call:
            response = self.client.post('/staging/external/change/', {'operation': 'external_stop'}, **self.secure)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/staging/external/')
        call.assert_called_once_with('external_stop', actor='operator')

    def test_external_mutation_requires_csrf(self):
        from django.test import Client
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        response = client.post('/staging/external/change/', {'operation': 'external_stop'}, **self.secure)
        self.assertEqual(response.status_code, 403)

    def test_invalid_external_destination_keeps_the_operator_input(self):
        from unittest.mock import patch
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
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

    def test_captured_email_is_escaped_in_the_authenticated_inbox(self):
        from unittest.mock import patch
        Authenticator.objects.create(user=self.operator, type='totp', data={'secret': 'test-fixture'})
        self.client.force_login(self.operator)
        message = {'id': '12345678900-' + 'a' * 16, 'recipients': ['test@example.com'],
                   'subject': '<script>subject</script>', 'body': '<script>body</script>'}
        with patch('companion_web.operations_client.call', side_effect=[{'messages': [message]}, message]):
            response = self.client.get('/staging/inbox/?message=' + message['id'], **self.secure)
        self.assertContains(response, '&lt;script&gt;body&lt;/script&gt;')
        self.assertNotContains(response, '<script>body</script>')
        self.assertNotContains(response, '<script>subject</script>')
        self.assertEqual(response['Cache-Control'], 'private, no-store')
