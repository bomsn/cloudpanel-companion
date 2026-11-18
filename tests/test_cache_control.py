import http.client
import re
import socket
import tempfile
import threading
import time
from pathlib import Path
import unittest
from unittest import mock

from companion.cache_config import render
from companion.cache_control import PAGE, REPEAT_LIMIT, ControlServer, Handler, RevisionController, ban_expression


class VarnishFreeController(RevisionController):
    """Records varnishadm commands and VCL activations instead of running Varnish."""

    def __init__(self, *args, refuse_bans=False):
        self.commands, self.activated, self.refuse_bans, self.refuse_admin = [], [], refuse_bans, False
        super().__init__(*args)

    def admin(self, *arguments, diagnostic=True):
        self.commands.append(arguments)
        if self.refuse_admin or (arguments[0] == 'ban' and self.refuse_bans):
            raise RuntimeError('Varnish did not accept the configuration operation')
        return ''

    def activate(self, host=None):
        self.activated.append(host)
        return 'cmcp_' + '0' * 32


def ban_pattern(expression):
    """The URL regex Varnish compiles from a ban, after its CLI unquoting."""
    quoted = re.fullmatch(r'obj\.http\.X-Cache-Manager-For-CloudPanel-Host == "[a-z0-9.-]+" && '
                          r'obj\.http\.X-Cache-Manager-For-CloudPanel-Url ~ "((?:[^"\\]|\\.)*)"', expression)
    return re.sub(r'\\(.)', r'\1', quoted.group(1))


def wait_for(condition):
    deadline = time.monotonic() + 5
    while not condition() and time.monotonic() < deadline:
        time.sleep(.01)


class ControllerFixture(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        # A cleanup, not tearDown: it must run after the cleanups subclasses add.
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.instance = self.root / 'instance'
        self.instance.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.ready = self.root / 'ready'
        self.ready.mkdir(mode=0o755)
        self.config = {'backend_port': 8080, 'sites': [
            {'host': 'one.example', 'purge_key': 'a' * 64},
            {'host': 'two.example', 'purge_key': 'b' * 64},
        ]}

    def varnish_free(self, **options):
        return VarnishFreeController(self.config, '# policy', self.state, self.instance, self.ready, **options)


class CacheControlTests(ControllerFixture):

    def test_credentials_cannot_cross_sites(self):
        controller = RevisionController(self.config, '# policy', self.state, self.instance, self.ready)
        try:
            self.assertTrue(controller.authenticated('one.example', 'a' * 64))
            self.assertFalse(controller.authenticated('two.example', 'a' * 64))
            self.assertFalse(controller.authenticated('unknown.example', 'a' * 64))
            self.assertFalse(controller.authenticated('one.example', 'a' * 63))
        finally:
            controller.close()

    def test_second_controller_cannot_race_revisions(self):
        controller = RevisionController(self.config, '# policy', self.state, self.instance, self.ready)
        try:
            with self.assertRaises(BlockingIOError):
                RevisionController(self.config, '# policy', self.state, self.instance, self.ready)
        finally:
            controller.close()

    def test_site_revision_does_not_change_other_site_namespace(self):
        revisions = {'one.example': '1' * 32, 'two.example': '2' * 32}
        first = render(self.config, '# policy', revisions)
        second = render(self.config, '# policy', {**revisions, 'one.example': '3' * 32})
        self.assertEqual([line for line in first.splitlines() if 'host == "two.example"' in line],
                         [line for line in second.splitlines() if 'host == "two.example"' in line])
        self.assertNotEqual(first, second)

    def test_availability_is_explicit_and_removed_on_shutdown(self):
        controller = RevisionController(self.config, '# policy', self.state, self.instance, self.ready)
        self.assertFalse(controller.marker('one.example').exists())
        controller.set_ready('one.example', True)
        self.assertTrue(controller.marker('one.example').is_file())
        controller.close()
        self.assertFalse(controller.marker('one.example').exists())

    def test_policy_change_also_changes_namespace(self):
        revisions = {'one.example': '1' * 32, 'two.example': '2' * 32}
        first = render(self.config, '# old policy', revisions)
        second = render(self.config, '# new policy', revisions)
        self.assertNotEqual([line for line in first.splitlines() if 'set req.http.' in line],
                            [line for line in second.splitlines() if 'set req.http.' in line])

    def test_revision_injection_rejected(self):
        with self.assertRaises(ValueError):
            render(self.config, '', {'one.example': '"; return(synth(200));', 'two.example': '2' * 32})

    def test_page_must_be_one_visible_ascii_request_target(self):
        for page in ('/', '/shop/', '/product/chair/?colour=red&size=2', '/caf%C3%A9/', '/a"b\\c', '/' + 'a' * 2047):
            self.assertTrue(PAGE.fullmatch(page), page)
        for page in ('', 'shop/', 'https://one.example/', '/a b', '/a\tb', '/a\r\nX-Injected: 1', '/a\n', '/a\r',
                     '/café/', '/\x7f', '/\x00', '/' + 'a' * 2048):
            self.assertFalse(PAGE.fullmatch(page), page)

    def test_ban_expression_is_scoped_to_one_site_and_page(self):
        self.assertEqual(ban_expression('one.example', '/shop/'),
                         'obj.http.X-Cache-Manager-For-CloudPanel-Host == "one.example" && '
                         'obj.http.X-Cache-Manager-For-CloudPanel-Url ~ "^/shop/([?]|$)"')
        # The regex backslash is doubled once more for the Varnish CLI.
        self.assertEqual(ban_expression('one.example', '/?p=1'),
                         'obj.http.X-Cache-Manager-For-CloudPanel-Host == "one.example" && '
                         'obj.http.X-Cache-Manager-For-CloudPanel-Url ~ "^/\\\\?p=1$"')

    def test_ban_expression_keeps_metacharacters_and_quotes_literal(self):
        for page in ('/a.b', '/(x)|y/', '/[a-z]+*{2}^$', '/a\\d', '/q"&& obj.http.x ~ ".', '/a?b=.*'):
            with self.subTest(page=page):
                pattern = ban_pattern(ban_expression('one.example', page))
                self.assertTrue(re.search(pattern, page))
                for other in (page + 'x', page[:-1] + '!' + page[-1], 'x' + page, page.replace('/', '', 1)):
                    self.assertFalse(re.search(pattern, other), other)
                # Without its own query a page also covers stored query variants.
                self.assertEqual(bool(re.search(pattern, page + '?utm_source=x')), '?' not in page)

    def test_ban_expression_covers_both_percent_escape_spellings(self):
        pattern = ban_pattern(ban_expression('one.example', '/caf%C3%A9/'))
        for page in ('/caf%C3%A9/', '/caf%c3%a9/', '/caf%c3%A9/'):
            self.assertTrue(re.search(pattern, page), page)
        for page in ('/caf%C3%A8/', '/CAF%C3%A9/', '/caf%25C3%A9/'):
            self.assertFalse(re.search(pattern, page), page)

    def test_page_clear_bans_and_repeats_once_in_flight_renders_end(self):
        controller = self.varnish_free()
        try:
            with mock.patch('companion.cache_control.REPEAT_SECONDS', 0):
                self.assertEqual(controller.clear_page('one.example', '/shop/'), 'url-ban-v1')
            wait_for(lambda: len(controller.commands) == 2)
            ban = ('ban', ban_expression('one.example', '/shop/'))
            self.assertEqual(controller.commands, [ban, ban])
            self.assertEqual(controller.activated, [])
            with self.assertRaises(ValueError):
                controller.clear_page('unknown.example', '/shop/')
        finally:
            controller.close()

    def test_refused_ban_becomes_a_site_revision(self):
        controller = self.varnish_free(refuse_bans=True)
        try:
            self.assertEqual(controller.clear_page('one.example', '/shop/'), 'site-revision-v1')
            self.assertEqual(controller.activated, ['one.example'])
            self.assertEqual(controller.repeats, {})
        finally:
            controller.close()

    def test_refused_repeat_becomes_a_site_revision(self):
        controller = self.varnish_free()
        try:
            with mock.patch('companion.cache_control.REPEAT_SECONDS', .2):
                self.assertEqual(controller.clear_page('two.example', '/shop/'), 'url-ban-v1')
            controller.refuse_bans = True
            wait_for(lambda: controller.activated)
            self.assertEqual(controller.activated, ['two.example'])
        finally:
            controller.close()

    def test_broad_page_clears_become_one_site_revision(self):
        controller = self.varnish_free()
        try:
            for number in range(REPEAT_LIMIT):
                self.assertEqual(controller.clear_page('one.example', f'/post-{number}/'), 'url-ban-v1')
            self.assertEqual(controller.clear_page('one.example', '/post-0/'), 'url-ban-v1')
            self.assertEqual(controller.clear_page('one.example', '/another/'), 'site-revision-v1')
            self.assertEqual(controller.clear_page('two.example', '/another/'), 'url-ban-v1')
            self.assertEqual(controller.activated, ['one.example'])
        finally:
            controller.close()


class ControlRequestTests(ControllerFixture):
    def setUp(self):
        super().setUp()
        self.controller = self.varnish_free()
        self.addCleanup(self.controller.close)
        self.server = ControlServer(('127.0.0.1', 0), Handler)
        self.server.controller = self.controller
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def purge(self, *headers, host='one.example', key='a' * 64, method='PURGE'):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            connection.putrequest(method, '/', skip_host=True)
            for name, value in (('Host', host), ('X-Cache-Manager-For-CloudPanel-Key', key), *headers):
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()
            response.read()
            return response.status, response.getheader('X-Cache-Manager-For-CloudPanel-Policy')
        finally:
            connection.close()

    def test_page_clear_reports_its_policy(self):
        self.assertEqual(self.purge(('X-Cache-Manager-For-CloudPanel-Url', '/shop/?orderby=price')), (200, 'url-ban-v1'))
        self.assertEqual(self.controller.commands, [('ban', ban_expression('one.example', '/shop/?orderby=price'))])
        self.assertEqual(self.controller.activated, [])

    def test_request_without_page_still_activates_a_site_revision(self):
        self.assertEqual(self.purge(), (200, 'site-revision-v1'))
        self.assertEqual(self.controller.activated, ['one.example'])
        self.assertEqual(self.controller.commands, [])

    def test_page_clear_cannot_cross_sites(self):
        page = ('X-Cache-Manager-For-CloudPanel-Url', '/shop/')
        self.assertEqual(self.purge(page, host='two.example'), (403, None))
        self.assertEqual(self.purge(page, host='unknown.example'), (403, None))
        self.assertEqual(self.purge(page, host='two.example', key='b' * 64), (200, 'url-ban-v1'))
        self.assertEqual(self.controller.commands, [('ban', ban_expression('two.example', '/shop/'))])

    def test_malformed_page_rejected_before_any_cache_operation(self):
        name = 'X-Cache-Manager-For-CloudPanel-Url'
        for headers in (((name, '/a'), (name, '/b')), ((name, ''),), ((name, 'shop/'),),
                        ((name, '/' + 'a' * 2048),), ((name, '/café/'),), ((name, '/a\r\n b'),)):
            with self.subTest(headers=headers):
                self.assertEqual(self.purge(*headers), (400, None))
        self.assertEqual(self.controller.commands, [])
        self.assertEqual(self.controller.activated, [])
        self.assertEqual(self.purge((name, '/' + 'a' * 2047)), (200, 'url-ban-v1'))

    def test_credential_check_clears_nothing(self):
        self.assertEqual(self.purge(method='OPTIONS'), (200, 'url-ban-v1'))
        self.assertEqual(self.controller.commands, [('ping',)])
        self.assertEqual(self.controller.activated, [])
        self.assertEqual(self.purge(method='OPTIONS', key='b' * 64), (403, None))
        self.assertEqual(self.purge(method='OPTIONS', host='unknown.example'), (403, None))
        self.assertEqual(self.purge(('X-Cache-Manager-For-CloudPanel-Url', '/shop/'), method='OPTIONS'), (400, None))
        self.assertEqual(self.controller.commands, [('ping',)])
        self.assertEqual(self.controller.activated, [])

    def test_credential_check_reports_an_unreachable_cache(self):
        self.controller.refuse_admin = True
        self.assertEqual(self.purge(method='OPTIONS'), (503, None))
        self.assertEqual(self.controller.activated, [])

    def test_folded_header_cannot_smuggle_a_line_break(self):
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=5) as connection:
            connection.sendall(b'PURGE / HTTP/1.1\r\nHost: one.example\r\nX-Cache-Manager-For-CloudPanel-Key: ' + b'a' * 64 +
                               b'\r\nX-Cache-Manager-For-CloudPanel-Url: /a\r\n\t/b\r\n\r\n')
            self.assertRegex(connection.recv(64), rb'^HTTP/1\.[01] 400 ')
        self.assertEqual(self.controller.commands, [])


class ControllerUnitTests(unittest.TestCase):
    def test_unit_serves_the_port_and_markers_the_installers_configure(self):
        # WordPress (CACHE_MANAGER_FOR_CLOUDPANEL_PORT/_READY) and Nginx are configured from these constants.
        from companion.cache_config import CONTROL_PORT, READY_DIRECTORY
        unit = (Path(__file__).resolve().parents[1] / 'assets/cache-manager-control.service').read_text()
        command = re.search(r'^ExecStart=(.*)$', unit, re.M)[1].split()
        self.assertEqual(command[command.index('--port') + 1], str(CONTROL_PORT))
        self.assertEqual(command[command.index('--ready') + 1], str(READY_DIRECTORY))


if __name__ == '__main__':
    unittest.main()
