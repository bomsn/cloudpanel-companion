"""The website's certificate authority: shipped roots, the installed file and real TLS checks."""
import hashlib
import http.server
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock
from companion import site_trust
from companion.health import Target, probe
from companion.monitor_setup import origin_trust

ROOT_USER = hasattr(os, 'geteuid') and os.geteuid() == 0


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


class CloudflareRootTests(unittest.TestCase):
    def test_shipped_roots_are_cloudflares_published_origin_ca_roots(self):
        # https://developers.cloudflare.com/ssl/static/origin_ca_rsa_root.pem and origin_ca_ecc_root.pem,
        # linked from https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/
        text = site_trust.CLOUDFLARE_ORIGIN_CA.read_text()
        blocks = re.findall(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', text, re.S)
        self.assertEqual([hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest() for block in blocks], [
            'd3c7e85c91707fc0a12abc5d88266747aa4fa8e7b162f633ffb3c9d989947620',  # RSA
            'aa63697a22764b67b2134ce14cb5690ea336940b93986113f49545917832d80d'])  # ECC
        context = ssl.create_default_context(cafile=str(site_trust.CLOUDFLARE_ORIGIN_CA))
        self.assertEqual(len(context.get_ca_certs()), 2)


@unittest.skipUnless(ROOT_USER, 'The installed file must be root-owned')
class InstalledFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        patcher = mock.patch.object(site_trust, 'CONFIG', Path(self.temp.name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_absent_means_the_system_store(self):
        self.assertIsNone(site_trust.site_ca_file('shop.example.com'))
        self.assertEqual(site_trust.curl_trust('shop.example.com'), [])

    def test_install_and_remove(self):
        site_trust.install('shop.example.com', site_trust.CLOUDFLARE_ORIGIN_CA)
        path = Path(self.temp.name) / 'site-ca-shop.example.com.crt'
        self.assertEqual(site_trust.site_ca_file('shop.example.com'), str(path))
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        self.assertEqual(path.read_bytes(), site_trust.CLOUDFLARE_ORIGIN_CA.read_bytes())
        self.assertEqual(site_trust.curl_trust('shop.example.com'), ['--cacert', str(path)])
        site_trust.remove('shop.example.com')
        self.assertIsNone(site_trust.site_ca_file('shop.example.com'))
        site_trust.remove('shop.example.com')

    def test_a_file_others_could_change_is_refused(self):
        path = Path(self.temp.name) / 'site-ca-shop.example.com.crt'
        path.write_text('')
        path.chmod(0o664)
        with self.assertRaises(ValueError):
            site_trust.site_ca_file('shop.example.com')
        path.unlink()
        path.symlink_to(site_trust.CLOUDFLARE_ORIGIN_CA)
        with self.assertRaises(ValueError):
            site_trust.site_ca_file('shop.example.com')

    def test_release_check_verifies_with_the_installed_authority(self):
        from companion import registered_deployment
        site_trust.install('shop.example.com', site_trust.CLOUDFLARE_ORIGIN_CA)
        with mock.patch.object(registered_deployment, 'command', return_value=b'') as command:
            registered_deployment.release_check('shop.example.com', 'companion-release-x.php')
        arguments = command.call_args.args[0]
        self.assertEqual(arguments[arguments.index('--cacert') + 1], site_trust.site_ca_file('shop.example.com'))

    def test_hostname_is_a_file_name_not_a_path(self):
        for host in ('../web.json', 'shop.example.com/x', ''):
            with self.subTest(host=host), self.assertRaises(ValueError):
                site_trust.bundle_path(host)


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for TLS fixture')
class PrivateAuthorityTests(unittest.TestCase):
    """A local CA stands in for Cloudflare's Origin CA: trusted only through the installed file."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        folder = Path(cls.temp.name)
        cls.ca = folder / 'ca.pem'
        leaf, key, csr, extensions = folder / 'leaf.pem', folder / 'leaf.key', folder / 'leaf.csr', folder / 'leaf.ext'
        run = lambda *arguments: subprocess.run(['openssl', *arguments], check=True, capture_output=True)
        run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(folder / 'ca.key'), '-out', str(cls.ca),
            '-days', '5480', '-subj', '/CN=Companion Test Origin CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(csr), '-subj', '/CN=localhost')
        extensions.write_text('subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n'
                              'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
                              'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
        # Fifteen years, the longest validity Cloudflare offers for an Origin CA certificate.
        run('x509', '-req', '-in', str(csr), '-CA', str(cls.ca), '-CAkey', str(folder / 'ca.key'),
            '-CAcreateserial', '-out', str(leaf), '-days', '5475', '-extfile', str(extensions))
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'https://localhost:{cls.server.server_port}/'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def setUp(self):
        self.config = tempfile.TemporaryDirectory()
        self.addCleanup(self.config.cleanup)
        patcher = mock.patch.object(site_trust, 'CONFIG', Path(self.config.name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_origin_check_passes_with_the_installed_authority_and_fails_without(self):
        site_trust.install('localhost', self.ca)
        targets = [{'name': 'origin', 'url': self.url, 'connect_host': '127.0.0.1'}]
        origin_trust(targets, 'localhost', True)
        trusted = probe(Target(**targets[0]))
        self.assertTrue(trusted.healthy)
        # Expiry is still read from the website's certificate, not hidden by the bundle.
        self.assertEqual(trusted.category, 'healthy')
        self.assertGreater(trusted.certificate_days, 5000)
        origin_trust(targets, 'localhost', False)
        self.assertNotIn('ca_file', targets[0])
        self.assertEqual(probe(Target(**targets[0])).category, 'certificate-invalid')

    def test_cloudflare_roots_do_not_trust_another_authority(self):
        result = probe(Target('origin', self.url, connect_host='127.0.0.1', ca_file=str(site_trust.CLOUDFLARE_ORIGIN_CA)))
        self.assertEqual(result.category, 'certificate-invalid')

    @unittest.skipUnless(ROOT_USER and shutil.which('curl'), 'curl and a root-owned installed file required')
    def test_release_style_curl_check_uses_the_installed_authority(self):
        request = lambda: subprocess.run(['curl', '-fsS', '-o', '/dev/null', '--resolve',
                                          'localhost:%d:127.0.0.1' % self.server.server_port,
                                          *site_trust.curl_trust('localhost'), self.url], capture_output=True)
        self.assertEqual(request().returncode, 60)  # peer certificate cannot be authenticated
        site_trust.install('localhost', self.ca)
        self.assertEqual(request().returncode, 0)


if __name__ == '__main__':
    unittest.main()
