import unittest
from companion.staging import Site, validate_pair, protected_template


class StagingTests(unittest.TestCase):
    def source(self):
        return Site('example.com', 'source', 'source_db', '8.3')

    def test_separate_identity(self):
        validate_pair(self.source(), Site('stage.example.com', 'staging', 'stage_db', '8.3'))

    def test_shared_resources_rejected(self):
        for target in [Site('example.com', 'staging', 'stage_db', '8.3'),
                       Site('stage.example.com', 'source', 'stage_db', '8.3'),
                       Site('stage.example.com', 'staging', 'source_db', '8.3')]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_pair(self.source(), target)

    def test_path_injection_rejected(self):
        with self.assertRaises(ValueError):
            Site('stage.example.com', '../root', 'stage_db', '8.3').root

    def test_unknown_template_is_rejected(self):
        with self.assertRaises(ValueError):
            protected_template('different template', '/etc/cloudpanel-companion/staging.htpasswd')

    def test_staging_has_explicit_php_route(self):
        template = ('  {{root}}\n  {{root}}\n    auth_basic off;\n'
                    '    {{varnish_proxy_pass}}\n'
                    '    fastcgi_param PHP_VALUE "{{php_settings}}";\n'
                    '  location ~ /.well-known {\n    allow all;\n  }')
        result = protected_template(template, '/etc/cloudpanel-companion/staging.htpasswd')
        self.assertIn('proxy_pass http://127.0.0.1:8080;', result)
        self.assertNotIn('{{varnish_proxy_pass}}', result)
        self.assertEqual(result.count('auth_basic "Private staging";'), 2)
        self.assertEqual(result.count('auth_basic off;'), 1)
        self.assertIn('^/\\.well-known/acme-challenge/[A-Za-z0-9_-]+$', result)
        self.assertIn('try_files $uri =404;', result)


if __name__ == '__main__':
    unittest.main()
