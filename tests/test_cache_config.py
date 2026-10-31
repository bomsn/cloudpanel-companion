import unittest
from companion.cache_config import render


class CacheConfigTests(unittest.TestCase):
    def config(self):
        return {'backend_port': 8080, 'sites': [{'host': 'example.com', 'purge_key': 'a' * 64}]}

    def test_valid_render(self):
        result = render(self.config(), '# policy')
        self.assertIn('Unregistered cache host', result)
        self.assertIn('cache_manager_for_cloudpanel_revision', result)
        self.assertNotIn('a' * 64, result)
        self.assertNotIn('import var;', result)
        self.assertIn('# policy', result)

    def test_config_injection_rejected(self):
        for host in ['example.com"; return(synth(200));', '-bad.example', 'a..example', 'a/' ]:
            config = self.config()
            config['sites'][0]['host'] = host
            with self.subTest(host=host), self.assertRaises(ValueError):
                render(config, '')

    def test_shared_credentials_rejected(self):
        config = self.config()
        config['sites'].append({'host': 'other.example', 'purge_key': 'a' * 64})
        with self.assertRaises(ValueError):
            render(config, '')

    def test_empty_registry_rejected(self):
        with self.assertRaises(ValueError):
            render({'backend_port': 8080, 'sites': []}, '')


if __name__ == '__main__':
    unittest.main()
