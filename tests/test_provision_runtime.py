import ast
import unittest
from pathlib import Path
from unittest import mock

from companion import provision


class ProvisionRuntimeTests(unittest.TestCase):
    """Workers that run as the staging owner must import the installed runtime.

    The operator's checkout usually lives in root's home, which the staging owner
    cannot read; importing from the current directory failed with
    "No module named 'companion'" on a fresh server.
    """

    def test_owner_workers_run_from_installed_runtime(self):
        tree = ast.parse(Path(provision.__file__).read_text())
        workers = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.List):
                values = [item.value for item in node.args[0].elts if isinstance(item, ast.Constant)]
                if '/usr/sbin/runuser' in values and '-m' in values:
                    workers.append(node)
                    cwd = [keyword.value for keyword in node.keywords if keyword.arg == 'cwd']
                    self.assertTrue(cwd and isinstance(cwd[0], ast.Name) and cwd[0].id == 'RUNTIME', values)
        self.assertEqual(len(workers), 2)
        self.assertEqual(provision.RUNTIME, '/opt/cloudpanel-companion')

    def test_clone_receiver_uses_runtime_directory(self):
        sender = mock.Mock(stdout=mock.Mock())
        sender.poll.return_value = 0
        sender.wait.return_value = 0
        receiver = mock.Mock(returncode=0, stdout=b'{"files": 1}', stderr=b'')
        source = mock.Mock(user='shop', root=Path('/home/shop/htdocs/shop.example.com'))
        target = mock.Mock(user='shopstg')
        with mock.patch.object(provision.subprocess, 'Popen', return_value=sender), \
                mock.patch.object(provision.subprocess, 'run', return_value=receiver) as executed:
            self.assertEqual(provision.transfer(source, target, {'task': 1}), {'files': 1})
        self.assertEqual(executed.call_args.kwargs['cwd'], '/opt/cloudpanel-companion')


class StagingUrlRewriteTests(unittest.TestCase):
    """Staging must not load the live site: every stored URL form of its host moves.

    The rehearsal copy kept 2,213 JSON-escaped live URLs while only `https://` was
    rewritten, and 21 more (double-escaped JSON, other forms) after the escaped pass.
    """
    BS = '\\'
    CHANGED = {
        'https://shop.example.com/a/': 'https://stg.example.com/a/',
        'http://shop.example.com': 'http://stg.example.com',
        '<img src="//shop.example.com/x.jpg">': '<img src="//stg.example.com/x.jpg">',
        '{"url":"https:\\/\\/shop.example.com\\/x.jpg"}': '{"url":"https:\\/\\/stg.example.com\\/x.jpg"}',
        '{"u":"http:\\/\\/shop.example.com","p":"\\/\\/shop.example.com"}':
            '{"u":"http:\\/\\/stg.example.com","p":"\\/\\/stg.example.com"}',
        '"{\\"url\\":\\"https:\\\\\\/\\\\\\/shop.example.com\\\\\\/x\\"}"':
            '"{\\"url\\":\\"https:\\\\\\/\\\\\\/stg.example.com\\\\\\/x\\"}"',
        '/wp-login.php?redirect_to=https%3A%2F%2Fshop.example.com%2Fcart%2F':
            '/wp-login.php?redirect_to=https%3A%2F%2Fstg.example.com%2Fcart%2F',
        'redirect_to=https%3a%2f%2fshop.example.com': 'redirect_to=https%3a%2f%2fstg.example.com',
        'https://shop.example.com:8443/ and https://shop.example.com.': 'https://stg.example.com:8443/ and https://stg.example.com.',
    }
    UNCHANGED = ('https://shop.example.com.au/', 'https://shop.example.community/', '//myshop.example.com/',
                 '//sub.shop.example.com/', 'orders@shop.example.com', '/home/shop/htdocs/shop.example.com/wp-content')

    def test_every_url_form_of_the_live_host_is_rewritten(self):
        import re
        pattern, replacement = provision.host_rewrite('shop.example.com', 'stg.example.com')
        python = replacement.replace('${1}', r'\g<1>')
        for before, after in self.CHANGED.items():
            self.assertEqual(re.sub(pattern, python, before), after, before)
        for value in self.UNCHANGED:
            self.assertEqual(re.sub(pattern, python, value), value, value)

    def test_wp_cli_pcre_gives_the_same_result(self):
        # WP-CLI applies the pattern with PHP's preg_replace and the '#' delimiter.
        import json
        import shutil
        import subprocess
        php = shutil.which('php')
        if not php:
            self.skipTest('PHP is not installed')
        pattern, replacement = provision.host_rewrite('shop.example.com', 'stg.example.com')
        values = list(self.CHANGED) + list(self.UNCHANGED)
        result = subprocess.run([php, '-r', '$d = json_decode(stream_get_contents(STDIN), true); echo json_encode('
                                 'array_map(fn($v) => preg_replace("#" . $d["p"] . "#", $d["r"], $v), $d["v"]));'],
                                input=json.dumps({'p': pattern, 'r': replacement, 'v': values}),
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), list(self.CHANGED.values()) + list(self.UNCHANGED))

    def test_import_runs_one_regex_search_replace(self):
        import tempfile
        calls = []
        ok = mock.Mock(returncode=0, stdout=b'', stderr=b'')
        with tempfile.TemporaryDirectory() as folder:
            args = mock.Mock(state=Path(folder))
            with mock.patch.object(provision.subprocess, 'run', return_value=ok), \
                    mock.patch.object(provision, 'site_wp', return_value=['wp']), \
                    mock.patch.object(provision, 'command', side_effect=lambda arguments, **kwargs: calls.append(arguments) or b''):
                provision.import_database(mock.Mock(host='shop.example.com'),
                                          mock.Mock(host='stg.example.com', database='stg', user='stg'), args, {}, 'secret')
        rewrites = [arguments for arguments in calls if 'search-replace' in arguments]
        self.assertEqual(len(rewrites), 1)
        start = rewrites[0].index('search-replace')
        self.assertEqual(rewrites[0][start + 1:start + 3], list(provision.host_rewrite('shop.example.com', 'stg.example.com')))
        for flag in ('--regex', '--regex-delimiter=#', '--skip-columns=guid', '--all-tables-with-prefix'):
            self.assertIn(flag, rewrites[0])


if __name__ == '__main__':
    unittest.main()
