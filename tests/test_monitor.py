import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from companion.health import Target
from companion.monitor import bounded_probe, run


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


@unittest.skipUnless(os.name == 'posix', 'Linux ownership and locking qualification')
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.config = self.root / 'monitor.json'
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.target = {'name': 'test', 'url': f'http://127.0.0.1:{self.server.server_port}'}
        self.config.write_text(json.dumps({'targets': [self.target]}))
        self.config.chmod(0o600)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def test_complete_run_and_marker(self):
        result = run(self.config, self.state)
        self.assertTrue(result['observations'][0]['healthy'])
        self.assertTrue((self.state / 'last-completed.json').is_file())

    def test_child_probe(self):
        self.assertTrue(bounded_probe(Target(**self.target)).healthy)

    def test_empty_inventory_is_error(self):
        self.config.write_text('{"targets": []}')
        with self.assertRaises(ValueError):
            run(self.config, self.state)
        self.assertFalse((self.state / 'last-completed.json').exists())

    def test_public_configuration_is_rejected(self):
        self.config.chmod(0o644)
        with self.assertRaises(ValueError):
            run(self.config, self.state)

    def test_overlapping_run_is_rejected(self):
        import fcntl
        with (self.state / 'monitor.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(RuntimeError):
                run(self.config, self.state)


if __name__ == '__main__':
    unittest.main()
