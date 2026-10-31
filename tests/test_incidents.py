from pathlib import Path
import tempfile
import unittest
from companion.health import Observation
from companion.incidents import IncidentStore


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'state.sqlite3'
        self.store = IncidentStore(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def observe(self, healthy, category=None):
        self.store.observe(Observation('site', healthy, category or ('healthy' if healthy else 'http-failure'), 200 if healthy else 503, 10), now=100)

    def test_transient_failure_is_quiet(self):
        self.observe(False)
        self.observe(True)
        self.assertEqual(self.store.pending(100), [])

    def test_initial_health_is_quiet(self):
        self.observe(True)
        self.observe(True)
        self.assertEqual(self.store.pending(100), [])

    def test_failed_delivery_survives_restart(self):
        self.observe(False)
        self.observe(False)
        event = self.store.pending(100)[0]
        self.store.failed(event[0], now=100)
        self.store.close()
        self.store = IncidentStore(self.path)
        self.assertEqual(self.store.pending(129), [])
        self.assertEqual(self.store.pending(130)[0][0], event[0])
        self.store.delivered(event[0])
        self.assertEqual(self.store.pending(200), [])

    def test_unchanged_outage_does_not_repeat(self):
        for _ in range(5):
            self.observe(False)
        self.assertEqual(len(self.store.pending(100)), 1)

    def test_recovery_and_certificate_warning_are_separate(self):
        self.observe(False)
        self.observe(False)
        self.observe(True)
        self.observe(True)
        self.observe(True, 'certificate-expiring')
        self.observe(True, 'certificate-expiring')
        self.assertEqual([event[2] for event in self.store.pending(100)], ['down', 'healthy', 'warning'])


if __name__ == '__main__':
    unittest.main()
