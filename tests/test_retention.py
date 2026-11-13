import unittest
from pathlib import Path
from companion.retention import job_created, plan, sha


class RetentionTests(unittest.TestCase):
    def records(self):
        result = []
        for number in range(5):
            old = 'stager' + f'{number:012x}'
            new = 'stager' + f'{number+1:012x}'
            result.append({'state': Path('/private') / str(number), 'created': number, 'database': new,
                           'receipt': {'phase': 'completed', 'old_database_identity': sha(old),
                                       'new_database_identity': sha(new),
                                       'recovery_generation': '/home/stage/.companion-generations/.companion-clone-' + f'{number:024x}'}})
        return result

    def test_keeps_latest_versions_and_current_database(self):
        records = self.records()
        result = plan(records, sha('stager000000000005'), 'stager000000000000', 'stage')
        self.assertEqual([item['database'] for item in result], ['stager000000000002', 'stager000000000001', 'stager000000000000'])

    def test_current_and_unfinished_database_are_never_removed(self):
        records = self.records()
        records.append({'state': Path('/private/running'), 'created': 6, 'database': None,
                        'receipt': {'phase': 'generation-prepared', 'old_database_identity': sha('stager000000000001')}})
        result = plan(records, sha('stager000000000002'), 'stager000000000000', 'stage')
        self.assertEqual([item['database'] for item in result], ['stager000000000000'])

    def test_editable_or_unregistered_database_cannot_authorize_deletion(self):
        records = self.records()
        records[0]['database'] = 'production'
        with self.assertRaises(ValueError):
            plan(records, sha('current'), 'stagebase', 'stage')

    def test_generation_outside_staging_recovery_directory_is_refused(self):
        records = self.records()
        records[0]['receipt']['recovery_generation'] = '/home/live/htdocs/production'
        with self.assertRaises(ValueError):
            plan(records, sha('current'), 'stagebase', 'stage')


    def test_creation_order_comes_from_the_job_name(self):
        self.assertEqual(job_created('/jobs/gui/shop/1793302884384679828-9b3b1e123c7cce1b'), 1793302884384679828)
        self.assertEqual(job_created('/jobs/refresh-acceptance-1793287322572064328'), 1793287322572064328)
        # Unknown names are treated as newest, so they are protected, not retired.
        records = self.records()
        records.append({'state': Path('/private/manual'), 'created': job_created('/private/manual'),
                        'database': 'stager000000000009',
                        'receipt': {'phase': 'completed', 'old_database_identity': sha('stager000000000008'),
                                    'new_database_identity': sha('stager000000000009'),
                                    'recovery_generation': '/home/stage/.companion-generations/.companion-clone-' + 'f' * 24}})
        result = plan(records, sha('stager000000000009'), 'stager000000000000', 'stage')
        self.assertNotIn('stager000000000008', [item['database'] for item in result])

    def test_service_can_run_native_database_retirement(self):
        # clpctl db:delete uses sudo and removal uses runuser; NoNewPrivileges
        # blocks both, so every scheduled retirement would fail.
        root = Path(__file__).resolve().parents[1]
        unit = (root / 'assets' / 'companion-retention.service').read_text()
        self.assertIn("'clpctl', 'db:delete'", (root / 'companion' / 'retention.py').read_text())
        self.assertNotIn('NoNewPrivileges=yes', unit)

if __name__ == '__main__':
    unittest.main()
