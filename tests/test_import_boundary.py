import unittest
from companion.import_worker import restricted_grants


class ImportBoundaryTests(unittest.TestCase):
    def test_native_explicit_database_privileges_are_accepted(self):
        self.assertTrue(restricted_grants(['GRANT USAGE ON *.* TO `stage`@`%`',
            'GRANT SELECT, INSERT, UPDATE, CREATE, DROP ON `stage`.* TO `stage`@`%`'], 'stage'))

    def test_global_and_other_database_privileges_are_rejected(self):
        own = 'GRANT ALL PRIVILEGES ON `stage`.* TO `stage`@`%`'
        for extra in ('GRANT FILE ON *.* TO `stage`@`%`',
                      'GRANT ALL PRIVILEGES ON `live`.* TO `stage`@`%`',
                      'GRANT `administrator` TO `stage`@`%`'):
            with self.subTest(extra=extra):
                self.assertFalse(restricted_grants([own, extra], 'stage'))

    def test_usage_without_database_access_is_rejected(self):
        self.assertFalse(restricted_grants(['GRANT USAGE ON *.* TO `stage`@`%`'], 'stage'))
