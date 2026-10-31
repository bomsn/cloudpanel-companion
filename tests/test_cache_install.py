import importlib.util
import unittest
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'install-cache.py'


def load():
    spec = importlib.util.spec_from_file_location('install_cache', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CacheInstallTests(unittest.TestCase):
    def test_first_install_does_not_reset_units_that_never_failed(self):
        # A fresh server has no loaded cache-manager-control unit; resetting it failed setup.
        installer = load()
        states = {'varnish.service': 1, 'cache-manager-control.service': 0}
        checked = lambda arguments, **kwargs: mock.Mock(returncode=states[arguments[-1]])
        with mock.patch.object(installer.subprocess, 'run', side_effect=checked), \
                mock.patch.object(installer, 'run') as executed:
            installer.clear_failed('varnish.service', 'cache-manager-control.service')
        executed.assert_called_once_with(['systemctl', 'reset-failed', 'cache-manager-control.service'])


if __name__ == '__main__':
    unittest.main()
