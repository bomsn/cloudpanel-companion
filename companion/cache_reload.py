"""Reload through fresh authenticated revisions, never an old startup VCL."""
import http.client
from pathlib import Path
from .cache_config import CONTROL_PORT
from .cache_control import KEY_HEADER, POLICY_HEADER, SITE_REVISION
from .monitor import private_json


def main():
    config = private_json(Path('/etc/cloudpanel-companion/cache-sites.json'))
    for site in config['sites']:
        connection = http.client.HTTPConnection('127.0.0.1', CONTROL_PORT, timeout=15)
        try:
            connection.request('PURGE', '/', headers={'Host': site['host'], KEY_HEADER: site['purge_key']})
            response = connection.getresponse()
            if response.status != 200 or response.getheader(POLICY_HEADER) != SITE_REVISION:
                raise RuntimeError('Cache reload failed; affected site remains bypassed')
            response.read()
        finally:
            connection.close()


if __name__ == '__main__':
    main()
