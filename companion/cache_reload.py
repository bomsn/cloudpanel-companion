"""Reload through fresh authenticated revisions, never an old startup VCL."""
import http.client
from pathlib import Path
from .monitor import private_json


def main():
    config = private_json(Path('/etc/cloudpanel-companion/cache-sites.json'))
    for site in config['sites']:
        connection = http.client.HTTPConnection('127.0.0.1', 6083, timeout=15)
        try:
            connection.request('PURGE', '/', headers={'Host': site['host'],
                'X-Cache-Manager-For-CloudPanel-Key': site['purge_key']})
            response = connection.getresponse()
            if response.status != 200 or response.getheader('X-Cache-Manager-For-CloudPanel-Policy') != 'site-revision-v1':
                raise RuntimeError('Cache reload failed; affected site remains bypassed')
            response.read()
        finally:
            connection.close()


if __name__ == '__main__':
    main()
