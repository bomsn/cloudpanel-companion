"""Run the registered PHP-worker check under its own website identity."""
import argparse
from .refresh import stop_staging_requests

parser = argparse.ArgumentParser()
parser.add_argument('--user', required=True)
parser.add_argument('--host', required=True)
parser.add_argument('--php', required=True)
args = parser.parse_args()
stop_staging_requests(args.user, args.host, args.php)
