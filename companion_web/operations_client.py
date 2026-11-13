"""Call the local allowlisted operations service without shell privileges."""
import json
import socket
from django.conf import settings


def call(operation, **values):
    path = settings.CONFIG.get('operations_socket')
    if not path:
        raise ValueError('Operations service is not configured')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(40)
        connection.connect(path)
        connection.sendall(json.dumps({'site': settings.CONFIG['operations_site'],
                                      'operation': operation, **values}).encode() + b'\n')
        with connection.makefile('rb') as stream:
            raw = stream.readline(4194305)
    if len(raw) > 4194304 or not raw.endswith(b'\n'):
        raise ValueError('Invalid operations response')
    response = json.loads(raw)
    if not response.get('ok'):
        raise ValueError(response.get('error', 'Operation failed'))
    return response['result']
