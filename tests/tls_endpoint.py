"""Minimal protocol fixtures: real Trino REST and S3 clients perform operations.

These servers are not Lakekeeper/SeaweedFS compatibility evidence. They retain
only allowlisted method/path observations, never Authorization or request bodies.
"""
import json
import ssl
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

METADATA = {
    'format-version': 2, 'table-uuid': str(uuid.uuid4()), 'location': 's3://bucket/table',
    'last-sequence-number': 0, 'last-updated-ms': 1700000000000, 'last-column-id': 1,
    'schemas': [{'type': 'struct', 'schema-id': 0, 'fields': [{'id': 1, 'name': 'id', 'required': False, 'type': 'long'}]}],
    'current-schema-id': 0, 'partition-specs': [{'spec-id': 0, 'fields': []}], 'default-spec-id': 0,
    'last-partition-id': 999, 'properties': {}, 'current-snapshot-id': -1, 'snapshots': [],
    'snapshot-log': [], 'metadata-log': [], 'sort-orders': [{'order-id': 0, 'fields': []}], 'default-sort-order-id': 0,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.respond()

    def do_HEAD(self):
        self.respond()

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.respond()

    def respond(self):
        server = self.server
        server.observations.append((self.command, self.path.split('?')[0], self.connection.version()))
        if server.role == 's3':
            assert self.headers.get('Authorization', '').startswith('AWS4-HMAC-SHA256 ')
            result = METADATA
        elif '/v1/config' in self.path:
            result = {'defaults': {}, 'overrides': {}}
        elif self.path.endswith('/namespaces'):
            result = {'namespaces': [['tls']]}
        elif self.path.endswith('/namespaces/tls'):
            result = {'namespace': ['tls'], 'properties': {'location': 's3://bucket/'}}
        elif self.path.endswith('/register'):
            result = {'metadata-location': 's3://bucket/table/metadata/v1.metadata.json', 'metadata': METADATA}
        else:
            self.send_error(404)
            return
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)


class Endpoint(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, role, pki):
        super().__init__(('127.0.0.1', 0), Handler)
        self.role, self.pki = role, pki
        self.observations = []
        self.select('valid')
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def select(self, variant):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        prefix = self.pki / f'{self.role}-{variant}'
        context.load_cert_chain(str(prefix) + '.crt', str(prefix) + '.key')
        self.context = context
        self.observations.clear()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except Exception:
            connection.close()
            raise

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join()
