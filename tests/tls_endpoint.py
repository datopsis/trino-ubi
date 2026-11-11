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


class InternalRelay:
    """TLS on both sides, to mutate only the actual self-worker connection.

    Opaque HTTP/2 bytes are forwarded after TLS termination. No application data
    is parsed, retained or logged; the upstream always verifies Trino's run CA.
    """
    def __init__(self, pki):
        import socket
        self.pki = pki
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.2', 8443))
        self.listener.listen()
        self.listener.settimeout(1)
        self.stopping = False
        self.connections = []
        self.select('valid')
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def select(self, variant):
        for connection in self.connections:
            connection.close()
        self.connections.clear()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['h2', 'http/1.1'])
        prefix = self.pki / f'trino-{variant}'
        context.load_cert_chain(str(prefix) + '.crt', str(prefix) + '.key')
        self.context = context

    def serve(self):
        import socket
        while not self.stopping:
            try:
                connection, _ = self.listener.accept()
                threading.Thread(target=self.forward, args=(connection,), daemon=True).start()
            except (TimeoutError, OSError):
                if self.stopping:
                    return

    def forward(self, connection):
        import select
        import socket
        incoming = upstream = None
        try:
            connection.settimeout(10)
            incoming = self.context.wrap_socket(connection, server_side=True)
            context = ssl.create_default_context(cafile=self.pki / 'ca.crt')
            context.set_alpn_protocols([incoming.selected_alpn_protocol() or 'http/1.1'])
            upstream = context.wrap_socket(socket.create_connection(('127.0.0.1', 8443), timeout=10), server_hostname='trino')
            self.connections.extend((incoming, upstream))
            # A single thread owns both SSL objects: concurrent SSL_read and
            # SSL_write on one object can corrupt TLS 1.3 record state.
            while not self.stopping:
                readable, _, _ = select.select([incoming, upstream], [], [], 1)
                for source, destination in ((incoming, upstream), (upstream, incoming)):
                    if source in readable or source.pending():
                        chunk = source.recv(65536)
                        if not chunk:
                            return
                        destination.sendall(chunk)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            for stream in (incoming, upstream, connection):
                if stream is not None:
                    stream.close()

    def close(self):
        self.stopping = True
        self.listener.close()
        for connection in self.connections:
            connection.close()
        self.thread.join(timeout=2)
