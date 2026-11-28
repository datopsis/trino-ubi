"""Native JWT qualification with ephemeral RSA keys, CA and HTTPS JWKS stub.

Uses only Python's standard library and the runner's OpenSSL CLI. Never embeds
keys/tokens in the image, prints them, or disables certificate verification.
"""
import base64
import http.server
import json
import secrets
import ssl
import subprocess
import threading
import time
import urllib.error


def openssl(*args, data=None):
    return subprocess.run(['openssl', *map(str, args)], input=data,
                          capture_output=True, check=True).stdout


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def checks(r, temp):
    material = temp / 'jwt-material'
    material.mkdir()
    ca_key, ca = material / 'ca.key', material / 'ca.pem'
    key, cert = material / 'tls.key', material / 'tls.pem'
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=ephemeral-runtime-ca', '-keyout', ca_key, '-out', ca)
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
            '-keyout', key, '-out', material / 'tls.csr')
    extensions = material / 'extensions'
    extensions.write_text('subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1\n'
                          'extendedKeyUsage=serverAuth\n')
    openssl('x509', '-req', '-in', material / 'tls.csr', '-CA', ca, '-CAkey', ca_key,
            '-CAcreateserial', '-days', '1', '-extfile', extensions, '-out', cert)
    signing = material / 'signing.key'
    wrong = material / 'wrong.key'
    for target in (signing, wrong):
        openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', target)
    public = openssl('pkey', '-in', signing, '-pubout')
    modulus = openssl('rsa', '-in', signing, '-modulus', '-noout').decode().strip().split('=')[1]
    jwks = json.dumps({'keys': [{'kty': 'RSA', 'kid': 'runtime-key', 'use': 'sig', 'alg': 'RS256',
                                'n': b64(bytes.fromhex(modulus)), 'e': 'AQAB'}]}).encode()
    hits = []

    class JWKS(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/jwks':
                self.send_error(404)
                return
            hits.append(self.path)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(jwks)))
            self.end_headers()
            self.wfile.write(jwks)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), JWKS)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        cfg = r.config_copy(temp / 'jwt')
        (cfg / 'tls.pem').write_bytes(key.read_bytes() + cert.read_bytes() + ca.read_bytes())
        (cfg / 'ca.pem').write_bytes(ca.read_bytes())
        (cfg / 'public.pem').write_bytes(public)
        settings = dict(line.split('=', 1) for line in (cfg / 'config.properties').read_text().splitlines()
                        if line and not line.startswith('#'))
        settings.update({
            'http-server.authentication.type': 'JWT',
            'http-server.http.enabled': 'false',
            'http-server.https.enabled': 'true',
            'http-server.https.port': '8443',
            'http-server.https.keystore.path': '/etc/trino/tls.pem',
            'internal-communication.https.required': 'true',
            'internal-communication.shared-secret': secrets.token_hex(64),
            'discovery.uri': 'https://127.0.0.1:8443',
            'http-server.authentication.jwt.key-file': f'https://host.docker.internal:{server.server_port}/jwks',
            'http-server.authentication.jwt.required-issuer': 'https://rauthy.example.invalid/auth/v1',
            'http-server.authentication.jwt.required-audience': 'trino',
            'http-server.authentication.jwt.principal-field': 'preferred_username',
            'jwk.http-client.trust-store-path': '/etc/trino/ca.pem',
        })

        def write(values):
            path = cfg / 'config.properties'
            path.chmod(0o600)
            path.write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
            # Runner-owned, group 0, readable but not writable by the runtime UID.
            for file in cfg.iterdir():
                if file.is_file():
                    subprocess.run(['sudo', 'chgrp', '0', str(file)], check=True)
                    file.chmod(0o440)

        def start(values, insecure=False):
            write(values)
            return r.start(extra=['--add-host', 'host.docker.internal:host-gateway',
                                  '-v', f'{cfg}:/etc/trino:ro'], port=8443, insecure=insecure)

        name = start(settings)
        context = ssl.create_default_context(cafile=str(ca))
        base = r.endpoint(name, 8443, secure=True)
        r.ready(name, base, context)
        claims = {'sub': 'different-subject', 'preferred_username': 'runtime-test',
                  'iss': settings['http-server.authentication.jwt.required-issuer'],
                  'aud': 'trino', 'iat': int(time.time()), 'exp': int(time.time()) + 600}

        def token(changes=None, signing_key=signing, algorithm='RS256'):
            payload = claims | (changes or {})
            encoded = '.'.join(b64(json.dumps(part).encode()) for part in
                               ({'alg': algorithm, 'kid': 'runtime-key'}, payload))
            signature = openssl('dgst', '-sha256', '-sign', signing_key, data=encoded.encode()) if algorithm != 'none' else b''
            return encoded + '.' + b64(signature)

        def accepted(label):
            assert r.query(base, 'SELECT current_user', context=context, bearer=token()) == [['runtime-test']]
            print(f'PASS JWT {label}: valid token, configured principal and real SQL over verified TLS', flush=True)

        accepted('HTTPS JWKS')
        assert hits, 'Trino never fetched the HTTPS JWKS'
        cases = [('expired', token({'exp': int(time.time()) - 3600})),
                 ('wrong-audience', token({'aud': 'other'})),
                 ('wrong-issuer', token({'iss': 'https://wrong.example.invalid'})),
                 ('wrong-key', token(signing_key=wrong)),
                 ('alg=none', token(algorithm='none')),
                 ('missing-principal', token({'preferred_username': None})),
                 ('missing-token', None)]
        for label, bearer in cases:
            try:
                r.query(base, 'SELECT current_user', context=context, bearer=bearer)
            except urllib.error.HTTPError as error:
                assert error.code == 401, (label, error.code)
                assert error.headers.get('WWW-Authenticate', '').startswith('Bearer'), label
            else:
                raise AssertionError(f'JWT {label} unexpectedly accepted')
            print(f'PASS JWT {label}: 401', flush=True)
        r.command('stop', '--time', '30', name)

        # Change only the trust source; prove the absolute mounted PEM branch.
        local = settings | {'http-server.authentication.jwt.key-file': '/etc/trino/public.pem'}
        del local['jwk.http-client.trust-store-path']
        name = start(local)
        base = r.endpoint(name, 8443, secure=True)
        r.ready(name, base, context)
        accepted('mounted key')
        r.command('stop', '--time', '30', name)

        required = {
            'http-server.http.enabled': 'HTTPS enabled and HTTP disabled',
            'http-server.https.enabled': 'HTTPS enabled and HTTP disabled',
            'http-server.https.port': 'HTTPS port 8443',
            'http-server.https.keystore.path': 'secret file',
            'internal-communication.https.required': 'https.required=true',
            'internal-communication.shared-secret': 'shared-secret is required',
            'discovery.uri': 'HTTPS discovery.uri',
            'http-server.authentication.jwt.key-file': 'JWT key-file requires',
            'http-server.authentication.jwt.required-issuer': 'jwt.required-issuer',
            'http-server.authentication.jwt.required-audience': 'jwt.required-audience',
            'http-server.authentication.jwt.principal-field': 'jwt.principal-field',
        }
        for key, diagnostic in required.items():
            values = settings.copy()
            del values[key]
            r.wait_exit(start(values), diagnostic)
            print(f'PASS JWT missing setting: {key}', flush=True)
        invalid = [
            ('HTTP JWKS', {'http-server.authentication.jwt.key-file': 'http://host.docker.internal/jwks'}, 'JWT key-file'),
            ('empty HTTPS URL', {'http-server.authentication.jwt.key-file': 'https://'}, 'JWT key-file'),
            ('missing key file', {'http-server.authentication.jwt.key-file': '/etc/trino/absent.pem'}, 'secret file'),
            ('HTTP enabled', {'http-server.http.enabled': 'true'}, 'HTTPS enabled and HTTP disabled'),
            ('HTTPS disabled', {'http-server.https.enabled': 'false'}, 'HTTPS enabled and HTTP disabled'),
            ('insecure HTTP auth', {'http-server.authentication.allow-insecure-over-http': 'true'}, 'insecure HTTP authentication'),
            ('mixed authentication', {'http-server.authentication.type': 'JWT,PASSWORD'}, 'mixed authentication'),
            ('blank issuer', {'http-server.authentication.jwt.required-issuer': ' '}, 'jwt.required-issuer'),
            ('empty audience', {'http-server.authentication.jwt.required-audience': ''}, 'jwt.required-audience'),
            ('empty principal', {'http-server.authentication.jwt.principal-field': ''}, 'jwt.principal-field'),
        ]
        for label, change, diagnostic in invalid:
            # Opt-out cannot bypass any JWT guard.
            r.wait_exit(start(settings | change, insecure=True), diagnostic)
            print(f'PASS JWT invalid setting with insecure opt-out: {label}', flush=True)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=10)
        assert not worker.is_alive()
