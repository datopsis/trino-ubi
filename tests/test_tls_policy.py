import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts'))
import tls_policy
from tls_runtime import is_loopback_socket, properties, protocol_rejection, validate_config


class TLSPolicyTests(unittest.TestCase):
    def test_executable_sources_have_no_verification_downgrades(self):
        tls_policy.check_repository(ROOT)

    def test_ipv4_and_mapped_ipv6_loopback_sockets(self):
        self.assertTrue(is_loopback_socket('0100007F'))
        self.assertTrue(is_loopback_socket('0000000000000000FFFF00000100007F'))
        self.assertTrue(is_loopback_socket('00000000000000000000000001000000'))
        self.assertFalse(is_loopback_socket('00000000'))
        self.assertFalse(is_loopback_socket('00000000000000000000000000000000'))
        self.assertFalse(is_loopback_socket('0100000A'))

    def test_plaintext_protocol_rejection(self):
        self.assertTrue(protocol_rejection(bytes.fromhex('15030300020250')))
        self.assertTrue(protocol_rejection(b'HTTP/1.1 400 Bad Request'))
        self.assertFalse(protocol_rejection(b'HTTP/1.1 200 OK'))
        self.assertFalse(protocol_rejection(b'HTTP/1.1 302 Found'))
        self.assertFalse(protocol_rejection(b'HTTP/1.1 403 Forbidden'))
        self.assertFalse(protocol_rejection(bytes.fromhex('17030300020250')))

    def test_deny_variants(self):
        for value in ('verify=False', 'verify: false', 'VERIFY="false"', '--insecure', 'curl x -k',
                      'ssl.CERT_NONE', 'check_hostname = False', 'InsecureSkipVerify=true',
                      'insecure_skip_verify=true', 'danger_accept_invalid_certs',
                      'danger_accept_invalid_hostnames', 'AWS_ALLOW_INVALID_CERTIFICATES=true',
                      'proxy_ssl_verify off', 'grpc_ssl_verify off', 'sslmode=verify-ca',
                      'sslmode=require', 'sslmode=disable', 'AWS_ALLOW_HTTP=true',
                      'TrustAll', 'NoopHostnameVerifier'):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                tls_policy.check_text(value)

    def test_rendered_config_requires_tls_and_explicit_stores(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'catalog').mkdir()
            fields = {'http-server.http.enabled': 'false', 'http-server.https.enabled': 'true',
                      'internal-communication.https.required': 'true', 'discovery.uri': 'https://trino:8443',
                      'internal-communication.https.keystore.path': '/run/tls/server.pem',
                      'internal-communication.https.truststore.path': '/run/tls/ca.crt'}
            def write():
                (root / 'config.properties').write_text(''.join(f'{k}={v}\n' for k, v in fields.items()))
            write()
            (root / 'truststore.properties').write_text('type=PKCS12\n')
            validate_config(root)
            for key, bad in [('http-server.http.enabled', 'true'), ('discovery.uri', 'http://trino:8080'),
                             ('internal-communication.https.truststore.path', '')]:
                previous = fields[key]; fields[key] = bad; write()
                with self.subTest(key=key), self.assertRaises(AssertionError):
                    validate_config(root)
                fields[key] = previous
            write()
            with (root / 'config.properties').open('a') as stream:
                stream.write('http-server.http.enabled=true\n')
            with self.assertRaises(AssertionError):
                properties(root / 'config.properties')
