import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts'))
import tls_policy
from tls_runtime import properties, validate_config


class TLSPolicyTests(unittest.TestCase):
    def test_executable_sources_have_no_verification_downgrades(self):
        tls_policy.check_repository(ROOT)

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
