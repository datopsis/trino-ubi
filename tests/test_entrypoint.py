"""Exercise the actual Bash guard in a temporary filesystem, without Java/images."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.geteuid() == 0, 'guard tests require an unprivileged test runner')
class GuardTests(unittest.TestCase):
    def test_profiles_and_required_jwt_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            etc = root / 'etc'
            etc.mkdir()
            for name in ('data', 'tmp'):
                (root / name).mkdir()
            for name in ('tls.pem', 'public.pem', 'passwords'):
                (etc / name).write_text('guard fixture, not cryptographic material\n')
                (etc / name).chmod(0o440)
            (etc / 'node.properties').write_text('node.data-dir=/var/lib/trino\nnode.id=test\nnode.environment=test\nnode.internal-address=127.0.0.1\n')
            (etc / 'log.properties').touch()
            (etc / 'password-authenticator.properties').write_text(
                f'password-authenticator.name=file\nfile.password-file={etc}/passwords\n')
            for name in ('node.properties', 'password-authenticator.properties'):
                (etc / name).chmod(0o440)
            script = (ROOT / 'container/entrypoint.sh').read_text()
            # Relocate only filesystem constants and replace Java with a harmless
            # executable. All property parsing and authentication guards run intact.
            script = script.replace('/etc/trino', str(etc)).replace('/var/lib/trino', str(root / 'data'))
            script = script.replace('/tmp/trino', str(root / 'tmp')).replace('/opt/java/bin/java', '/bin/true')
            (etc / 'node.properties').chmod(0o640)
            (etc / 'node.properties').write_text(
                f'node.data-dir={root}/data\nnode.id=test\nnode.environment=test\nnode.internal-address=127.0.0.1\n')
            (etc / 'node.properties').chmod(0o440)
            values = {
                'coordinator': 'true', 'node-scheduler.include-coordinator': 'true',
                'http-server.authentication.type': 'JWT', 'http-server.http.enabled': 'false',
                'http-server.https.enabled': 'true', 'http-server.https.port': '8443',
                'http-server.https.keystore.path': str(etc / 'tls.pem'),
                'internal-communication.https.required': 'true',
                'internal-communication.https.keystore.path': str(etc / 'tls.pem'),
                'internal-communication.https.truststore.path': str(etc / 'public.pem'),
                'internal-communication.shared-secret': 'unit-fixture',
                'discovery.uri': 'https://127.0.0.1:8443',
                'http-server.authentication.jwt.key-file': 'https://issuer.invalid/jwks',
                'http-server.authentication.jwt.required-issuer': 'https://issuer.invalid',
                'http-server.authentication.jwt.required-audience': 'trino',
                'http-server.authentication.jwt.principal-field': 'sub',
            }

            def run(config, insecure='false'):
                path = etc / 'config.properties'
                if path.exists():
                    path.chmod(0o640)
                path.write_text(''.join(f'{k}={v}\n' for k, v in config.items()))
                path.chmod(0o440)
                environment = {k: v for k, v in os.environ.items()
                               if k not in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS')}
                environment['TRINO_UBI_ALLOW_INSECURE'] = insecure
                return subprocess.run(['bash', '-c', script], env=environment, capture_output=True, text=True)

            for profile in ('PASSWORD', 'JWT'):
                result = run(values | {'http-server.authentication.type': profile})
                self.assertEqual(result.returncode, 0, result.stderr)
            result = run(values | {'http-server.authentication.jwt.key-file': str(etc / 'public.pem')})
            self.assertEqual(result.returncode, 0, result.stderr)
            for key in values:
                if key in ('coordinator', 'node-scheduler.include-coordinator', 'http-server.authentication.type'):
                    continue
                for insecure in ('false', 'true'):
                    with self.subTest(missing=key, insecure=insecure):
                        result = run({k: v for k, v in values.items() if k != key}, insecure)
                        self.assertNotEqual(result.returncode, 0, result.stderr)
                        self.assertIn('trino-entrypoint:', result.stderr)
            for key_source in ('', 'http://issuer.invalid/jwks', 'https://', 'relative.pem',
                               'https://user:pass@issuer.invalid/jwks', 'https://issuer.invalid/#fragment'):
                result = run(values | {'http-server.authentication.jwt.key-file': key_source})
                self.assertNotEqual(result.returncode, 0, key_source)
            for profile in ('JWT,PASSWORD', 'PASSWORD,JWT', 'jwt', 'Jwt', 'password,jwt'):
                result = run(values | {'http-server.authentication.type': profile}, 'true')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('mixed authentication', result.stderr)
