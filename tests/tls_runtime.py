#!/usr/bin/env python3
"""Native image qualification; fresh JVMs and verified controls around mutations."""
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import runtime as rt
from tls_endpoint import Endpoint
from tls_pki import cleanup, prepare, protect

ROOT = rt.ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
from tls_policy import check_text
RESULTS = []
BASE = 'https://trino:8443'
TLS_ERRORS = {
    'wrong-ca': r'PKIX path building failed|unable to find valid certification path',
    'wrong-trust': r'PKIX path building failed|unable to find valid certification path',
    'wrong-san': r'No subject alternative DNS name matching|Certificate for .* doesn.t match|No name matching',
    'other-service': r'No subject alternative DNS name matching|Certificate for .* doesn.t match|No name matching',
    'alias': r'No subject alternative DNS name matching|Certificate for .* doesn.t match|No name matching',
    'expired': r'CertificateExpiredException|validity check failed|NotAfter:',
}
ORIGINAL_RESOLVE = socket.getaddrinfo


def resolve(host, *args, **kwargs):
    # DNS mapping only: SSL still verifies the original URL hostname and SAN.
    return ORIGINAL_RESOLVE('127.0.0.1' if host in ('trino', 'alias') else host, *args, **kwargs)


def record(edge, case, outcome):
    RESULTS.append({'edge': edge, 'case': case, 'outcome': outcome})
    print(f'PASS {edge}: {case}: {outcome}', flush=True)


def properties(path):
    result = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, value = line.split('=', 1)
        assert key not in result and key == key.strip() and value == value.strip()
        result[key] = value
    return result


def validate_config(cfg):
    """Parse rendered settings, not just a substring check of templates."""
    for path in cfg.rglob('*.properties'):
        check_text(path.read_text())
    conf = properties(cfg / 'config.properties')
    assert conf['http-server.http.enabled'] == 'false'
    assert conf['http-server.https.enabled'] == 'true'
    assert conf['internal-communication.https.required'] == 'true'
    assert conf['discovery.uri'].startswith('https://')
    assert conf['internal-communication.https.keystore.path']
    assert conf['internal-communication.https.truststore.path']
    for path in (cfg / 'catalog').glob('*.properties'):
        catalog = properties(path)
        for key in ('iceberg.rest-catalog.uri', 's3.endpoint'):
            if key in catalog:
                assert catalog[key].startswith('https://')
        if catalog.get('connector.name') == 'iceberg':
            assert catalog['iceberg.rest-catalog.vended-credentials-enabled'] == 'false'
    assert properties(cfg / 'truststore.properties')['type'] == 'PKCS12'


class Rehearsal:
    def __init__(self, root):
        self.root = root
        self.pki = root / 'authority'
        self.inventory = prepare(self.pki)
        self.password = secrets.token_hex(24)
        self.shared = secrets.token_hex(48)
        self.access = secrets.token_hex(16)
        self.secret = secrets.token_hex(32)
        self.context = ssl.create_default_context(cafile=self.pki / 'ca.crt')
        assert self.context.check_hostname and self.context.verify_mode == ssl.CERT_REQUIRED
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
        self.rest, self.s3 = Endpoint('catalog', self.pki), Endpoint('s3', self.pki)
        self.name = None
        # Build truststores with the image's keytool, no compiler/tool dependency.
        for ca in ('ca', 'unrelated'):
            folder = root / ca
            folder.mkdir(mode=0o777)
            folder.chmod(0o777)
            shutil.copyfile(self.pki / f'{ca}.crt', folder / 'ca.crt')
            (folder / 'password').write_text(self.password + '\n')
            (folder / 'password').chmod(0o444)
            (folder / 'ca.crt').chmod(0o444)
            rt.command('run', '--rm', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                       '--network=none', '--entrypoint=/opt/java/bin/keytool', '-v', f'{folder}:/work:rw', rt.IMAGE,
                       '-importcert', '-noprompt', '-alias', 'run-ca', '-file', '/work/ca.crt',
                       '-keystore', '/work/trust.p12', '-storetype', 'PKCS12', '-storepass:file', '/work/password')
            folder.chmod(0o755)

    def stop(self):
        if self.name:
            rt.command('rm', '-f', self.name, check=False)
            self.name = None

    def start(self, variant='valid', edge='inbound', defect=None, extra=(), login_exception=True, mounts=True, native_tmp=True):
        self.stop()
        self.rest.select(variant if edge == 'REST' and variant not in ('alias', 'wrong-trust') else 'valid')
        self.s3.select(variant if edge == 'S3' and variant not in ('alias', 'wrong-trust') else 'valid')
        if edge == 'S3' and variant == 'wrong-trust':
            self.rest.select('wrong-ca')  # Keep REST valid under the alternate JVM trust root.
        run = self.root / secrets.token_hex(8)
        run.mkdir(mode=0o755)
        cfg = rt.config_copy(run / 'config')
        material = run / 'tls'; material.mkdir()
        leaf = variant if edge in ('inbound', 'internal') and variant not in ('wrong-trust', 'alias') else 'valid'
        shutil.copyfile(self.pki / f'trino-{leaf}.pem', material / 'server.pem')
        trust = 'unrelated' if variant == 'wrong-trust' and edge in ('REST', 'S3') else 'ca'
        shutil.copyfile(self.root / trust / 'trust.p12', material / 'trust.p12')
        shutil.copyfile(self.pki / ('unrelated.crt' if edge == 'internal' and variant == 'wrong-trust' else 'ca.crt'), material / 'internal-ca.pem')
        (material / 'password').write_text(self.password + '\n')
        address = 'alias' if edge == 'internal' and variant == 'alias' else 'trino'
        (cfg / 'node.properties').write_text(
            'node.environment=testing\nnode.id=single-node\nnode.data-dir=/var/lib/trino\n' + f'node.internal-address={address}\n')
        (cfg / 'config.properties').write_text(
            'coordinator=true\nnode-scheduler.include-coordinator=true\n'
            'http-server.http.enabled=false\nhttp-server.https.enabled=true\nhttp-server.https.port=8443\n'
            'http-server.https.keystore.path=/run/tls/server.pem\n'
            'internal-communication.https.required=true\n'
            'internal-communication.https.keystore.path=/run/tls/server.pem\n'
            'internal-communication.https.truststore.path=/run/tls/internal-ca.pem\n'
            f'internal-communication.shared-secret={self.shared}\ndiscovery.uri=https://{address}:8443\n'
            'query.max-memory=256MB\nquery.max-memory-per-node=256MB\nmemory.heap-headroom-per-node=256MB\n'
            'http-server.log.enabled=false\n')
        (cfg / 'truststore.properties').write_text('path=/run/tls/trust.p12\ntype=PKCS12\npassword-file=/run/tls/password\n')
        if edge in ('REST', 'S3'):
            rest_host = 'alias' if edge == 'REST' and variant == 'alias' else 'catalog'
            s3_host = 'alias' if edge == 'S3' and variant == 'alias' else 's3'
            (cfg / 'catalog/iceberg.properties').write_text(
                'connector.name=iceberg\niceberg.catalog.type=rest\n'
                f'iceberg.rest-catalog.uri=https://{rest_host}:{self.rest.server_port}\n'
                'iceberg.rest-catalog.vended-credentials-enabled=false\n'
                'iceberg.register-table-procedure.enabled=true\nfs.s3.enabled=true\n'
                f's3.endpoint=https://{s3_host}:{self.s3.server_port}\ns3.region=us-east-1\n'
                's3.path-style-access=true\ns3.max-error-retries=1\n'
                f's3.aws-access-key={self.access}\ns3.aws-secret-key={self.secret}\n')
        validate_config(cfg)
        if defect:
            defect(cfg, material)
        protect(cfg); protect(material)
        self.name = 'trino-tls-' + secrets.token_hex(6)
        args = ['run', '-d', '--name', self.name, '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--pids-limit=512', '--memory=3g', '--network=host',
                '--tmpfs', '/tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=256m',
                '--tmpfs', '/var/lib/trino:rw,noexec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=512m',
                '-v', f'{cfg}:/etc/trino:ro', '-v', f'{material}:/run/tls:ro',
                '-e', 'TRINO_UBI_ALLOW_INSECURE=true']
        for host in ('trino', 'catalog', 's3', 'alias'):
            args += ['--add-host', host + ':127.0.0.1']
        if not login_exception:
            index = args.index('TRINO_UBI_ALLOW_INSECURE=true')
            del args[index - 1:index + 1]
        if not mounts:
            index = args.index('/var/lib/trino:rw,noexec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=512m')
            del args[index - 1:index + 1]
        if not native_tmp:
            index = args.index('/tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=256m')
            del args[index - 1:index + 1]
        rt.command(*args, *extra, rt.IMAGE)
        return self.name

    def positive(self, edge):
        name = self.start(edge=edge)
        rt.ready(name, BASE, self.context)
        if edge in ('inbound', 'internal'):
            assert rt.query(BASE, 'SELECT version()', self.context) == [[rt.LOCK['trino']['version']]]
            assert rt.query(BASE, 'SELECT count(*) FROM tpch.tiny.nation', self.context) == [[25]]
            assert rt.query(BASE, "SELECT count(*) FROM system.runtime.nodes WHERE state = 'active'", self.context) == [[1]]
        else:
            self.operation(edge)
        self.plaintext()
        return name

    def operation(self, edge):
        if edge == 'REST':
            rows = rt.query(BASE, 'SHOW SCHEMAS FROM iceberg', self.context)
            assert ['tls'] in rows, rows
            assert any(path == '/v1/namespaces' for _, path, _ in self.rest.observations)
        else:
            rt.query(BASE, "CALL iceberg.system.register_table(schema_name => 'tls', table_name => 'probe', table_location => 's3://bucket/table', metadata_file_name => 'v1.metadata.json')", self.context)
            assert any(method == 'GET' and path == '/bucket/table/metadata/v1.metadata.json' for method, path, _ in self.s3.observations)
        for _, _, version in self.rest.observations + self.s3.observations:
            assert version in ('TLSv1.2', 'TLSv1.3')

    def plaintext(self):
        # Both address families, legacy and effective ports; protocol errors only.
        for host in ('127.0.0.1', '::1'):
            for port in (8080, 8443):
                try:
                    with socket.create_connection((host, port), timeout=2) as sock:
                        sock.sendall(b'GET /v1/info HTTP/1.1\r\nHost: trino\r\nConnection: close\r\n\r\n')
                        response = sock.recv(4096)
                    assert port == 8443 and (not response or response.startswith(b'HTTP/1.1 400')), f'plaintext response on {host}:{port}: {response[:160]!r}'
                    assert b'nodeVersion' not in response and b'Location:' not in response
                except (ConnectionRefusedError, ConnectionResetError):
                    pass
        # Inspect the JVM's own socket inodes; host-network test endpoints aren't Trino listeners.
        script = 'for f in /proc/1/fd/*; do readlink "$f" || :; done'
        descriptors = rt.command('exec', self.name, '/bin/bash', '-c', script).stdout
        ports = set()
        for family in ('tcp', 'tcp6'):
            for line in rt.command('exec', self.name, 'cat', '/proc/1/net/' + family).stdout.splitlines()[1:]:
                parts = line.split()
                if parts[3] == '0A' and f'socket:[{parts[9]}]' in descriptors:
                    ports.add(int(parts[1].split(':')[1], 16))
        assert ports == {8443}, ports

    def inbound_negative(self, variant):
        self.start(variant)
        context = ssl.create_default_context(cafile=self.pki / ('unrelated.crt' if variant == 'wrong-trust' else 'ca.crt'))
        base = 'https://alias:8443' if variant == 'alias' else BASE
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                rt.request(base + '/v1/info', context=context)
            except urllib.error.URLError as error:
                if isinstance(error.reason, ssl.SSLCertVerificationError):
                    reason = error.reason.verify_message
                    expected = {'wrong-ca': 'issuer', 'wrong-trust': 'issuer', 'expired': 'expired'}.get(variant, 'mismatch')
                    assert expected in reason.lower(), reason
                    return reason
                if not isinstance(error.reason, ConnectionRefusedError):
                    raise
            else:
                raise AssertionError('invalid certificate accepted by inbound client')
            time.sleep(1)
        raise AssertionError('no TLS-specific inbound failure')

    def negative(self, edge, variant):
        if edge == 'inbound':
            return self.inbound_negative(variant)
        name = self.start(variant, edge)
        if edge != 'internal':
            rt.ready(name, BASE, self.context)
            try:
                self.operation(edge)
            except AssertionError as error:
                diagnostic = str(error) + rt.logs(name)
                match = re.search(TLS_ERRORS[variant], diagnostic, re.I)
                assert match, 'operation failed without the required TLS diagnostic'
                # No application operation reached the mutated endpoint.
                assert not (self.rest if edge == 'REST' else self.s3).observations
                return match.group(0)
            raise AssertionError(f'{edge} accepted {variant}')
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            output = rt.logs(name)
            match = re.search(TLS_ERRORS[variant], output, re.I)
            if match and ('Announcer' in output or 'Discovery' in output):
                return match.group(0)
            state = json.loads(rt.command('inspect', name).stdout)[0]['State']
            assert state['Running'], 'internal mutation caused startup failure rather than client TLS rejection'
            time.sleep(1)
        raise AssertionError('internal client has no TLS-specific rejection')

    def fail_closed(self):
        def append(text):
            def mutate(cfg, _material):
                with (cfg / 'config.properties').open('a') as stream:
                    stream.write(text)
            return mutate
        cases = [
            ('authentication required', {'login_exception': False}),
            ('/var/lib/trino', {'mounts': False}),
            ('/tmp/trino', {'native_tmp': False}),
            ('refusing root', {'extra': ['--user', '0:0']}),
            ('must be true or false', {'extra': ['-e', 'TRINO_UBI_ALLOW_INSECURE=yes']}),
            ('unprivileged port', {'defect': append('http-server.http.port=443\n')}),
            ('duplicate property', {'defect': append('http-server.https.port=8443\n')}),
            ('unsupported escape', {'defect': append('test=bad\\escape\n')}),
            ('not-a-trino-property', {'defect': append('not-a-trino-property=true\n')}),
        ]
        for variable in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS'):
            cases.append(('Java option environment overrides', {'extra': ['-e', variable + '=-version']}))
        for filename in ('server.pem', 'internal-ca.pem', 'trust.p12', 'password'):
            cases.append(('secret file', {'defect': lambda _cfg, material, f=filename: (material / f).unlink()}))
        cases.append(('invalid PKCS12', {'defect': lambda _cfg, material: (material / 'trust.p12').write_text('malformed')}))
        cases.append(('requires only path', {'defect': lambda cfg, _material: (cfg / 'truststore.properties').write_text('path=/run/tls/trust.p12\ntype=PKCS12\npassword-file=/run/tls/password\nextra=-version\n')}))
        for diagnostic, options in cases:
            name = self.start(**options)
            rt.wait_exit(name, diagnostic)
            for port in (8080, 8443):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=2):
                        raise AssertionError('failed startup left a listener')
                except ConnectionRefusedError:
                    pass
            record('guard', diagnostic, 'nonzero startup exit and no HTTP/HTTPS fallback')
        name = self.positive('internal')
        rt.command('stop', '--time', '30', name)
        assert json.loads(rt.command('inspect', name).stdout)[0]['State']['ExitCode'] in (0, 143)
        record('runtime', 'shutdown', 'SIGTERM without SIGKILL')

    def close(self):
        self.stop()
        self.rest.close(); self.s3.close()


def main():
    os.umask(0o077)
    socket.getaddrinfo = resolve
    root = ROOT / '.runtime' / ('tls-' + secrets.token_hex(6))
    root.mkdir(parents=True, mode=0o755)
    root.chmod(0o755); root.parent.chmod(0o755)
    rehearsal = None
    report = {'architecture': os.environ.get('ARCHITECTURE', 'local'), 'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(), 'results': RESULTS}
    try:
        rehearsal = Rehearsal(root)
        report['certificates'] = rehearsal.inventory
        for edge in ('inbound', 'internal', 'REST', 'S3'):
            for variant in ('wrong-ca', 'wrong-trust', 'wrong-san', 'other-service', 'alias', 'expired'):
                rehearsal.positive(edge)
                outcome = rehearsal.negative(edge, variant)
                rehearsal.positive(edge)
                record(edge, variant, outcome + '; valid operation before and after')
            record(edge, 'plaintext', '8080 refused; 8443 protocol rejection; IPv4/IPv6; only JVM listener 8443')
        rt.inspect_security(rehearsal.name)
        record('runtime', 'hardening', 'restricted runtime properties preserved')
        rehearsal.fail_closed()
        report['complete'] = True
    except Exception as error:
        report['complete'] = False
        report['failure'] = type(error).__name__
        report['failure_detail'] = str(error) if rehearsal else 'fixture preparation failed'
        if rehearsal:
            for secret in (rehearsal.password, rehearsal.shared, rehearsal.access, rehearsal.secret):
                report['failure_detail'] = report['failure_detail'].replace(secret, '[REDACTED]')
            report['failure_detail'] = report['failure_detail'][:3000]
        # Raw diagnostics are runner-local, never part of an uploaded report.
        diagnostics = ROOT / '.runtime/diagnostics'
        diagnostics.mkdir(exist_ok=True, mode=0o700)
        (diagnostics / 'failure.txt').write_text(str(error))
        if rehearsal and rehearsal.name:
            (diagnostics / 'server.log').write_text(rt.logs(rehearsal.name))
        raise RuntimeError('TLS qualification failed; raw diagnostics retained only in .runtime/diagnostics') from None
    finally:
        if rehearsal:
            rehearsal.close()
        cleanup(root)
        socket.getaddrinfo = ORIGINAL_RESOLVE
        (ROOT / 'reports').mkdir(exist_ok=True)
        text = json.dumps(report, indent=2) + '\n'
        assert 'PRIVATE KEY' not in text
        (ROOT / 'reports/tls.json').write_text(text)


if __name__ == '__main__':
    main()
