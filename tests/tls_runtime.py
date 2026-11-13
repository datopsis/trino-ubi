#!/usr/bin/env python3
"""Native image qualification; fresh JVMs and verified controls around mutations."""
import ipaddress
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
from tls_endpoint import Endpoint, InternalRelay
from tls_pki import cleanup, prepare, protect

ROOT = rt.ROOT
sys.path.insert(0, str(ROOT / 'scripts'))
from tls_policy import check_text
RESULTS = []
BASE = 'https://trino:8443'
TLS_ERRORS = {
    'wrong-ca': r'PKIX path building failed|unable to find valid certification path',
    'wrong-trust': r'PKIX path building failed|unable to find valid certification path',
    'wrong-san': r'No subject alternative (?:DNS name|names) matching|Certificate for .*? doesn.t match|No name matching',
    'other-service': r'No subject alternative (?:DNS name|names) matching|Certificate for .*? doesn.t match|No name matching',
    'alias': r'No subject alternative (?:DNS name|names) matching|Certificate for .*? doesn.t match|No name matching',
    'expired': r'CertificateExpiredException|validity check failed|NotAfter:',
}
ORIGINAL_RESOLVE = socket.getaddrinfo


def resolve(host, *args, **kwargs):
    # DNS mapping only: SSL still verifies the original URL hostname and SAN.
    return ORIGINAL_RESOLVE('127.0.0.1' if host in ('trino', 'alias') else host, *args, **kwargs)


def record(edge, case, outcome):
    RESULTS.append({'edge': edge, 'case': case, 'outcome': outcome})
    print(f'PASS {edge}: {case}: {outcome}', flush=True)


def is_loopback_socket(encoded):
    # Linux procfs renders addresses as native-endian 32-bit words. The JVM
    # commonly represents an IPv4 bind using an IPv4-mapped IPv6 socket.
    packed = b''.join(int(encoded[i:i + 8], 16).to_bytes(4, sys.byteorder)
                      for i in range(0, len(encoded), 8))
    address = ipaddress.ip_address(packed)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_loopback


def protocol_rejection(response):
    # A TLS fatal alert is the TLS equivalent of HTTP 400, not application data.
    return (not response or response.startswith(b'HTTP/1.1 400 ') or
            response.startswith(b'HTTP/1.0 400 ') or
            (len(response) == 7 and response[:2] == b'\x15\x03' and response[3:6] == b'\x00\x02\x02'))


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
        self.versions = {'Iceberg REST': set(), 'native S3': set()}
        self.access = secrets.token_hex(16)
        self.secret = secrets.token_hex(32)
        self.context = ssl.create_default_context(cafile=self.pki / 'ca.crt')
        assert self.context.check_hostname and self.context.verify_mode == ssl.CERT_REQUIRED
        urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
        self.rest, self.s3 = Endpoint('catalog', self.pki), Endpoint('s3', self.pki)
        self.name = None
        self.relay = None
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

    def start(self, variant='valid', edge='inbound', defect=None, extra=(), login_exception=True, mounts=True, native_tmp=True, writable_config=False, public_key=False):
        self.stop()
        if self.relay:
            self.relay.close()
            self.relay = None
        if edge == 'self-worker':
            self.relay = InternalRelay(self.pki)
            self.relay.select(variant if variant not in ('alias', 'wrong-trust') else 'valid')
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
        shutil.copyfile(self.pki / ('unrelated.crt' if edge in ('internal', 'self-worker') and variant == 'wrong-trust' else 'ca.crt'), material / 'internal-ca.pem')
        (material / 'password').write_text(self.password + '\n')
        address = 'alias' if edge == 'self-worker' and variant == 'alias' else 'trino'
        (cfg / 'node.properties').write_text(
            'node.environment=testing\nnode.id=single-node\nnode.data-dir=/var/lib/trino\nnode.bind-ip=127.0.0.1\n' + f'node.internal-address={address}\n')
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
        if edge == 'internal':
            conf = cfg / 'config.properties'
            target = 'alias' if variant == 'alias' else '127.0.0.1'
            conf.write_text(conf.read_text().replace(f'discovery.uri=https://{address}:8443', f'discovery.uri=https://{target}:8443'))
        if edge == 'self-worker':
            # Real discovery bypasses the mutation relay. Self-worker requests
            # retain their advertised DNS name and go through the TLS relay.
            conf = cfg / 'config.properties'
            conf.write_text(conf.read_text().replace(f'discovery.uri=https://{address}:8443', 'discovery.uri=https://127.0.0.1:8443') +
                            'announcer.http-client.trust-store-path=/run/tls/discovery-ca.pem\nquery.remote-task.max-error-duration=5s\n')
            shutil.copyfile(self.pki / 'ca.crt', material / 'discovery-ca.pem')
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
        if edge in ('internal', 'self-worker'):
            client = 'announcer' if edge == 'internal' else 'scheduler'
            with (cfg / 'config.properties').open('a') as stream:
                stream.write(f'{client}.http-client.log.enabled=true\n{client}.http-client.log.path=/var/lib/trino\n{client}.http-client.log.flush-interval=100ms\n')
        validate_config(cfg)
        if defect:
            defect(cfg, material)
        protect(cfg); protect(material)
        if writable_config:
            subprocess.run(['sudo', 'chmod', '0666', str(cfg / 'config.properties')], check=True)
        if public_key:
            subprocess.run(['sudo', 'chmod', '0444', str(material / 'server.pem')], check=True)
        self.name = 'trino-tls-' + secrets.token_hex(6)
        args = ['run', '-d', '--name', self.name, '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--pids-limit=512', '--memory=3g', '--network=host',
                '--tmpfs', '/tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=256m',
                '--tmpfs', '/var/lib/trino:rw,noexec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=512m',
                '-v', f'{cfg}:/etc/trino:' + ('rw' if writable_config else 'ro'), '-v', f'{material}:/run/tls:ro',
                '-e', 'TRINO_UBI_ALLOW_INSECURE=true']
        for host in ('trino', 'catalog', 's3', 'alias'):
            target = '127.0.0.2' if edge == 'self-worker' and host in ('trino', 'alias') else '127.0.0.1'
            args += ['--add-host', host + ':' + target]
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
        if edge in ('inbound', 'internal', 'self-worker'):
            assert rt.query(BASE, 'SELECT version()', self.context) == [[rt.LOCK['trino']['version']]]
            assert rt.query(BASE, 'SELECT count(*) FROM tpch.tiny.nation', self.context) == [[25]]
            assert rt.query(BASE, "SELECT count(*) FROM system.runtime.nodes WHERE state = 'active'", self.context) == [[1]]
        else:
            self.operation(edge)
        if edge in ('internal', 'self-worker'):
            client = 'announcer' if edge == 'internal' else 'scheduler'
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if any(row[4].isdigit() and 200 <= int(row[4]) < 300 for row in self.client_events(client)):
                    break
                time.sleep(0.2)
            else:
                raise AssertionError(f'no successful real {client} request recorded')
        self.plaintext()
        if edge in ('REST', 'S3'):
            fixture = self.rest if edge == 'REST' else self.s3
            before = len(fixture.observations)
            try:
                with socket.create_connection(('127.0.0.1', fixture.server_port), timeout=2) as sock:
                    sock.sendall(b'GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n')
                    response = sock.recv(4096)
                    assert protocol_rejection(response), 'plaintext fixture response'
            except ConnectionResetError:
                pass
            assert len(fixture.observations) == before, 'plaintext reached application handler'
        return name

    def operation(self, edge):
        if edge == 'REST':
            rows = rt.query(BASE, 'SHOW SCHEMAS FROM iceberg', self.context)
            assert ['tls'] in rows, rows
            assert any(path == '/v1/namespaces' for _, path, _ in self.rest.observations)
        else:
            rt.query(BASE, "CALL iceberg.system.register_table(schema_name => 'tls', table_name => 'probe', table_location => 's3://bucket/table', metadata_file_name => 'v1.metadata.json')", self.context)
            assert any(method == 'GET' and path == '/bucket/table/metadata/v1.metadata.json' for method, path, _ in self.s3.observations)
        for label, fixture in (('Iceberg REST', self.rest), ('native S3', self.s3)):
            for _, _, version in fixture.observations:
                assert version in ('TLSv1.2', 'TLSv1.3')
                self.versions[label].add(version)

    def plaintext(self):
        # Both address families, legacy and effective ports; protocol errors only.
        for host in (('127.0.0.1', '::1', '127.0.0.2') if self.relay else ('127.0.0.1', '::1')):
            for port in (8080, 8443):
                try:
                    with socket.create_connection((host, port), timeout=2) as sock:
                        sock.sendall(b'GET /v1/info HTTP/1.1\r\nHost: trino\r\nConnection: close\r\n\r\n')
                        response = sock.recv(4096)
                    assert port == 8443 and protocol_rejection(response), f'plaintext response on {host}:{port}: {response[:160]!r}'
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
                    assert is_loopback_socket(parts[1].split(':')[0]), f'test listener must bind loopback: {family} {parts[1]}'
                    ports.add(int(parts[1].split(':')[1], 16))
        assert ports == {8443}, ports
        self.socket_ports = sorted(ports)

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

    def client_events(self, client):
        output = rt.command('exec', self.name, 'cat', f'/var/lib/trino/{client}-http-client.log', check=False).stdout
        rows = [line.split('\t') for line in output.splitlines()]
        return [row for row in rows if len(row) == 12 and row[3].startswith('https://')]

    def negative(self, edge, variant):
        if edge == 'inbound':
            return self.inbound_negative(variant)
        name = self.start(variant, edge)
        if edge not in ('internal', 'self-worker'):
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
        if edge == 'self-worker':
            rt.ready(name, BASE, self.context)
            try:
                rt.query(BASE, 'SELECT count(*) FROM tpch.tiny.nation', self.context)
            except AssertionError as error:
                diagnostic = str(error) + rt.logs(name)
                match = re.search(TLS_ERRORS[variant], diagnostic, re.I)
                if match:
                    return match.group(0)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if any('/v1/task/' in row[3] and row[4] == 'SSLHANDSHAKE' for row in self.client_events('scheduler')):
                        return 'scheduler /v1/task: SSLHANDSHAKE'
                    time.sleep(0.2)
                raise AssertionError('self-worker SQL failed without TLS-specific evidence: ' + repr(self.client_events('scheduler')))
            raise AssertionError('self-worker accepted an invalid certificate')
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            # Airlift's ordinary warning hides nested TLS causes. Its built-in
            # request event records the originating Jetty failure class, without
            # headers, bodies, credentials or certificate bytes (Airlift 451).
            for row in self.client_events('announcer'):
                if row[3].endswith('/v1/announce') and row[4] == 'SSLHANDSHAKE':
                    return 'announcer POST /v1/announce: SSLHANDSHAKE'
            state = json.loads(rt.command('inspect', name).stdout)[0]['State']
            assert state['Running'], 'internal mutation caused startup failure rather than client TLS rejection'
            time.sleep(1)
        raise AssertionError('internal client has no TLS-specific rejection: ' + repr(self.client_events('announcer')))

    def secret_isolation(self):
        inspected = json.loads(rt.command('inspect', self.name).stdout)[0]
        bindings = [m for m in inspected['Mounts'] if m['Type'] == 'bind']
        assert {m['Destination'] for m in bindings} == {'/etc/trino', '/run/tls'}
        assert all(not m['RW'] for m in bindings)
        assert not any(secret in str(inspected['Config']['Env']) for secret in
                       (self.password, self.shared, self.access, self.secret))
        for path in ('server.pem', 'internal-ca.pem', 'trust.p12', 'password'):
            info = rt.command('exec', self.name, 'stat', '-c', '%u:%g:%a', '/run/tls/' + path).stdout.strip()
            assert info == '0:0:440', info
        # Same GID does not grant access to another role: only own material is mounted.
        rt.command('exec', self.name, '/bin/bash', '-c',
                   'test ! -r /run/tls/catalog.key && test ! -r /run/tls/s3.key && '
                   'test ! -r /run/tls/ca.key && test ! -e /authority && '
                   'test ! -e /run/tls/../catalog && test ! -e /run/tls/../s3')
        record('runtime', 'secret-isolation', 'only own read-only mounts; root:0 0440; other roles and signing key inaccessible')

    def fail_closed(self):
        def append(text):
            def mutate(cfg, _material):
                with (cfg / 'config.properties').open('a') as stream:
                    stream.write(text)
            return mutate
        cases = [
            ('authentication required', {'login_exception': False}),
            ('config.properties', {'defect': lambda cfg, _material: (cfg / 'config.properties').unlink()}),
            ('configuration must be read-only', {'writable_config': True}),
            ('must not be world-accessible', {'public_key': True}),
            ('isolated HTTPS tests require truststore.properties', {'defect': lambda cfg, _material: (cfg / 'truststore.properties').unlink()}),
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
        cases.append(('invalid PKCS12', {'defect': lambda _cfg, material: (material / 'password').write_text(secrets.token_hex(24))}))
        for filename in ('server.pem', 'internal-ca.pem'):
            cases.append((filename, {'defect': lambda _cfg, material, f=filename: (material / f).write_text('malformed')}))
        cases.append(('HTTPS enabled and HTTP disabled', {'defect': lambda cfg, _material: (cfg / 'config.properties').write_text((cfg / 'config.properties').read_text().replace('http-server.http.enabled=false', 'http-server.http.enabled=true'))}))
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
        if self.relay:
            self.relay.close()


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
        report['active_case'] = 'runtime/hardening'
        rehearsal.positive('inbound')
        rt.inspect_security(rehearsal.name)
        rehearsal.secret_isolation()
        record('runtime', 'hardening', 'restricted runtime properties preserved')
        report['active_case'] = 'startup guards'
        rehearsal.fail_closed()
        for edge in ('internal', 'self-worker', 'REST', 'S3', 'inbound'):
            report['active_case'] = f'{edge}/initial valid control'
            rehearsal.positive(edge)
            for variant in ('wrong-ca', 'wrong-trust', 'wrong-san', 'other-service', 'alias', 'expired'):
                report['active_case'] = f'{edge}/{variant}'
                print('CHECK ' + report['active_case'], flush=True)
                outcome = rehearsal.negative(edge, variant)
                rehearsal.positive(edge)
                record(edge, variant, outcome + '; valid operation before and after')
            record(edge, 'plaintext', '8080 refused; 8443 fatal TLS alert or close; IPv4/IPv6; only JVM listener 8443; exercised endpoint refused plaintext')
        del report['active_case']
        report['negotiated_tls'] = {key: sorted(value) for key, value in rehearsal.versions.items()}
        report['negotiated_tls']['urllib SQL'] = sorted(rt.TLS_VERSIONS)
        report['complete'] = True
    except Exception as error:
        report['complete'] = False
        report['failure'] = type(error).__name__
        report['failure_detail'] = str(error) if rehearsal else 'fixture preparation failed'
        if rehearsal and rehearsal.name:
            diagnostic_lines = [line for line in rt.logs(rehearsal.name).splitlines()
                                if re.search(r'ERROR|WARN|Exception|PKIX|certificate|Certificate', line)]
            report['failure_detail'] += '\n' + '\n'.join(diagnostic_lines[-25:])
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
