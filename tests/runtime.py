#!/usr/bin/env python3
"""Real HTTP SQL and fail-closed tests against the exact native container image."""
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'artifacts/trino.lock.json').read_text())
RUNTIME = os.environ.get('CONTAINER_RUNTIME', 'podman')
IMAGE = os.environ.get('IMAGE', 'localhost/trino-ubi:dev')
CONTAINERS = []


def command(*args, check=True, **kwargs):
    return subprocess.run([RUNTIME, *args], check=check, text=True, capture_output=True, **kwargs)


def start(extra=(), mounts=True, insecure=False, port=8080, native_tmp=True):
    name = 'trino-test-' + secrets.token_hex(6)
    args = ['run', '-d', '--name', name, '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=512', '--memory=3g',
            '-p', f'127.0.0.1::{port}']
    if native_tmp:
        args += ['--tmpfs', '/tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=256m']
    if mounts:
        args += ['--tmpfs', '/var/lib/trino:rw,noexec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=512m']
    if insecure:
        args += ['-e', 'TRINO_UBI_ALLOW_INSECURE=true']
    CONTAINERS.append(name)
    command(*args, *extra, IMAGE)
    return name


def logs(name):
    result = command('logs', name, check=False)
    return result.stdout + result.stderr


def wait_exit(name, diagnostic, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = json.loads(command('inspect', name).stdout)[0]['State']
        if not state['Running']:
            assert state['ExitCode'] != 0, f'{name}: unexpectedly succeeded'
            output = logs(name)
            assert diagnostic.lower() in output.lower(), f'expected diagnostic {diagnostic!r}: {output}'
            print(f'PASS fail-closed: {diagnostic}', flush=True)
            return
        time.sleep(1)
    raise AssertionError(f'expected failure {diagnostic!r}; still running: {logs(name)}')


def endpoint(name, port, secure=False):
    address = command('port', name, str(port)).stdout.strip().splitlines()[0]
    return ('https://' if secure else 'http://') + address


def request(url, sql=None, context=None, credentials=None):
    headers = {'X-Trino-User': 'runtime-test'}
    if credentials:
        import base64
        headers['Authorization'] = 'Basic ' + base64.b64encode(credentials.encode()).decode()
    req = urllib.request.Request(url, data=sql.encode() if sql else None, headers=headers)
    with urllib.request.urlopen(req, timeout=10, context=context) as response:
        return json.load(response)


def ready(name, base, context=None):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        state = json.loads(command('inspect', name).stdout)[0]['State']
        if not state['Running']:
            raise AssertionError(f'early server exit: {logs(name)}')
        try:
            info = request(base + '/v1/info', context=context)
            if not info['starting']:
                assert info['nodeVersion']['version'] == LOCK['trino']['version']
                print('PASS HTTP readiness and locked server version', flush=True)
                return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise AssertionError(f'server readiness timeout: {logs(name)}')


def query(base, sql, context=None, credentials=None):
    result = request(base + '/v1/statement', sql, context, credentials)
    rows = []
    deadline = time.monotonic() + 90
    while True:
        assert 'error' not in result, result.get('error')
        rows.extend(result.get('data', []))
        if 'nextUri' not in result:
            return rows
        assert time.monotonic() < deadline, 'SQL timeout'
        # The server can advertise its internal address. Keep requests confined
        # to the explicitly published loopback endpoint.
        uri = urllib.parse.urlsplit(result['nextUri'])
        result = request(base + uri.path + ('?' + uri.query if uri.query else ''), context=context, credentials=credentials)


def inspect_security(name):
    config = json.loads(command('inspect', name).stdout)[0]
    assert config['Config']['User'] == '10001:0'
    assert config['HostConfig']['ReadonlyRootfs']
    assert config['HostConfig']['CapDrop'] == ['ALL']
    assert 'no-new-privileges' in str(config['HostConfig']['SecurityOpt'])
    output = command('exec', name, '/bin/bash', '-c',
                     'for p in /proc/[0-9]*/status; do cat "$p"; done').stdout
    count = 0
    for line in output.splitlines():
        if line.startswith('Uid:'):
            assert set(line.split()[1:]) == {'10001'}, line
            count += 1
        elif line.startswith(('CapEff:', 'CapPrm:', 'CapBnd:')):
            assert int(line.split()[1], 16) == 0, line
        elif line.startswith('NoNewPrivs:'):
            assert line.split()[1] == '1', line
    assert count >= 1
    process = command('exec', name, 'cat', '/proc/1/cmdline').stdout
    assert process.split('\0')[0] == '/opt/java/bin/java'
    assert command('exec', name, 'touch', '/etc/forbidden', check=False).returncode != 0
    mountinfo = command('exec', name, 'cat', '/proc/1/mountinfo').stdout
    assert any(line.split()[4] == '/' and 'ro' in line.split()[5].split(',') for line in mountinfo.splitlines())
    command('exec', name, '/usr/local/bin/trino-healthcheck')
    plugins = command('exec', name, 'ls', '-1', '/opt/trino/plugin').stdout.splitlines()
    assert sorted(plugins) == LOCK['plugins']
    command('exec', name, '/bin/bash', '-c',
            'set -eu; for p in rpm dnf microdnf yum curl wget javac gcc sshd; do ! command -v "$p" || exit 1; done; '
            'test ! -d /etc/yum.repos.d; test ! -d /etc/pki/rpm-gpg; '
            'test ! -d /opt/trino/secrets-plugin; test ! -d /opt/trino/bin; '
            'test -z "$(find / -xdev -type f -perm /6000 -print -quit 2>/dev/null)"')
    for file in ('tcp', 'tcp6'):
        sockets = command('exec', name, 'cat', '/proc/net/' + file).stdout
        for line in sockets.splitlines()[1:]:
            columns = line.split()
            if columns[3] == '0A':
                assert int(columns[1].split(':')[1], 16) >= 1024, line
    release = command('exec', name, 'cat', '/opt/java/release').stdout
    arch = config['Architecture'] if 'Architecture' in config else json.loads(command('image', 'inspect', IMAGE).stdout)[0]['Architecture']
    expected = LOCK['architectures'][arch]['jre']['version'].removeprefix('jdk-').split('+')[0]
    assert f'JAVA_VERSION="{expected}"' in release
    print('PASS processes non-root, Java PID 1, zero capabilities, no-new-privileges, read-only root, plugins, JRE and package-manager absence', flush=True)


def config_copy(root):
    root.mkdir()
    for name in ('config.properties', 'node.properties', 'log.properties'):
        shutil.copyfile(ROOT / 'container' / name, root / name)
    shutil.copytree(ROOT / 'container/catalog', root / 'catalog')
    return root


def main():
    name = start(insecure=True)
    base = endpoint(name, 8080)
    ready(name, base)
    assert query(base, 'SELECT version()') == [[LOCK['trino']['version']]]
    assert query(base, 'SELECT count(*) FROM tpch.tiny.nation') == [[25]]
    assert query(base, "SELECT count(*) FROM system.runtime.nodes WHERE state = 'active'") == [[1]]
    print('PASS real SQL: version(), 25 TPCH nations, one active coordinator/worker', flush=True)
    inspect_security(name)
    command('stop', '--time', '30', name)
    exit_code = json.loads(command('inspect', name).stdout)[0]['State']['ExitCode']
    assert exit_code in (0, 143), f'unclean shutdown: {exit_code}'
    print('PASS SIGTERM shutdown without SIGKILL', flush=True)
    wait_exit(start(), 'authentication required')
    wait_exit(start(insecure=True, mounts=False), '/var/lib/trino')
    wait_exit(start(insecure=True, native_tmp=False), '/tmp/trino')
    wait_exit(start(extra=['-e', 'JAVA_TOOL_OPTIONS=-version'], insecure=True), 'Java option environment overrides')
    wait_exit(start(extra=['--user', '0:0']), 'refusing root')
    wait_exit(start(extra=['-e', 'TRINO_UBI_ALLOW_INSECURE=yes']), 'must be true or false')
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        temp.chmod(0o755)
        empty = temp / 'empty'; empty.mkdir()
        wait_exit(start(extra=['-v', f'{empty}:/etc/trino:ro'], insecure=True), 'config.properties')
        cfg = config_copy(temp / 'password-without-tls')
        with (cfg / 'config.properties').open('a') as stream:
            stream.write('\nhttp-server.authentication.type=PASSWORD\n')
        wait_exit(start(extra=['-v', f'{cfg}:/etc/trino:ro']), 'HTTPS enabled and HTTP disabled')
        cfg = config_copy(temp / 'writable')
        (cfg / 'config.properties').chmod(0o666)
        wait_exit(start(extra=['-v', f'{cfg}:/etc/trino:rw'], insecure=True), 'configuration must be read-only')
        cases = [('privileged', '\nhttp-server.https.port=443\n', 'unprivileged port'),
                 ('duplicate', '\nhttp-server.http.port=9090\n', 'duplicate property'),
                 ('escape', '\nhttp-server.authentication.type=PASS\\u0057ORD\n', 'unsupported escape'),
                 ('unknown', '\nnot-a-trino-property=true\n', 'not-a-trino-property')]
        for label, extra, message in cases:
            cfg = config_copy(temp / label)
            with (cfg / 'config.properties').open('a') as stream:
                stream.write(extra)
            wait_exit(start(extra=['-v', f'{cfg}:/etc/trino:ro'], insecure=True), message)
    print('All native runtime checks passed', flush=True)


if __name__ == '__main__':
    try:
        main()
    finally:
        for container in CONTAINERS:
            # Never print secrets. Runtime logs contain no mounted credentials
            # in these opt-out tests; secure qualification is a separate step.
            output = logs(container)
            print(f'--- diagnostics {container} ---\n{output[-16000:]}', flush=True)
            command('rm', '-f', container, check=False)
