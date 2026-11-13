#!/usr/bin/env python3
"""Shared restricted-container helpers for native TLS qualification."""
import json
import os
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'artifacts/trino.lock.json').read_text())
RUNTIME = os.environ.get('CONTAINER_RUNTIME', 'podman')
IMAGE = os.environ.get('IMAGE', 'localhost/trino-ubi:dev')
TLS_VERSIONS = set()


def command(*args, check=True, **kwargs):
    return subprocess.run([RUNTIME, *args], check=check, text=True, capture_output=True, **kwargs)


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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise AssertionError('unexpected redirect from TLS endpoint')


def request(url, sql=None, context=None, credentials=None):
    assert url.startswith('https://')
    assert context is not None and context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    headers = {'X-Trino-User': 'runtime-test'}
    if credentials:
        import base64
        headers['Authorization'] = 'Basic ' + base64.b64encode(credentials.encode()).decode()
    req = urllib.request.Request(url, data=sql.encode() if sql else None, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                          urllib.request.HTTPSHandler(context=context), NoRedirect())
    with opener.open(req, timeout=10) as response:
        TLS_VERSIONS.add(response.fp.raw._sock.version())
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
                print('PASS HTTPS readiness and locked server version', flush=True)
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
        assert uri.scheme == 'https' and uri.netloc == urllib.parse.urlsplit(base).netloc, 'nextUri downgrade or unexpected authority'
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
    descriptors = command('exec', name, '/bin/bash', '-c',
                          'for f in /proc/[0-9]*/fd/*; do readlink "$f" || :; done').stdout
    for file in ('tcp', 'tcp6'):
        sockets = command('exec', name, 'cat', '/proc/net/' + file).stdout
        for line in sockets.splitlines()[1:]:
            columns = line.split()
            if columns[3] == '0A' and f'socket:[{columns[9]}]' in descriptors:
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



if __name__ == '__main__':
    from tls_runtime import main
    main()
