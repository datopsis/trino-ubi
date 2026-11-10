#!/usr/bin/env python3
"""Resolve candidate locks or acquire exact locked bytes; only refresh resolves versions."""
import argparse
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'artifacts/trino.lock.json'
ARCHES = {'amd64': ('x86_64', 'x64'), 'arm64': ('aarch64', 'aarch64')}
ADOPTIUM = '3B04D753C9050D9A5D343F39843C48A565F8F04B'
REDHAT = ['567E347AD0044ADE55BA8A5F199E2F91FD431D51',
          '7E4624258C406535D56D6F135054E4A45A6340B3']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def get(url):
    if not url.startswith('https://'):
        raise ValueError('only HTTPS acquisition is allowed')
    return subprocess.check_output(['curl', '--fail', '--silent', '--show-error',
                                    '--location', '--retry', '3', '--max-time', '120',
                                    '--proto', '=https', '--proto-redir', '=https', url])


def download(item):
    cache = ROOT / '.cache/artifacts' / item['sha256']
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        cache.write_bytes(get(item['url']))
    if 'size' in item and cache.stat().st_size != item['size']:
        raise ValueError(f"size mismatch: {item['url']}")
    if digest(cache.read_bytes()) != item['sha256']:
        raise ValueError(f"SHA-256 mismatch: {item['url']}")
    return cache


def key_fingerprints(path):
    output = subprocess.check_output(['gpg', '--batch', '--with-colons', '--show-keys', str(path)], text=True)
    return [line.split(':')[9] for line in output.splitlines() if line.startswith('fpr:')]


def verify_keys(lock):
    for name, expected in [('adoptium', [ADOPTIUM]), ('redhat', REDHAT)]:
        path = ROOT / f'artifacts/keys/{name}.asc'
        if digest(path.read_bytes()) != lock['keys'][name]['sha256']:
            raise ValueError(f'{name} key digest mismatch')
        if not set(expected).issubset(key_fingerprints(path)):
            raise ValueError(f'{name} publisher fingerprint mismatch')


def verify_base_signature(path, expected_digest, repository):
    """Verify Red Hat simple-signing identity AND manifest digest, not just GPG."""
    with tempfile.TemporaryDirectory() as temp:
        home = Path(temp) / 'gnupg'
        home.mkdir(mode=0o700)
        subprocess.run(['gpg', '--batch', '--homedir', str(home), '--import',
                        str(ROOT / 'artifacts/keys/redhat.asc')], check=True, capture_output=True)
        checked = subprocess.run(['gpg', '--batch', '--homedir', str(home), '--status-fd=2',
                                  '--decrypt', str(path)], check=True, capture_output=True, text=True)
    signers = [line.split()[2] for line in checked.stderr.splitlines()
               if line.startswith('[GNUPG:] VALIDSIG ')]
    if len(signers) != 1 or signers[0] not in REDHAT:
        raise ValueError('base signature is not from a pinned Red Hat publisher')
    critical = json.loads(checked.stdout)['critical']
    identity = critical['identity']['docker-reference']
    if (critical['type'] != 'atomic container signature'
            or critical['image']['docker-manifest-digest'] != expected_digest
            or not re.fullmatch(re.escape(repository) + r':[a-zA-Z0-9_.-]+', identity)):
        raise ValueError('base signature manifest digest or repository identity mismatch')
    return {'identity': identity, 'signer': signers[0]}


def verify_bases(lock, arch):
    for entry in lock['bases'].values():
        repository = entry['reference'].split(':')[0]
        for key in ('index', arch):
            expected = entry['reference'].split('@')[1] if key == 'index' else entry['platforms'][key]
            record = entry['signatures'][key]
            actual = verify_base_signature(download(record), expected, repository)
            if actual != {k: record[k] for k in ('identity', 'signer')}:
                raise ValueError('base publisher identity differs from lock')


def extract(archive, destination):
    """Reject traversal/devices; resolve internal symlinks into a regular-file tree."""
    with tempfile.TemporaryDirectory() as temp:
        staging = Path(temp)
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                target = (staging / member.name).resolve()
                if not target.is_relative_to(staging) or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError('unsafe archive member')
                if member.islnk() and not (staging / member.linkname).resolve().is_relative_to(staging):
                    raise ValueError('unsafe archive hard link')
                if member.issym() and not (target.parent / member.linkname).resolve().is_relative_to(staging):
                    raise ValueError('unsafe archive link')
            # All paths checked before extraction; pinned publisher artifacts only.
            tar.extractall(staging, **({'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}))
        entries = list(staging.iterdir())
        if len(entries) != 1 or not entries[0].is_dir():
            raise ValueError('archive must contain one top-level directory')
        shutil.copytree(entries[0], destination, symlinks=False)


def manifest(bundle):
    files = sorted(p for p in bundle.rglob('*') if p.is_file() and p != bundle / 'SHA256SUMS')
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in bundle.rglob('*')):
        raise ValueError('bundle must contain only regular files and directories')
    return ''.join(f'{digest(p.read_bytes())}  {p.relative_to(bundle)}\n' for p in files).encode()


def acquire(lock, arch, output, candidate=False):
    validate(lock)
    verify_keys(lock)
    verify_bases(lock, arch)
    selected = lock['architectures'][arch]
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        home = temp / 'gnupg'
        home.mkdir(mode=0o700)
        subprocess.run(['gpg', '--batch', '--homedir', str(home), '--import',
                        str(ROOT / 'artifacts/keys/adoptium.asc')], check=True, capture_output=True)
        jre = download(selected['jre'])
        signature = download(selected['jre']['signature'])
        checked = subprocess.run(['gpg', '--batch', '--homedir', str(home), '--status-fd=1',
                                  '--verify', str(signature), str(jre)], check=True, capture_output=True, text=True)
        if f'[GNUPG:] VALIDSIG {ADOPTIUM} ' not in checked.stdout:
            raise ValueError('JRE signature did not match the pinned publisher')
        bundle = temp / 'bundle'
        bundle.mkdir()
        extract(download(lock['trino']), bundle / 'trino')
        extract(jre, bundle / 'jre')
        # The core tarball has no data connector. Retain the password plugin
        # and add only TPCH, whose generated data exercises real split execution.
        plugins = bundle / 'trino/plugin'
        actual = sorted(p.name for p in plugins.iterdir())
        if actual != lock['trino']['core_plugins']:
            raise ValueError('upstream core plugin inventory changed')
        for plugin in plugins.iterdir():
            if plugin.name != 'password-authenticators':
                shutil.rmtree(plugin)
        with zipfile.ZipFile(download(lock['tpch'])) as archive:
            for member in archive.infolist():
                target = (plugins / 'tpch' / member.filename).resolve()
                if not target.is_relative_to((plugins / 'tpch').resolve()):
                    raise ValueError('unsafe plugin ZIP path')
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError('plugin ZIP symlinks forbidden')
            extracted = temp / 'tpch-extracted'
            archive.extractall(extracted)
            entries = list(extracted.iterdir())
            if len(entries) != 1 or entries[0].name != 'trino-tpch-' + lock['trino']['version']:
                raise ValueError('unexpected TPCH ZIP layout')
            shutil.copytree(entries[0], plugins / 'tpch')
        if sorted(p.name for p in plugins.iterdir()) != lock['plugins']:
            raise ValueError('runtime plugin inventory mismatch')
        shutil.rmtree(bundle / 'trino/bin')
        shutil.rmtree(bundle / 'trino/secrets-plugin')
        (bundle / 'rpms').mkdir()
        rpmdb = temp / 'rpmdb'
        subprocess.run(['rpm', '--dbpath', str(rpmdb), '--initdb'], check=True)
        subprocess.run(['rpm', '--dbpath', str(rpmdb), '--import', str(ROOT / 'artifacts/keys/redhat.asc')], check=True)
        for item in selected['rpms']:
            path = download(item)
            check = subprocess.check_output(['rpmkeys', '--dbpath', str(rpmdb), '--checksig', str(path)], text=True)
            if 'signatures OK' not in check or 'NOT OK' in check:
                raise ValueError('RPM publisher signature verification failed')
            actual = subprocess.check_output(['rpm', '--dbpath', str(rpmdb), '-qp', '--qf',
                                              '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}', str(path)], text=True)
            source = subprocess.check_output(['rpm', '--dbpath', str(rpmdb), '-qp', '--qf',
                                              '%{SOURCERPM}', str(path)], text=True)
            if source != item['source_rpm']:
                raise ValueError('RPM source-package mismatch')
            if actual != item['nevra']:
                raise ValueError('RPM NEVRA mismatch')
            shutil.copyfile(path, bundle / 'rpms' / item['filename'])
        content = manifest(bundle)
        if not candidate and digest(content) != selected['bundle_sha256']:
            raise ValueError('extracted bundle manifest differs from lock')
        (bundle / 'SHA256SUMS').write_bytes(content)
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(bundle, output)
        return digest(content)


def validate(lock):
    if lock['schema'] != 1 or lock['trino']['license'] != 'Apache-2.0':
        raise ValueError('unsupported schema or Trino licence')
    if set(lock['architectures']) != set(ARCHES):
        raise ValueError('both architectures required')
    if not re.fullmatch(r'\d+', lock['trino']['version']):
        raise ValueError('invalid Trino version')
    version = lock['trino']['version']
    for key, filename in [('trino', f'trino-server-core-{version}.tar.gz'),
                          ('tpch', f'trino-tpch-{version}.zip')]:
        if lock[key]['url'] != f'https://github.com/trinodb/trino/releases/download/{version}/{filename}':
            raise ValueError('only official Trino release assets are permitted')
    if lock['plugins'] != ['password-authenticators', 'tpch']:
        raise ValueError('unexpected plugin set')
    for role, name in [('builder', 'ubi-minimal'), ('runtime', 'ubi-micro')]:
        if not re.fullmatch(rf'registry.access.redhat.com/ubi9/{name}:9\.8@sha256:[0-9a-f]{{64}}', lock['bases'][role]['reference']):
            raise ValueError('UBI 9.8 digest pin required')
        if set(lock['bases'][role]['signatures']) != {'index', *ARCHES}:
            raise ValueError('base index and both platform signatures required')
        if set(lock['bases'][role]['platforms']) != set(ARCHES):
            raise ValueError('both base platforms required')
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key.endswith('sha256') and not re.fullmatch('[a-f0-9]{64}', item):
                    raise ValueError('invalid SHA-256')
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(lock)
    for arch, item in lock['architectures'].items():
        if item['jre']['signer'] != ADOPTIUM:
            raise ValueError('unexpected JRE publisher identity')
        if {p['name'] for p in item['rpms']} != {'libstdc++', 'zlib'}:
            raise ValueError('unexpected runtime RPM set')
        for rpm in item['rpms']:
            if rpm['architecture'] != ARCHES[arch][0]:
                raise ValueError('wrong RPM architecture')


def base(name):
    url = f'https://registry.access.redhat.com/v2/ubi9/{name}/manifests/9.8'
    request = urllib.request.Request(url, headers={'Accept': 'application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read()
        sha = 'sha256:' + digest(raw)
        if response.headers['Docker-Content-Digest'] != sha:
            raise ValueError('base registry digest mismatch')
    entries = json.loads(raw)['manifests']
    platforms = {}
    for arch in ARCHES:
        matches = [x for x in entries if x['platform']['architecture'] == arch and x['platform']['os'] == 'linux']
        if len(matches) != 1:
            raise ValueError('base index lacks unique architecture')
        platforms[arch] = matches[0]['digest']
    signatures = {}
    repository = f'registry.access.redhat.com/ubi9/{name}'
    for platform, manifest in {'index': sha, **platforms}.items():
        url = f'https://access.redhat.com/webassets/docker/content/sigstore/ubi9/{name}@{manifest.replace(":", "=")}/signature-1'
        data = get(url)
        record = {'url': url, 'sha256': digest(data), 'size': len(data)}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'signature'
            path.write_bytes(data)
            record.update(verify_base_signature(path, manifest, repository))
        signatures[platform] = record
    return {'reference': f'{repository}:9.8@{sha}', 'platforms': platforms, 'signatures': signatures}


def resolve_rpms(architecture):
    url = f'https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/{architecture}/baseos/os/'
    ns = {'r': 'http://linux.duke.edu/metadata/repo', 'c': 'http://linux.duke.edu/metadata/common', 'rpm': 'http://linux.duke.edu/metadata/rpm'}
    root = ET.fromstring(get(url + 'repodata/repomd.xml'))
    data = root.find("r:data[@type='primary']", ns)
    raw = get(url + data.find('r:location', ns).attrib['href'])
    if digest(raw) != data.find('r:checksum', ns).text:
        raise ValueError('repository metadata digest mismatch')
    packages = ET.fromstring(gzip.decompress(raw))
    result = []
    for name in ('libstdc++', 'zlib'):
        matches = [p for p in packages if p.find('c:name', ns).text == name and p.find('c:arch', ns).text == architecture]
        if len(matches) != 1:
            raise ValueError(f'expected one current RPM for {name}; review repository metadata')
        p = matches[0]
        v = p.find('c:version', ns).attrib
        href = p.find('c:location', ns).attrib['href']
        result.append({'name': name, 'architecture': architecture,
                       'nevra': f"{name}-{v['epoch']}:{v['ver']}-{v['rel']}.{architecture}",
                       'url': url + href, 'filename': href.split('/')[-1],
                       'sha256': p.find('c:checksum', ns).text,
                       'size': int(p.find('c:size', ns).attrib['package']),
                       'source_rpm': p.find('c:format/rpm:sourcerpm', ns).text})
    return result


def release_asset(release, name):
    matches = [a for a in release['assets'] if a['name'] == name]
    if len(matches) != 1 or not matches[0].get('digest', '').startswith('sha256:'):
        raise ValueError(f'missing digest for release asset: {name}')
    asset = matches[0]
    return {'url': asset['browser_download_url'], 'sha256': asset['digest'][7:], 'size': asset['size']}


def github(path):
    # Refresh only: gh uses the caller's read-only token, never in an artifact.
    return json.loads(subprocess.check_output(['gh', 'api', path]))


def refresh(version, output):
    release = github(f'repos/trinodb/trino/releases/tags/{version}')
    java = github('repos/adoptium/temurin25-binaries/releases/latest')
    trino = release_asset(release, f'trino-server-core-{version}.tar.gz')
    trino.update(version=version, license='Apache-2.0',
                 verification='digest-only; no detached tarball signature published',
                 core_plugins=['blob-cache-alluxio', 'blob-cache-memory', 'exchange-filesystem',
                               'functions-python', 'geospatial', 'password-authenticators',
                               'resource-group-managers', 'session-property-managers', 'spooling-filesystem'])
    lock = {'schema': 1, 'trino': trino, 'tpch': release_asset(release, f'trino-tpch-{version}.zip'),
            'plugins': ['password-authenticators', 'tpch'],
            'bases': {role: base(name) for role, name in [('builder', 'ubi-minimal'), ('runtime', 'ubi-micro')]},
            'keys': {name: {'sha256': digest((ROOT / f'artifacts/keys/{name}.asc').read_bytes())}
                     for name in ('redhat', 'adoptium')}, 'architectures': {}}
    for arch, (rpm_arch, java_arch) in ARCHES.items():
        matches = [a for a in java['assets'] if re.fullmatch(
            rf'OpenJDK25U-jre_{java_arch}_linux_hotspot_.*\.tar\.gz', a['name'])]
        if len(matches) != 1:
            raise ValueError('expected one JRE release asset')
        name = matches[0]['name']
        jre = release_asset(java, name)
        jre.update(version=java['tag_name'], signature=release_asset(java, name + '.sig'), signer=ADOPTIUM)
        lock['architectures'][arch] = {'jre': jre, 'rpms': resolve_rpms(rpm_arch), 'bundle_sha256': '0' * 64}
    for arch in ARCHES:
        with tempfile.TemporaryDirectory() as temp:
            lock['architectures'][arch]['bundle_sha256'] = acquire(lock, arch, Path(temp) / 'bundle', candidate=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(lock, indent=2) + '\n')
    print(f'Candidate written to {output}; review it, no commit or approval was created.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['validate', 'fetch', 'refresh'])
    parser.add_argument('--lock', type=Path, default=LOCK)
    parser.add_argument('--arch', choices=ARCHES)
    parser.add_argument('--version')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.command == 'refresh':
        refresh(args.version or json.loads(args.lock.read_text())['trino']['version'], args.output or ROOT / 'candidates/trino.lock.json')
    else:
        lock = json.loads(args.lock.read_text())
        validate(lock)
        verify_keys(lock)
        if args.command == 'fetch':
            if not args.arch:
                parser.error('--arch required')
            acquire(lock, args.arch, args.output or ROOT / '.artifact-bundle' / args.arch)


if __name__ == '__main__':
    main()
