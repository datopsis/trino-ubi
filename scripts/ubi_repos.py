"""Shared UBI repository configuration and fresh metadata for locks and gating."""
import configparser
import gzip
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin

CONFIG = Path(__file__).resolve().parents[1] / 'artifacts/ubi.repo'
RPM_ARCH = {'amd64': 'x86_64', 'arm64': 'aarch64'}
NS = {'r': 'http://linux.duke.edu/metadata/repo', 'c': 'http://linux.duke.edu/metadata/common',
      'rpm': 'http://linux.duke.edu/metadata/rpm'}


def repositories(arch, path=CONFIG):
    rpm_arch = RPM_ARCH[arch]
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(path.read_text())
    if set(config.sections()) != {'baseos'} or config.defaults():
        raise ValueError('missing or unexpected UBI repositories')
    result = {}
    for name in config.sections():
        entry = config[name]
        if entry.getboolean('enabled') is not True or entry.getboolean('gpgcheck') is not True:
            raise ValueError('UBI repositories must be enabled with signature checking')
        url = entry['baseurl'].replace('$basearch', rpm_arch)
        if url != f'https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/{rpm_arch}/{name}/os/':
            raise ValueError('unexpected UBI repository URL')
        result[name] = url
    return result


def get(url):
    return subprocess.check_output(['curl', '--fail', '--silent', '--show-error', '--location',
                                    '--max-time', '45', '--proto', '=https', '--proto-redir', '=https', url],
                                   timeout=50)


def location(base, href):
    url = urljoin(base, href)
    if not url.startswith(base):
        raise ValueError('repository location escaped configured URL')
    return url


def load_packages(arch):
    packages = []
    for name, url in repositories(arch).items():
        root = ET.fromstring(get(url + 'repodata/repomd.xml'))
        entries = root.findall("r:data[@type='primary']", NS)
        if len(entries) != 1:
            raise ValueError('missing or ambiguous primary repository metadata')
        data = entries[0]
        raw = get(location(url, data.find('r:location', NS).attrib['href']))
        checksum = data.find('r:checksum', NS)
        if checksum.attrib['type'] != 'sha256' or hashlib.sha256(raw).hexdigest() != checksum.text:
            raise ValueError('repository metadata digest mismatch')
        primary = ET.fromstring(gzip.decompress(raw))
        entries = primary.findall('c:package', NS)
        if not entries or int(primary.attrib['packages']) != len(entries):
            raise ValueError(f'missing, empty or incomplete UBI repository: {name}')
        for p in entries:
            v = p.find('c:version', NS).attrib
            checksum = p.find('c:checksum', NS)
            if p.attrib['type'] != 'rpm' or checksum.attrib['type'] != 'sha256':
                raise ValueError('unexpected repository package or checksum type')
            href = p.find('c:location', NS).attrib['href']
            packages.append({'name': p.find('c:name', NS).text,
                             'architecture': p.find('c:arch', NS).text,
                             'evr': f"{v['epoch']}:{v['ver']}-{v['rel']}",
                             'url': location(url, href), 'filename': href.split('/')[-1],
                             'sha256': checksum.text,
                             'size': int(p.find('c:size', NS).attrib['package']),
                             'source_rpm': p.find('c:format/rpm:sourcerpm', NS).text})
    return packages
