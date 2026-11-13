"""Repository metadata failures must never prove an unavailable fix."""
import gzip
import hashlib
import subprocess
import unittest
from unittest.mock import patch

from test_policy import module

repos = module('ubi_repos')


def metadata(primary):
    raw = gzip.compress(primary.encode())
    index = ('<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary">'
             '<checksum type="sha256">' + hashlib.sha256(raw).hexdigest() + '</checksum>'
             '<location href="repodata/primary.xml.gz"/></data></repomd>').encode()
    return index, raw


class RepositoryTests(unittest.TestCase):
    def test_errors_empty_missing_corrupt_metadata_fail(self):
        for error in [subprocess.TimeoutExpired('curl', 50), subprocess.CalledProcessError(22, 'curl')]:
            with self.subTest(error=error), patch.object(repos, 'get', side_effect=error):
                with self.assertRaises(type(error)):
                    repos.load_packages('amd64')
        empty = '<metadata xmlns="http://linux.duke.edu/metadata/common" packages="0"/>'
        index, raw = metadata(empty)
        for responses in [[b'<repomd/>'], [index, raw + b'corrupt'], [index, raw],
                          [index.replace(b'sha256', b'sha1'), raw]]:
            with self.subTest(responses=responses), patch.object(repos, 'get', side_effect=responses):
                with self.assertRaises(ValueError):
                    repos.load_packages('arm64')

    def test_metadata_filters_nothing_before_query_and_verifies_checksum(self):
        primary = ('<metadata xmlns="http://linux.duke.edu/metadata/common" '
                   'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">'
                   '<package type="rpm"><name>sample</name><arch>noarch</arch>'
                   '<version epoch="1" ver="2.0" rel="3.el9"/>'
                   '<checksum type="sha256">' + 'a' * 64 + '</checksum>'
                   '<size package="123"/><location href="Packages/s/sample.rpm"/>'
                   '<format><rpm:sourcerpm>sample.src.rpm</rpm:sourcerpm></format>'
                   '</package></metadata>')
        for arch, machine in repos.RPM_ARCH.items():
            with patch.object(repos, 'get', side_effect=metadata(primary)) as get:
                packages = repos.load_packages(arch)
            self.assertIn('/' + machine + '/baseos/', get.call_args_list[0].args[0])
            self.assertEqual(packages[0]['evr'], '1:2.0-3.el9')
            self.assertEqual(packages[0]['architecture'], 'noarch')
        with patch.object(repos, 'get', side_effect=metadata(primary.replace('packages="1"', 'packages="2"'))):
            with self.assertRaises(ValueError):
                repos.load_packages('amd64')

    def test_no_repository_location_escape(self):
        for href in ['https://example.invalid/metadata', '../metadata']:
            with self.assertRaises(ValueError):
                repos.location('https://cdn-ubi.redhat.com/base/', href)
