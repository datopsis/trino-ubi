import sys
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class PolicyTests(unittest.TestCase):
    def test_lock_rejects_unsafe_inputs(self):
        artifacts = module('artifacts')
        lock = json.loads((ROOT / 'artifacts/trino.lock.json').read_text())
        artifacts.validate(lock)
        for change in ('edition', 'iceberg-source', 'digest', 'architecture', 'base', 'plugins'):
            broken = copy.deepcopy(lock)
            if change == 'edition':
                broken['trino']['url'] = broken['trino']['url'].replace('trinodb/trino', 'untrusted/trino')
            elif change == 'iceberg-source':
                broken['iceberg']['url'] = broken['iceberg']['url'].replace('/484/', '/483/')
            elif change == 'plugins':
                broken['plugins'].remove('iceberg')
            elif change == 'digest':
                broken['trino']['sha256'] = 'bad'
            elif change == 'architecture':
                del broken['architectures']['arm64']
            else:
                broken['bases']['runtime']['reference'] = 'registry.access.redhat.com/ubi9/ubi-micro:latest'
            with self.subTest(change=change), self.assertRaises(ValueError):
                artifacts.validate(broken)

    def test_corrupt_cached_artifact_is_rejected(self):
        artifacts = module('artifacts')
        with tempfile.TemporaryDirectory() as temp:
            artifacts.ROOT = Path(temp)
            expected = artifacts.digest(b'trusted bytes')
            path = Path(temp) / '.cache/artifacts' / expected
            path.parent.mkdir(parents=True)
            path.write_bytes(b'trusted bytes')
            item = {'sha256': expected, 'url': 'https://example.invalid/never-requested'}
            self.assertEqual(artifacts.download(item), path)
            path.write_bytes(b'altered bytes')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                artifacts.download(item)

    def test_archive_traversal_rejected(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'bad.tar'
            with tarfile.open(path, 'w') as tar:
                item = tarfile.TarInfo('../escape')
                item.size = 1
                tar.addfile(item, io.BytesIO(b'x'))
            with self.assertRaises(ValueError):
                module('artifacts').extract(path, Path(temp) / 'output')

    def test_plugin_zip_admission(self):
        import stat
        import zipfile
        artifacts = module('artifacts')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('tpch', 'iceberg'):
                archive = root / f'{name}.zip'
                expected = f'trino-{name}-484/'
                for defect in ('traversal', 'symlink', 'layout', 'valid'):
                    with zipfile.ZipFile(archive, 'w') as z:
                        if defect == 'symlink':
                            info = zipfile.ZipInfo(expected + 'link')
                            info.external_attr = (stat.S_IFLNK | 0o777) << 16
                            z.writestr(info, '/etc/passwd')
                        else:
                            path = {'traversal': '../escape', 'layout': 'other/file',
                                    'valid': expected + 'plugin.jar'}[defect]
                            z.writestr(path, b'upstream bytes')
                    with self.subTest(plugin=name, defect=defect):
                        destination = root / name
                        if defect == 'valid':
                            artifacts.install_plugin(archive, destination, name, '484')
                            self.assertEqual((destination / 'plugin.jar').read_bytes(), b'upstream bytes')
                        else:
                            with self.assertRaises(ValueError):
                                artifacts.install_plugin(archive, destination, name, '484')

    def test_scan_gate_blocks_each_scanner(self):
        scanner = module('scan_gate')
        trivy = {'SchemaVersion': 2, 'Results': []}
        grype = {'descriptor': {'name': 'grype'}, 'matches': []}
        self.assertFalse(scanner.gate(trivy, grype))
        trivy['Results'] = [{'Vulnerabilities': [{'Severity': 'HIGH', 'VulnerabilityID': 'test',
                                               'PkgName': 'p', 'InstalledVersion': '1', 'FixedVersion': '2'}]}]
        self.assertTrue(scanner.gate(trivy, grype))
        trivy['Results'][0]['Vulnerabilities'][0]['FixedVersion'] = ''
        self.assertFalse(scanner.gate(trivy, grype))
        grype['matches'] = [{'artifact': {'name': 'p', 'version': '1'}, 'vulnerability': {
            'id': 'test', 'severity': 'Critical', 'fix': {'state': 'fixed', 'versions': ['2']}}}]
        self.assertTrue(scanner.gate(trivy, grype))
        grype['matches'][0]['vulnerability']['fix'] = {'state': 'not-fixed', 'versions': []}
        self.assertFalse(scanner.gate(trivy, grype))
        with self.assertRaises(ValueError):
            scanner.gate({}, grype)
        with self.assertRaises(ValueError):
            scanner.gate(trivy, {})

    def test_base_signature_binds_manifest_and_repository(self):
        from unittest.mock import patch
        import subprocess
        artifacts = module('artifacts')
        expected = 'sha256:' + 'a' * 64
        repository = 'registry.access.redhat.com/ubi9/ubi-micro'
        payload = {'critical': {'type': 'atomic container signature',
                               'image': {'docker-manifest-digest': expected},
                               'identity': {'docker-reference': repository + ':signed-tag'}}}
        status = '[GNUPG:] VALIDSIG ' + artifacts.REDHAT[0] + ' rest-of-status\n'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'signature'
            def verify(data, signer_status=status):
                result = subprocess.CompletedProcess([], 0, json.dumps(data), signer_status)
                with patch.object(artifacts.subprocess, 'run', return_value=result):
                    return artifacts.verify_base_signature(path, expected, repository)
            self.assertEqual(verify(payload)['signer'], artifacts.REDHAT[0])
            for defect in ('digest', 'repository', 'type', 'signer'):
                altered = copy.deepcopy(payload)
                signer_status = status
                if defect == 'digest':
                    altered['critical']['image']['docker-manifest-digest'] = 'sha256:' + 'b' * 64
                elif defect == 'repository':
                    altered['critical']['identity']['docker-reference'] = 'attacker/ubi-micro:signed-tag'
                elif defect == 'type':
                    altered['critical']['type'] = 'unrelated signed message'
                else:
                    signer_status = '[GNUPG:] VALIDSIG ' + 'F' * 40 + ' rest\n'
                with self.subTest(defect=defect), self.assertRaises(ValueError):
                    verify(altered, signer_status)
            with patch.object(artifacts.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'gpg')):
                with self.assertRaises(subprocess.CalledProcessError):
                    artifacts.verify_base_signature(path, expected, repository)
