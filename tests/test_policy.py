import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
        for change in ('edition', 'digest', 'architecture', 'base'):
            broken = copy.deepcopy(lock)
            if change == 'edition':
                broken['trino']['url'] = broken['trino']['url'].replace('trinodb/trino', 'untrusted/trino')
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
