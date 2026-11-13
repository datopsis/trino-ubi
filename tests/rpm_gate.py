"""Run with /usr/bin/python3: exercise real librpm comparison and repository filtering."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from ubi_repoquery import at_least, evr, query
from ubi_repos import repositories


class RpmTests(unittest.TestCase):
    def test_epoch_version_release_ordering(self):
        for candidate, fixed, expected in [
            ('2.37.4-28.el9_9', '2.37.4-28.el9_9', True),
            ('2.37.4-28.el9_9.1', '2.37.4-28.el9_9', True),
            ('2.37.4-28.el9_9', '2.37.4-28.el9_9.1', False),
            ('2.37.4-25.el9', '2.37.4-28.el9_9', False),
            ('1:1.0-1', '0:9.0-99', True), ('0:9.0-99', '1:1.0-1', False),
            ('1.0-2', '0:1.0-2', True), ('1.0-10', '1.0-9', True),
            ('1.0~rc1-1', '1.0-1', False), ('1.0^git1-1', '1.0-1', True),
        ]:
            with self.subTest(candidate=candidate, fixed=fixed):
                self.assertEqual(at_least(candidate, fixed), expected)

    def test_unparsable_versions(self):
        for value in ['', 'unspecified', '1.0', '>=1.0-1', '1:2:1.0-1', '1.0-1,1.0-2',
                      '-1', '1.0-', ' 1.0-1', None, 1]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                evr(value)

    def test_query_filters_arch_and_uses_any_fix_branch(self):
        packages = [{'name': 'sample', 'architecture': 'aarch64', 'evr': '0:1.0-2'},
                    {'name': 'sample', 'architecture': 'x86_64', 'evr': '0:1.0-5'},
                    {'name': 'other', 'architecture': 'aarch64', 'evr': '0:1.0-5'}]
        self.assertTrue(query(packages, {'name': 'sample', 'fixes': ['1.0-3', '1.0-2']}, 'arm64')['available'])
        self.assertFalse(query(packages, {'name': 'sample', 'fixes': ['1.0-3']}, 'arm64')['available'])
        self.assertFalse(query([], {'name': 'sample', 'fixes': ['1.0-2']}, 'arm64')['available'])
        with self.assertRaises(ValueError):
            query(packages, {'name': 'sample', 'fixes': ['1.0-2', 'invalid']}, 'arm64')
        packages.append({'name': 'sample', 'architecture': 'noarch', 'evr': '0:1.0-3'})
        self.assertTrue(query(packages, {'name': 'sample', 'fixes': ['1.0-3']}, 'arm64')['available'])
        packages.append({'name': 'sample', 'architecture': 'aarch64', 'evr': 'invalid'})
        with self.assertRaises(ValueError):
            query(packages, {'name': 'sample', 'fixes': ['1.0-3']}, 'arm64')

    def test_missing_or_disabled_repo_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'ubi.repo'
            with self.assertRaises(FileNotFoundError):
                repositories('amd64', path)
            path.write_text('[unexpected]\nenabled=1\n')
            with self.assertRaises(ValueError):
                repositories('amd64', path)
            source = Path('artifacts/ubi.repo').read_text()
            path.write_text(source.replace('enabled=1', 'enabled=0', 1))
            with self.assertRaises(ValueError):
                repositories('amd64', path)


if __name__ == '__main__':
    unittest.main()
