"""Admission, reporting and notification regression tests."""
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from test_policy import module

gate = module('scan_gate')

tracker = module('track_vulnerabilities')


def finding():
    return dict(scanner='Trivy', id='CVE-test', package='sample', severity='HIGH', installed='1.0-1',
                fixes=['1.0-2'], fix_reported=True, rpm=True, package_arch='x86_64')


def response(available):
    return {'repositories': {'urls': {}}, 'results': [{'available': available, 'candidates': ['0:1.0-1']}]}


class AvailabilityTests(unittest.TestCase):
    def test_available_blocks_unavailable_defers_each_architecture_and_severity(self):
        for arch, rpm_arch in [('amd64', 'x86_64'), ('arm64', 'aarch64')]:
            for severity in ['HIGH', 'CRITICAL']:
                for available in [True, False]:
                    row = finding() | {'package_arch': rpm_arch, 'severity': severity}
                    query = Mock(return_value=response(available))
                    rows, evidence = gate.evaluate([row], arch, query)
                    self.assertEqual(rows[0]['decision'], 'block' if available else 'deferred')
                    query.assert_called_once_with([{'name': 'sample', 'fixes': ['1.0-2']}], arch)
                    self.assertIn('1.0-2', gate.summary(rows, arch))
                    self.assertEqual(evidence, response(available))

    def test_query_failures_block(self):
        for error in [TimeoutError('timeout'), subprocess.TimeoutExpired('dnf', 180),
                      subprocess.CalledProcessError(1, 'dnf'), ValueError('missing repository')]:
            rows, _ = gate.evaluate([finding()], 'amd64', Mock(side_effect=error))
            self.assertEqual(rows[0]['decision'], 'block')
        for result in [{'error': 'unparsable EVR'}, {}, {'available': 'false', 'candidates': []},
                       {'available': False}]:
            rows, _ = gate.evaluate([finding()], 'amd64', lambda *_: {'results': [result]})
            self.assertEqual(rows[0]['decision'], 'block')
        rows, _ = gate.evaluate([finding(), finding()], 'amd64', lambda *_: response(False))
        self.assertTrue(all(r['decision'] == 'block' for r in rows))

    def test_non_rpm_unknown_identity_wrong_arch_and_missing_arch_block(self):
        for changes, arch in [({'rpm': False}, 'amd64'), ({'package_arch': None}, 'amd64'),
                              ({'package_arch': 'aarch64'}, 'amd64'), ({}, None)]:
            query = Mock(side_effect=AssertionError('must not query'))
            rows, _ = gate.evaluate([finding() | changes], arch, query)
            self.assertEqual(rows[0]['decision'], 'block')
            query.assert_not_called()

    def test_non_rpm_scanner_findings_block(self):
        for kind in ['jar', 'go-module', 'python', 'rust-crate', 'npm']:
            grype = {'descriptor': {'name': 'grype'}, 'matches': [{'artifact': {'name': 'sample', 'version': '1.0-1', 'type': kind},
                                 'vulnerability': {'id': 'CVE-test', 'severity': 'Critical',
                                                   'fix': {'state': 'fixed', 'versions': ['2.0']}}}]}
            rows, _ = gate.evaluate(gate.findings({'SchemaVersion': 2, 'Results': []}, grype), 'amd64', Mock())
            self.assertEqual(rows[0]['decision'], 'block')

    def test_non_rpm_trivy_findings_block(self):
        for kind in ['jar', 'gobinary', 'python-pkg', 'rust-binary', 'npm']:
            trivy = {'SchemaVersion': 2, 'Results': [{'Class': 'lang-pkgs', 'Type': kind,
                     'Vulnerabilities': [{'Severity': 'HIGH', 'VulnerabilityID': 'test',
                                          'PkgName': 'sample', 'InstalledVersion': '1', 'FixedVersion': '2'}]}]}
            query = Mock()
            rows, _ = gate.evaluate(gate.findings(trivy, {'descriptor': {'name': 'grype'}, 'matches': []}),
                                    'arm64', query)
            self.assertEqual(rows[0]['decision'], 'block')
            query.assert_not_called()

    def test_unfixed_stays_reported_without_query(self):
        query = Mock()
        rows, _ = gate.evaluate([finding() | {'fix_reported': False, 'fixes': []}], 'amd64', query)
        self.assertEqual(rows[0]['decision'], 'unfixed')
        self.assertIn('no fix reported', gate.summary(rows, 'amd64'))
        query.assert_not_called()

    def test_missing_installed_versions_still_fail_closed(self):
        trivy = {'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [
            {'Severity': 'HIGH', 'VulnerabilityID': 'test', 'PkgName': 'sample'}]}]}
        grype = {'descriptor': {'name': 'grype'}, 'matches': []}
        with self.assertRaises(KeyError):
            gate.findings(trivy, grype)
        trivy['Results'] = []
        grype['matches'] = [{'artifact': {'name': 'sample'},
                            'vulnerability': {'id': 'test', 'severity': 'High'}}]
        with self.assertRaises(KeyError):
            gate.findings(trivy, grype)

    def test_scanner_rpm_identity(self):
        purl = 'pkg:rpm/redhat/sample@1.0-1?arch=aarch64&distro=redhat-9'
        trivy = {'SchemaVersion': 2, 'Results': [{'Type': 'redhat', 'Class': 'os-pkgs', 'Vulnerabilities': [
            {'Severity': 'HIGH', 'VulnerabilityID': 'CVE-test', 'PkgName': 'sample', 'InstalledVersion': '1.0-1', 'FixedVersion': '1.0-2',
             'PkgIdentifier': {'PURL': purl}}]}]}
        grype = {'descriptor': {'name': 'grype'}, 'matches': [{'artifact': {'name': 'sample', 'version': '1.0-1', 'type': 'rpm', 'purl': purl},
                             'vulnerability': {'id': 'CVE-test', 'severity': 'High',
                                               'namespace': 'redhat:distro:redhat:9',
                                               'fix': {'state': 'fixed', 'versions': ['0:1.0-2']}}}]}
        for row in gate.findings(trivy, grype):
            self.assertTrue(row['rpm'])
            self.assertEqual(row['package_arch'], 'aarch64')
        for invalid in [None, '', purl.replace('sample@', 'other@'), purl.replace('rpm/', 'pypi/'),
                        purl + '&arch=x86_64']:
            self.assertIsNone(gate.rpm_arch(invalid, 'sample'))

    def test_fixed_state_without_version_blocks(self):
        row = finding() | {'fixes': []}
        rows, _ = gate.evaluate([row], 'amd64', lambda *_: {'results': [{'error': 'missing RPM fixed versions'}]})
        self.assertEqual(rows[0]['decision'], 'block')
        self.assertIn('unspecified', gate.summary(rows, 'amd64'))

    def test_system_rpm_unit_tests(self):
        result = subprocess.run(['/usr/bin/python3', 'tests/rpm_gate.py'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class TrackingTests(unittest.TestCase):
    def state(self, decision='deferred'):
        return {'architectures': {a: ([finding() | {'decision': decision}] if decision == 'deferred' else [])
                                  for a in ['amd64', 'arm64']}}

    def test_create_one_issue_and_no_duplicate_on_unchanged_state(self):
        value = self.state()
        call = Mock(side_effect=[[], {'number': 7}])
        tracker.update('owner/repo', value, 'https://example.invalid/run/1', call)
        self.assertEqual(call.call_args.args[1:3], ('issues', 'POST'))
        body = tracker.render(value, 'https://example.invalid/run/1')[0]
        call = Mock(return_value=[[{'number': 7, 'body': body, 'state': 'open'}]])
        tracker.update('owner/repo', value, 'https://example.invalid/run/2', call)
        self.assertEqual(call.call_count, 1)

    def test_publication_comments_and_reuses_issue(self):
        body = tracker.render(self.state(), 'https://example.invalid/run/1')[0]
        call = Mock(side_effect=[[[{'number': 7, 'body': body, 'state': 'open'}]], {}, {}])
        tracker.update('owner/repo', self.state('block'), 'https://example.invalid/run/2', call)
        self.assertEqual(call.call_args_list[1].args[1:3], ('issues/7/comments', 'POST'))
        self.assertIn('No deferred findings', call.call_args_list[1].args[3]['body'])
        self.assertEqual(call.call_args_list[2].args[1:3], ('issues/7', 'PATCH'))

    def test_missing_architecture_evidence_preserves_existing_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                tracker.state(Path(tmp), {'native': 'failure'})

    def test_query_error_preserves_existing_deferred_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for arch in ['amd64', 'arm64']:
                (directory / arch).mkdir()
                (directory / arch / 'vulnerabilities.json').write_text(json.dumps(
                    {'schema_version': 1, 'architecture': arch, 'query': {'error': 'timeout'},
                     'findings': [finding() | {'decision': 'block'}]}))
            with self.assertRaises(ValueError):
                tracker.state(directory, {'native': 'failure'})

    def test_only_deferred_set_changes_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            def write(extra):
                for arch in ['amd64', 'arm64']:
                    (directory / f'{arch}').mkdir(exist_ok=True)
                    (directory / arch / 'vulnerabilities.json').write_text(json.dumps(
                        {'schema_version': 1, 'architecture': arch,
                         'findings': [finding() | {'decision': 'deferred'}] + extra}))
            write([])
            before = tracker.state(directory, {'native': 'success'})
            write([finding() | {'decision': 'block'}, finding() | {'decision': 'unfixed'}])
            self.assertEqual(before, tracker.state(directory, {'native': 'failure'}))

    def test_fix_order_and_duplicate_findings_do_not_notify(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            def write(rows):
                for arch in ['amd64', 'arm64']:
                    (directory / arch).mkdir(exist_ok=True)
                    (directory / arch / 'vulnerabilities.json').write_text(json.dumps(
                        {'schema_version': 1, 'architecture': arch, 'findings': rows}))
            row = finding() | {'decision': 'deferred', 'fixes': ['1.0-3', '1.0-2']}
            write([row])
            before = tracker.state(directory, {'native': 'success'})
            row['fixes'].reverse()
            write([row, row])
            self.assertEqual(before, tracker.state(directory, {'native': 'success'}))

    def test_fingerprint_changes_for_fix_version_and_decision(self):
        value = self.state()
        changed = copy.deepcopy(value)
        changed['architectures']['amd64'][0]['fixes'] = ['1.0-3']
        self.assertNotEqual(tracker.render(value, '')[1], tracker.render(changed, '')[1])

    def test_resolved_issue_closes_and_later_reopens(self):
        body = tracker.render(self.state(), '')[0]
        call = Mock(side_effect=[[[{'number': 7, 'body': body, 'state': 'open'}]], {}, {}])
        tracker.update('owner/repo', self.state('unfixed'), '', call)
        self.assertEqual(call.call_args.args[3]['state'], 'closed')
        body = tracker.render(self.state('unfixed'), '')[0]
        call = Mock(side_effect=[[[{'number': 7, 'body': body, 'state': 'closed'}]], {}, {}])
        tracker.update('owner/repo', self.state(), '', call)
        self.assertEqual(call.call_args.args[3]['state'], 'open')
