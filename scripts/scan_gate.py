#!/usr/bin/env python3
"""Retain every finding; fail on fixed High/Critical from either scanner."""
import json
import sys
from pathlib import Path


def findings(trivy, grype):
    if trivy.get('SchemaVersion') != 2 or not isinstance(trivy.get('Results'), list):
        raise ValueError('missing or invalid Trivy report')
    if grype.get('descriptor', {}).get('name') != 'grype' or not isinstance(grype.get('matches'), list):
        raise ValueError('missing or invalid Grype report')
    rows = []
    for result in trivy['Results']:
        for v in result.get('Vulnerabilities', []):
            if v['Severity'].upper() in ('HIGH', 'CRITICAL'):
                rows.append(('Trivy', v['VulnerabilityID'], v['PkgName'], v['InstalledVersion'],
                             v['Severity'], v.get('FixedVersion', '').strip()))
    for match in grype['matches']:
        v = match['vulnerability']
        if v['severity'].upper() in ('HIGH', 'CRITICAL'):
            fixed = ', '.join(v.get('fix', {}).get('versions', []))
            # Treat a fixed state without a version as blocking too.
            if not fixed and v.get('fix', {}).get('state') == 'fixed':
                fixed = '(fixed; version unspecified)'
            rows.append(('Grype', v['id'], match['artifact']['name'], match['artifact']['version'], v['severity'], fixed))
    return rows


def gate(trivy, grype):
    rows = findings(trivy, grype)
    for scanner, cve, package, version, severity, fixed in rows:
        print(f'{scanner}: {severity} {cve} {package}@{version}: fix={fixed or "not available"}')
    blockers = sum(bool(row[-1]) for row in rows)
    print(f'High/Critical: {len(rows)} scanner findings; {blockers} with fixes; {len(rows)-blockers} without fixes')
    return bool(blockers)


if __name__ == '__main__':
    sys.exit(gate(*(json.loads(Path(p).read_text()) for p in sys.argv[1:])))
