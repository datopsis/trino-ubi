#!/usr/bin/env python3
"""Block fixed High/Critical findings unless an RPM fix is absent from UBI."""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


def rpm_arch(purl, name):
    """Only positively identified Red Hat RPMs can use repository deferral."""
    if not isinstance(purl, str):
        return None
    parsed = urlsplit(purl)
    if parsed.scheme != 'pkg' or not parsed.path.startswith('rpm/redhat/'):
        return None
    package = parsed.path.removeprefix('rpm/redhat/').split('@', 1)
    if len(package) != 2 or unquote(package[0]) != name:
        return None
    arch = parse_qs(parsed.query).get('arch', [])
    return arch[0] if len(arch) == 1 else None


def findings(trivy, grype):
    if trivy.get('SchemaVersion') != 2 or not isinstance(trivy.get('Results'), list):
        raise ValueError('missing or invalid Trivy report')
    if grype.get('descriptor', {}).get('name') != 'grype' or not isinstance(grype.get('matches'), list):
        raise ValueError('missing or invalid Grype report')
    rows = []
    for result in trivy.get('Results', []):
        for item in result.get('Vulnerabilities', []):
            if item['Severity'].upper() in ['HIGH', 'CRITICAL']:
                fixed = item.get('FixedVersion', '')
                rows.append(dict(scanner='Trivy', id=item['VulnerabilityID'], package=item['PkgName'],
                                 severity=item['Severity'].upper(), installed=item['InstalledVersion'],
                                 fixes=[v.strip() for v in fixed.split(',')] if fixed else [],
                                 fix_reported=bool(fixed) or item.get('Status') == 'fixed',
                                 rpm=result.get('Class') == 'os-pkgs' and result.get('Type') == 'redhat',
                                 package_arch=rpm_arch(item.get('PkgIdentifier', {}).get('PURL'), item['PkgName'])))
    for match in grype.get('matches', []):
        vuln, artifact = match['vulnerability'], match['artifact']
        if vuln['severity'].upper() in ['HIGH', 'CRITICAL']:
            fix = vuln.get('fix', {})
            reported = bool(fix.get('versions')) or fix.get('state') == 'fixed'
            rows.append(dict(scanner='Grype', id=vuln['id'], package=artifact['name'],
                             severity=vuln['severity'].upper(), installed=artifact['version'],
                             fixes=fix.get('versions', []) if reported else [], fix_reported=reported,
                             rpm=artifact.get('type') == 'rpm' and vuln.get('namespace') == 'redhat:distro:redhat:9',
                             package_arch=rpm_arch(artifact.get('purl'), artifact['name'])))
    return rows


def repoquery(requests, arch):
    script = Path(__file__).with_name('ubi_repoquery.py')
    # RPM bindings belong to the OS Python, not the hash-pinned CI venv.
    result = subprocess.run(['/usr/bin/python3', str(script), '--arch', arch],
                            input=json.dumps(requests), text=True, capture_output=True, timeout=180, check=True)
    response = json.loads(result.stdout)
    if not isinstance(response.get('repositories'), dict) or len(response['results']) != len(requests):
        raise ValueError('incomplete repository query response')
    return response


def evaluate(rows, arch, query=None):
    query = query or repoquery
    requests, pending = [], []
    expected_arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(arch)
    for row in rows:
        row['decision'] = 'unfixed'
        row['reason'] = 'scanner reports no fix'
        if not row['fix_reported']:
            continue
        row['decision'] = 'block'
        row['reason'] = 'fixed non-RPM or unverified RPM identity/architecture'
        if row['rpm'] and expected_arch and row['package_arch'] in [expected_arch, 'noarch']:
            row['reason'] = 'repository query not completed'
            requests.append({'name': row['package'], 'fixes': row['fixes']})
            pending.append(row)
    evidence = {}
    if requests:
        try:
            evidence = query(requests, arch)
            results = evidence['results']
            if len(results) != len(pending):
                raise ValueError('incomplete repository query response')
            for row, result in zip(pending, results):
                if result.get('error'):
                    row['reason'] = 'repository query error: ' + str(result['error'])
                elif type(result.get('available')) is not bool or not isinstance(result.get('candidates'), list):
                    row['reason'] = 'invalid repository query response'
                else:
                    row['candidates'] = result['candidates']
                    row['decision'] = 'block' if result['available'] else 'deferred'
                    row['reason'] = ('fixed RPM available from UBI' if result['available'] else
                                     'vendor fix not yet available from UBI repositories')
        except Exception as error:
            # Reset every pending row even if an error occurred after a partial response.
            for row in pending:
                row['decision'] = 'block'
                row['reason'] = f'repository query failed ({type(error).__name__}): {error}'
            evidence = {'error': str(error)}
    return rows, evidence


def cell(value):
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ')


def summary(rows, arch):
    lines = [f'### Vulnerability admission ({cell(arch or "architecture unspecified")})', '',
             'Deferred RPM findings still affect this image; they are not remediated or suppressed.', '',
             'Scanner | ID | Package | Severity | Vendor fixed version | Decision | Reason',
             '--- | --- | --- | --- | --- | --- | ---']
    for row in rows:
        fixed = ', '.join(row['fixes']) or ('unspecified' if row['fix_reported'] else 'no fix reported')
        lines.append(' | '.join(cell(v) for v in [row['scanner'], row['id'], row['package'], row['severity'],
                                                fixed, row['decision'], row['reason']]))
    lines += ['', 'Scanner | Fixable-blocking | Deferred | Unfixed', '--- | ---: | ---: | ---:']
    for scanner in ['Trivy', 'Grype']:
        counts = [sum(r['scanner'] == scanner and r['decision'] == d for r in rows)
                  for d in ['block', 'deferred', 'unfixed']]
        lines.append(' | '.join([scanner, *(str(n) for n in counts)]))
    return '\n'.join(lines) + '\n'


def gate(trivy, grype, arch=None):
    rows, _ = evaluate(findings(trivy, grype), arch)
    print(summary(rows, arch))
    return any(row['decision'] == 'block' for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trivy')
    parser.add_argument('grype')
    parser.add_argument('--arch', default=os.environ.get('ARCHITECTURE'))
    args = parser.parse_args()
    trivy, grype = [json.loads(Path(p).read_text()) for p in [args.trivy, args.grype]]
    if not isinstance(trivy.get('Results'), list) or not isinstance(grype.get('matches'), list):
        raise ValueError('missing scanner results; refusing an empty success')
    rows, query = evaluate(findings(trivy, grype), args.arch)
    report = summary(rows, args.arch)
    print(report)
    Path('reports').mkdir(exist_ok=True)
    Path('reports/vulnerabilities.md').write_text(report)
    Path('reports/vulnerabilities.json').write_text(json.dumps(
        {'schema_version': 1, 'architecture': args.arch, 'findings': rows, 'query': query}, indent=2) + '\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(report)
    return int(any(row['decision'] == 'block' for row in rows))


if __name__ == '__main__':
    sys.exit(main())
