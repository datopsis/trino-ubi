#!/usr/bin/env python3
"""Maintain one issue for native CI admission state; run only on trusted main."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

MARKER = '<!-- trino-ubi-repository-fix-tracker -->'
TITLE = 'UBI repository fix availability'


def api(repo, endpoint, method='GET', payload=None):
    command = ['gh', 'api', f'repos/{repo}/{endpoint}']
    if method == 'GET':
        command += ['--paginate', '--slurp']
    else:
        command += ['--method', method, '--input', '-']
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True, check=True, timeout=60)
    return json.loads(result.stdout)


def state(directory, jobs):
    if any(status != 'success' for name, status in jobs.items() if name != 'native'):
        raise ValueError('incomplete CI; refusing to update deferred state')
    result = {'architectures': {}}
    decoded = [json.loads(path.read_text()) for path in directory.rglob('vulnerabilities.json')]
    for arch in ['amd64', 'arm64']:
        reports = [report for report in decoded if report.get('architecture') == arch]
        if len(reports) != 1 or reports[0].get('schema_version') != 1:
            raise ValueError('missing, duplicate or invalid admission evidence')
        rows = reports[0]['findings']
        fields = ['scanner', 'id', 'package', 'severity', 'fixes', 'decision']
        if not isinstance(rows, list) or any(not isinstance(r, dict) or not set(fields) <= r.keys() or
                                            r['decision'] not in ['block', 'deferred', 'unfixed'] for r in rows):
            raise ValueError('invalid admission decisions')
        if reports[0].get('query', {}).get('error') or any(
                r['decision'] == 'block' and 'query' in r.get('reason', '') for r in rows):
            raise ValueError('repository query failed; previous deferred state must be preserved')
        # Only changes to the deferred set notify. New blockers/unfixed findings,
        # job outcomes, run URLs and timestamps do not change the fingerprint.
        unique = {json.dumps({k: r[k] for k in fields}, sort_keys=True)
                  for r in rows if r['decision'] == 'deferred'}
        result['architectures'][arch] = [json.loads(row) for row in sorted(unique)]
    return result


def render(value, run_url):
    digest = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    fingerprint = f'<!-- state-sha256:{digest} -->'
    lines = [MARKER, fingerprint, '', 'Tracks RPM vendor fixes awaiting publication in the configured UBI repositories.',
             'Deferred findings remain vulnerabilities. Publication changes the next gate result to **block**.', '',
             f'[Native CI evidence]({run_url})', '',
             'Architecture | Scanner | Finding | Package | Severity | Vendor fixed version | Decision',
             '--- | --- | --- | --- | --- | --- | ---']
    attention = False
    for arch, rows in value['architectures'].items():
        if isinstance(rows, dict):
            lines.append(f'{arch} | — | Missing admission evidence | — | — | — | **block**')
            attention = True
            continue
        for row in rows:
            if row['decision'] == 'unfixed':
                continue
            attention = True
            values = [arch, row['scanner'], row['id'], row['package'], row['severity'],
                      ', '.join(row['fixes']) or 'unspecified', row['decision']]
            lines.append(' | '.join(str(v).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                                    .replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ') for v in values))
    if not attention:
        lines += ['', 'No deferred findings. Blocking and unfixed findings remain in CI artifacts.']
    return '\n'.join(lines) + '\n', fingerprint, attention


def update(repo, value, run_url, call=api):
    body, fingerprint, attention = render(value, run_url)
    pages = call(repo, 'issues?state=all&per_page=100')
    issues = [i for page in pages for i in page if not i.get('pull_request') and MARKER in (i.get('body') or '')]
    if len(issues) > 1:
        raise ValueError('multiple tracking issues; refusing to create another')
    if not issues:
        issue = call(repo, 'issues', 'POST', {'title': TITLE, 'body': body})
        if not attention:
            return call(repo, f'issues/{issue["number"]}', 'PATCH', {'state': 'closed'})
        return issue
    issue = issues[0]
    desired = 'open' if attention else 'closed'
    if fingerprint in issue['body']:
        if issue['state'] != desired:
            return call(repo, f'issues/{issue["number"]}', 'PATCH', {'state': desired})
        return issue
    # Comment before updating the fingerprint, so a failed notification retries.
    call(repo, f'issues/{issue["number"]}/comments', 'POST', {'body': 'Deferred set changed.\n\n' + body})
    return call(repo, f'issues/{issue["number"]}', 'PATCH', {'body': body, 'state': desired})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    jobs = json.loads(os.environ['CI_JOB_RESULTS'])
    value = state(args.directory, jobs)
    repo = os.environ['GITHUB_REPOSITORY']
    run_url = f'https://github.com/{repo}/actions/runs/{os.environ["GITHUB_RUN_ID"]}'
    if args.dry_run:
        print(render(value, run_url)[0])
    else:
        if os.environ.get('GITHUB_EVENT_NAME') not in ['schedule', 'workflow_dispatch'] or os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise ValueError('issue updates require a scheduled or manual main-branch run')
        print(json.dumps(update(repo, value, run_url)))


if __name__ == '__main__':
    main()
