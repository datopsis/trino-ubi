#!/usr/bin/env python3
"""Read-only UBI metadata query helper, run with the system Python and RPM bindings."""
import argparse
import hashlib
import json
import re
import sys

import rpm

from ubi_repos import RPM_ARCH, load_packages, repositories, CONFIG


def evr(value):
    # Vendor RPM fixes must include version AND release. Do not guess at ranges,
    # distro suffixes, missing versions, or semantic-version notation.
    if not isinstance(value, str):
        raise ValueError('RPM fixed version must be a string')
    match = re.fullmatch(r'(?:(\d+):)?([A-Za-z0-9][A-Za-z0-9._+~^]*)-([A-Za-z0-9][A-Za-z0-9._+~^]*)', value)
    if not match:
        raise ValueError(f'unparsable RPM EVR: {value!r}')
    epoch, version, release = match.groups()
    return epoch or '0', version, release


def at_least(candidate, fixed):
    return rpm.labelCompare(evr(candidate), evr(fixed)) >= 0


def query(packages, request, arch):
    name, fixes = request['name'], request['fixes']
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._-]*', name):
        raise ValueError('invalid RPM name')
    if not isinstance(fixes, list) or not fixes:
        raise ValueError('missing RPM fixed versions')
    for fixed in fixes:
        evr(fixed)
    candidates = sorted({p['evr'] for p in packages
                         if p['name'] == name and p['architecture'] in [RPM_ARCH[arch], 'noarch']})
    for candidate in candidates:
        evr(candidate)
    # Any advertised fix branch that can be met must block. All supplied
    # versions are parsed first, so one malformed branch cannot be deferred.
    available = any(at_least(candidate, fixed) for candidate in candidates for fixed in fixes)
    return {'available': available, 'candidates': candidates}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', required=True, choices=RPM_ARCH)
    args = parser.parse_args()
    requests = json.load(sys.stdin)
    if not isinstance(requests, list) or not requests:
        raise ValueError('missing query requests')
    packages = load_packages(args.arch)
    repos = {'config_sha256': hashlib.sha256(CONFIG.read_bytes()).hexdigest(), 'urls': repositories(args.arch)}
    results = []
    for request in requests:
        try:
            results.append(query(packages, request, args.arch))
        except Exception as error:
            results.append({'error': str(error)})
    print(json.dumps({'repositories': repos, 'results': results}))


if __name__ == '__main__':
    main()
