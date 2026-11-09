#!/usr/bin/env python3
"""Offline syntax, formatting, workflow permission and lock checks."""
import ast
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from artifacts import validate

root = Path(__file__).resolve().parents[1]
files = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], text=True).splitlines()
for filename in files:
    path = root / filename
    if not path.is_file() or path.suffix == '.asc':
        continue
    text = path.read_text()
    assert text.endswith('\n'), f'{filename}: missing final newline'
    assert all(line == line.rstrip() for line in text.splitlines()), f'{filename}: trailing whitespace'
    assert not re.search(r'^(<<<<<<< |=======$|>>>>>>> )', text, re.MULTILINE), f'{filename}: conflict marker'
    if path.suffix == '.py':
        ast.parse(text, filename)
    elif path.suffix == '.sh':
        subprocess.run(['bash', '-n', str(path)], check=True)
    elif path.suffix == '.json':
        json.loads(text)
    elif path.suffix == '.xml':
        ET.fromstring(text)
    elif path.suffix in ('.yaml', '.yml'):
        yaml.safe_load(text)
    if filename.startswith('.github/workflows/'):
        workflow = yaml.safe_load(text)
        assert workflow['permissions'] == {'contents': 'read'}, 'workflows must be read-only'
        assert 'pull_request_target' not in text
        assert 'tags:' not in text and 'conformance.yml' not in text
        for use in re.findall(r'uses:\s*(\S+)', text):
            assert re.fullmatch(r'[^@]+@[a-f0-9]{40}', use), f'unpinned action: {use}'
        for job in workflow['jobs'].values():
            assert 'permissions' not in job and 'continue-on-error' not in str(job)
lock = json.loads((root / 'artifacts/trino.lock.json').read_text())
validate(lock)
containerfile = (root / 'Containerfile').read_text()
for base in lock['bases'].values():
    assert base['reference'] in containerfile, 'Containerfile base default differs from lock'
assert 'USER 10001:0' in containerfile and 'VOLUME ' not in containerfile
assert 'filelock==4.2.9' in (root / '.github/requirements/pre-commit.in').read_text()
print('Repository lint passed')
