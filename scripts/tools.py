#!/usr/bin/env python3
"""Install the hash-locked ShellCheck binary for repository lint (not the image)."""
import hashlib
import io
import json
import platform
import tarfile
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
lock = json.loads((root / 'artifacts/tools.lock.json').read_text())
item = lock['shellcheck'][platform.machine()]
with urllib.request.urlopen(item['url'], timeout=60) as response:
    data = response.read()
if hashlib.sha256(data).hexdigest() != item['sha256']:
    raise ValueError('ShellCheck digest mismatch')
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    content = archive.extractfile('shellcheck-v0.11.0/shellcheck').read()
output = root / '.cache/tools/shellcheck'
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(content)
output.chmod(0o755)
print(output)
