"""Per-invocation RSA PKI. No key, password or raw command output is evidence."""
import datetime as dt
import secrets
import subprocess
from pathlib import Path


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('OpenSSL fixture preparation failed')
    return result.stdout


def prepare(root):
    root.mkdir(mode=0o700)
    now = dt.datetime.now(dt.timezone.utc)
    stamp = lambda t: t.strftime('%Y%m%d%H%M%SZ')
    for issuer in ('ca', 'unrelated'):
        openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '1',
                '-subj', '/CN=' + issuer, '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                '-keyout', root / f'{issuer}.key', '-out', root / f'{issuer}.crt')
    inventory = {}
    for role in ('trino', 'catalog', 's3'):
        for variant in ('valid', 'wrong-ca', 'wrong-san', 'other-service', 'expired'):
            prefix = root / f'{role}-{variant}'
            issuer = 'unrelated' if variant == 'wrong-ca' else 'ca'
            san = 'wrong.invalid' if variant == 'wrong-san' else ('other-service' if variant == 'other-service' else role)
            # Correct CN / incorrect SAN deliberately distinguishes SAN validation.
            cn = 'other-service' if variant == 'other-service' else role
            openssl('req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-subj', '/CN=' + cn,
                    '-keyout', str(prefix) + '.key', '-out', str(prefix) + '.csr')
            (root / 'index').write_text('')
            (root / 'serial').write_text(secrets.token_hex(16) + '\n')
            (root / 'issue.cnf').write_text(
                f'[ca]\ndefault_ca=issuer\n[issuer]\ndatabase={root}/index\nserial={root}/serial\n'
                f'new_certs_dir={root}\ncertificate={root}/{issuer}.crt\nprivate_key={root}/{issuer}.key\n'
                'default_md=sha256\npolicy=policy\nx509_extensions=leaf\n[policy]\ncommonName=supplied\n'
                f'[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                f'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{san}' + ((',IP:127.0.0.2' if variant in ('wrong-san', 'other-service') else ',IP:127.0.0.1') if role == 'trino' else '') + '\n')
            start = now - dt.timedelta(hours=2) if variant == 'expired' else now - dt.timedelta(minutes=5)
            end = now - dt.timedelta(hours=1) if variant == 'expired' else now + dt.timedelta(hours=6)
            openssl('ca', '-batch', '-notext', '-config', root / 'issue.cnf',
                    '-in', str(prefix) + '.csr', '-out', str(prefix) + '.crt',
                    '-startdate', stamp(start), '-enddate', stamp(end))
            Path(str(prefix) + '.pem').write_bytes(Path(str(prefix) + '.key').read_bytes() + Path(str(prefix) + '.crt').read_bytes())
            inventory[f'{role}/{variant}'] = openssl('x509', '-in', str(prefix) + '.crt', '-noout',
                                                    '-fingerprint', '-sha256', '-dates', '-ext', 'subjectAltName').strip()
    for issuer in ('ca', 'unrelated'):
        (root / f'{issuer}.key').unlink()
    for path in root.iterdir():
        path.chmod(0o600)
    return inventory


def protect(path):
    """Root:0, read-only private files; CI runner has passwordless sudo."""
    subprocess.run(['sudo', 'chown', '-R', '0:0', str(path)], check=True)
    subprocess.run(['sudo', 'find', str(path), '-type', 'f', '-exec', 'chmod', '0440', '{}', '+'], check=True)
    subprocess.run(['sudo', 'find', str(path), '-type', 'd', '-exec', 'chmod', '0750', '{}', '+'], check=True)


def cleanup(path):
    subprocess.run(['sudo', 'rm', '-rf', str(path)], check=True)
