"""Static TLS downgrade deny rules; definitions are deliberately not scanned."""
import re
from pathlib import Path

# This file alone defines the forbidden spellings. Test vectors live only in
# test_tls_policy.py; neither exclusion applies to runtime harness/config files.
DENY = re.compile(
    r'verify[\s\"\x27:=]+false|--insecure\b|curl\s+[^\n]*\s-k\b|CERT_NONE|'
    r'check_hostname[\s:=]+false|insecure_?skip_?verify[\s\"\x27:=]+true|'
    r'danger_accept_invalid_(?:certs|hostnames)|AWS_ALLOW_INVALID_CERTIFICATES[\s:=]+true|'
    r'(?:proxy|grpc)_ssl_verify\s+off|sslmode[\s:=]+(?:require|allow|prefer|disable|verify-ca)\b|'
    r'AWS_ALLOW_HTTP[\s:=]+true|TrustAll|NoopHostnameVerifier|setHostnameVerifier|'
    r'hostname-verification[\s:=]+false', re.I)


def check_text(text):
    assert not DENY.search(text), 'TLS verification downgrade detected'


def check_repository(root):
    for directory in ('container', 'tests', '.github/workflows'):
        for path in (root / directory).rglob('*'):
            if path.is_file() and path.suffix in ('.py', '.sh', '.properties', '.yml', '.yaml'):
                if path == root / 'tests/test_tls_policy.py':
                    continue
                check_text(path.read_text())


if __name__ == '__main__':
    check_repository(Path(__file__).resolve().parents[1])
