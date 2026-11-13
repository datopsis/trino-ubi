# Trino on Red Hat UBI 9

First development increment of a security-oriented, rootless Trino 484 image.
No image has been published. Passing tests are evidence for the tested native
architecture and configuration only, not production or platform qualification.

## Contents and trust boundary

- UBI 9.8 Micro runtime and UBI Minimal builder, both pinned by manifest-list
  digest with Red Hat signature verification. Both lists include Linux amd64
  and arm64.
- Official `trino-server-core-484.tar.gz` (291,790,975 bytes), plus the separate
  TPCH plugin ZIP. The full 860 MB server distribution is unnecessary.
- Exactly two plugins: `password-authenticators` and `tpch`. SQL functions and
  the `system` catalog are built into the engine. No external data connector,
  Python functions, remote cache, spooling, or optional plugin is retained.
- Temurin **JRE 25.0.5+8**, pinned separately for each architecture, with its
  Adoptium GPG signature verified. A compiler/JDK is unnecessary at runtime.
  Trino 484 requires Java 25, at least 25.0.1.
- Additional UBI RPMs `libstdc++` and `zlib`, pinned by NEVRA and SHA-256 per
  architecture and verified against Red Hat public signing keys.

Trino tarballs and plugin ZIPs have **no published detached signature**. Their
SHA-256 lock is this project's reviewable record of exact bytes, **not proof of
publisher identity**. Neither the GitHub digest nor acquisition is described as
signature verification. See [artifact acquisition](docs/ARTIFACT-ACQUISITION.md).

## Build and verify

Linux prerequisites: Python 3.11+, curl, GnuPG, RPM/rpmkeys, Git, and Podman or
Docker. Lock refresh also needs the GitHub CLI. Build from the repository root:

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes --only-binary=:all: -r .github/requirements/pre-commit.txt
python3 scripts/tools.py
PATH="$PWD/.cache/tools:$PWD/.venv/bin:$PATH" pre-commit run --all-files
python3 -m unittest discover -s tests -p 'test_*.py' -v
bash scripts/build.sh amd64
CONTAINER_RUNTIME=podman IMAGE=localhost/trino-ubi:dev python3 tests/runtime.py
```

Use `arm64` on an ARM host. Set `CONTAINER_RUNTIME=docker` for Docker. Native
CI uses Docker; the Podman invocation is not yet runtime-qualified because the
local sandbox blocks namespaces. The
canonical build fetches and verifies the locked bundle first, pre-pulls the
locked bases, then assembles with networking disabled and pulls disabled.
Invoking `Containerfile` without the admitted bundle and its locked manifest
fails; do not manufacture a manifest from unreviewed files.

## Isolated single-node test

The bundled configuration follows upstream's supported coordinator-plus-worker
single-node topology. **Startup refuses its unauthenticated configuration by
default.** Only for an isolated local test, opt out explicitly:

```sh
podman run --rm --name trino-test --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=512 --memory=3g \
  --tmpfs /var/lib/trino:rw,noexec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=512m \
  --tmpfs /tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=256m \
  -e TRINO_UBI_ALLOW_INSECURE=true -p 127.0.0.1:8080:8080 \
  localhost/trino-ubi:dev
```

The test suite sends real HTTP requests and executes `SELECT version()`,
`SELECT count(*) FROM tpch.tiny.nation` (25 rows), and a query for one active
node. It verifies the runtime identity, Java PID 1, every process's capabilities
and no-new-privileges, read-only root, unprivileged sockets, plugin inventory,
locked Java/server versions, shutdown, and meaningful startup failures.

## Runtime contract

| Item | Contract |
| --- | --- |
| Identity | UID 10001, GID 0; no root startup or privilege transition |
| Listeners | 8080 HTTP only with explicit insecure opt-out; 8443 HTTPS for guarded mode |
| Writable data | `/var/lib/trino`, owned by UID 10001; mount explicitly |
| Writable native-library temp | `/tmp/trino`, owned by UID 10001; **exec required** by Trino native libraries, with nosuid/nodev |
| Configuration | `/etc/trino`, mounted read-only for operator configuration |
| Logs | Console stdout/stderr; bundled HTTP access-file logging disabled |
| Memory | 1 GiB Java heap, two active processors; `TRINO_HEAP_SIZE` accepts e.g. `2G` or `1024M` |
| Healthcheck | Java PID 1 liveness only; not readiness, authentication, or SQL health |
| Stop | SIGTERM, tested with 30-second timeout |

The executable temp mount is a deliberate upstream requirement, not a claim
that every writable path can use `noexec`. Do not put credentials there.
A production workload needs separate resource sizing and qualification.

## Authentication and deployment responsibility

Without `TRINO_UBI_ALLOW_INSECURE=true`, the entrypoint requires PASSWORD
authentication, HTTPS enabled on 8443, HTTP disabled, internal HTTPS and a shared
secret, HTTPS discovery, and readable, non-writable, non-world-accessible TLS
and password files. It rejects missing, duplicate or ambiguous guard properties.
Trino validates the actual certificates, password hashes, and remaining settings.
See [configuration](docs/CONFIGURATION.md) for the exact boundary.

The operator supplies all credentials, private keys, trust, authorization rules,
network isolation, node identity, storage, resource limits and runtime security
flags. Authentication alone does not implement least-privilege authorization;
Trino's default access control is permissive. This increment is **not production
qualified**. Overriding the entrypoint or Java command bypasses image guards;
container admission policy must prevent that where required.

## Repository layout and CI

`Containerfile` assembles the image; `container/` owns startup and configuration;
`artifacts/` holds reviewed-input locks and public verification keys; `scripts/`
owns lock refresh/admission/build/scan gates; `tests/` checks policy and the real
product; `.github/requirements/` contains complete hash-pinned CI requirements;
`.github/workflows/` runs lint, native builds/runtime, SBOM and blocking scans.

Both scanners report all severities, including unfixed findings. A separate,
tested gate blocks **fixable High/Critical findings from either scanner**. Only
RPM fixes proven absent from the build's UBI repositories are deferred, with vendor
fix versions in the job summary and a scheduled tracking issue. Fixed non-RPM
findings, query errors and missing/malformed reports block. See [SECURITY.md](SECURITY.md).
There are no vulnerability suppressions.
Reports and SPDX SBOMs are retained for 14 days even when the gate fails.
`update-locks.yml` has read-only permissions and uploads candidates and a diff
for review; it cannot commit or open a PR. No workflow publishes or signs an
image, and tags trigger no publishing workflow.

See [roadmap](docs/ROADMAP.md), [version policy](docs/VERSION.md),
[security policy](SECURITY.md), and [third-party notices](THIRD_PARTY_NOTICES.md).
