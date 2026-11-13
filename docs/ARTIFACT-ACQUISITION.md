# Artifact acquisition

`artifacts/trino.lock.json` pins both UBI 9.8 manifest lists and their amd64/arm64
child manifests and their Red Hat signatures, upstream core/TPCH archives,
Temurin JREs and detached signatures,
public verification keys, added RPMs, and each extracted bundle manifest.
The canonical build consumes this committed lock; only refresh resolves versions.
RPM resolution and vulnerability admission share `artifacts/ubi.repo` and the
checksum-verified UBI metadata reader. Only UBI 9 BaseOS is configured for both
architectures; native admission compares EVRs with the system `python3-rpm` bindings.

## Trino

[Trino 484](https://github.com/trinodb/trino/releases/tag/484) requires Java 25
(minimum 25.0.1), as stated in its
[deployment documentation](https://github.com/trinodb/trino/blob/484/docs/src/main/sphinx/installation/deployment.md).
Server tarballs ceased being published to Maven Central starting with 477;
Maven URLs now redirect to GitHub. This project's acquisition source is the
**official GitHub release**, explicitly authorized for this increment.

We chose `trino-server-core-484.tar.gz` (291,790,975 bytes) rather than the full
860,660,442-byte server tarball. Its nine plugins are recorded in the lock:
blob-cache-alluxio, blob-cache-memory, exchange-filesystem, functions-python,
geospatial, password-authenticators, resource-group-managers,
session-property-managers and spooling-filesystem. Only password-authenticators
remains. The separately published TPCH ZIP supplies the only data connector.
All other plugin directories, the separate keystore-secrets-plugin directory,
and upstream daemon launchers are removed. Native
libraries embedded in retained JARs remain upstream bytes, not rebuilt code.

No detached Trino tarball or plugin ZIP signature is published. The lock's
SHA-256 is this project's reviewable record of exact bytes, **not proof of
publisher identity**. GitHub's API digest helps construct a candidate; normal
builds verify the committed digest independently. No human review is invented.

## Java and RPMs

Temurin JRE 25.0.5+8 is pinned per architecture and verified by SHA-256 and
Adoptium detached GPG signature, with full fingerprint
`3B04D753C9050D9A5D343F39843C48A565F8F04B`. Public key source:
<https://packages.adoptium.net/artifactory/api/gpg/key/public>.
This follows the acquisition pattern in datopsis/neo4j-ubi. The JRE provides
all modules needed here without a runtime compiler.

The additional RPMs are zlib and libstdc++, each with architecture, NEVRA and
SHA-256. RPM signatures are checked against pinned Red Hat public keys:
`567E347AD0044ADE55BA8A5F199E2F91FD431D51` and
`7E4624258C406535D56D6F135054E4A45A6340B3`, published at
<https://security.access.redhat.com/data/fd431d51.txt> and
<https://security.access.redhat.com/data/5a6340b3.txt>.
Base-image packages are inherited through the pinned OCI digest, not independently
resolved RPM inputs. Base manifest lists and both architecture manifests have Red Hat simple-signing
signatures from the publisher sigstore. Acquisition verifies the pinned signature
bytes with the Red Hat key, then checks the signed manifest digest and repository
identity. Merely obtaining a valid GPG signature is not sufficient. OCI pulls
verify content against those signed digests.

Acquisition verifies hashes even on cache hits, validates key fingerprints,
verifies UBI and JRE signatures, checks RPM signatures and NEVRAs, rejects unsafe
archive paths, prunes plugins, and compares the resulting complete file manifest
with the lock. Assembly rechecks the manifest digest, every file digest and the
exact file count, rejects links/special files, then installs only local RPMs
with networking disabled. Public verification keys and RPM downloads are not
copied into the final runtime.

## Refresh

```sh
python3 scripts/artifacts.py refresh --output candidates/trino.lock.json
diff -u artifacts/trino.lock.json candidates/trino.lock.json
```

Refresh keeps the selected Trino version unless `--version` explicitly changes
it; resolves current UBI 9.8, JRE 25 and runtime RPMs; verifies both architectures;
and writes candidate locks only. Review the changed inputs, licences, upstream
requirements, plugin inventory and scans before adopting candidates and updating
Containerfile base defaults. No reviewed_by, reviewed_on or approval is filled
by automation. The read-only update-locks workflow uploads the candidate and diff.

Python lint dependencies have a complete `.in` and hash lock in
`.github/requirements/`; regeneration is documented in that input. ShellCheck
has its own binary digest lock. CI action references are full commit SHAs;
Syft, Trivy and Grype versions are fixed in the workflow. Vulnerability databases
are intentionally refreshed at scan time, not frozen to preserve a green result.
