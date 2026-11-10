# Artifact acquisition

`artifacts/trino.lock.json` pins both UBI 9.8 manifest lists and their amd64/arm64
child manifests and their Red Hat signatures, upstream core/TPCH/Iceberg archives,
Temurin JREs and detached signatures,
public verification keys, added RPMs, and each extracted bundle manifest.
The canonical build consumes this committed lock; only refresh resolves versions.

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
remains. Separately published TPCH and Iceberg ZIPs supply the data connectors.
All other plugin directories, the separate keystore-secrets-plugin directory,
and upstream daemon launchers are removed. Native
libraries embedded in retained JARs remain upstream bytes, not rebuilt code.

No detached Trino tarball or plugin ZIP signature is published. The lock's
SHA-256 is this project's reviewable record of exact bytes, **not proof of
publisher identity**. GitHub's API digest helps construct a candidate; normal
builds verify the committed digest independently. No human review is invented.

## Iceberg plugin inventory

The official `trino-iceberg-484.zip` is 266,094,206 bytes. An independent download
and SHA-256 calculation matched
`eba73e90f063cd4cdc376af1f517e3314b568b250561ab51e817bd342497639a`.
It uses the same digest-only admission as TPCH: no detached publisher signature
is published and the digest is not proof of publisher identity.

The ZIP contains 317 JARs totaling 266,025,104 uncompressed bytes (253.70 MiB),
including its service descriptor JAR. The complete upstream dependency closure
is retained: Iceberg API/core/REST, Trino connector and shared Hive,
metastore and filesystem code, Parquet/ORC/Avro readers and codecs, AWS SDK/S3,
HTTP/authentication, telemetry, and upstream catalog/filesystem adapters for
Glue, JDBC/PostgreSQL, Nessie, Snowflake, Azure and GCS. These extra adapters do
not extend this image's supported target beyond REST + S3. Shared classes are
linked across modules; keeping upstream dependencies avoids an unproven custom
classpath. Embedded upstream licences and notices remain intact. No JARs are
patched and the blocking gate scans all retained components.

Both architecture bundle manifests include the plugin's exact file bytes.
Acquisition checks official release URLs, ZIP layout, traversal and symlinks;
refresh includes Iceberg when generating a new candidate lock. An Iceberg-only
change recomputes both bundle manifests from the existing pinned inputs, without
resolving unrelated base/JRE/RPM updates. `tests/runtime.py` verifies plugin
registration without a default catalog and loads a read-only mounted REST/S3
catalog with static credentials and path-style access on the hardened runtime.
Actual Lakekeeper and SeaweedFS operations belong to a later integration test.

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
