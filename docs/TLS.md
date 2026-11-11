# Phase A HTTPS isolated-test profile

Implements item 5 of the [pinned lakehouse TLS plan](https://github.com/datopsis/lakehouse-integration/blob/55b8e83374375210bc06fa117c9a0954d66bd593/docs/TLS-PLAN.md).
Qualification is pending native CI. This branch includes the plan's exact
Iceberg baseline, commit `964802b7afd3ae526039ef7dc7fcf605ce3d5b26` (PR #2).
Its known fixed High vulnerabilities remain blocking. No dependency or JAR is
changed relative to that baseline; this is not a vulnerability exemption.

`TRINO_UBI_ALLOW_INSECURE=true` now waives authentication only. It requires
HTTPS-only ingress on 8443, HTTPS discovery, explicit internal keystore and
truststore, an internal shared secret and `node.internal-address`. The previous
plaintext isolated-test profile is refused. Default authentication still
requires PASSWORD and the guarded password file. This profile does not provide
authorization or production qualification.

Mount the operator's complete `/etc/trino` and its own `/run/tls` read-only.
Keep UID 10001:GID 0, read-only root, all capabilities dropped,
no-new-privileges and the existing data/native-temp tmpfs restrictions. Use
root:0, mode 0440 files and mode 0750 directories. Never mount other services'
private keys or the CA signing directory. Never commit or bake certificates,
keys, passwords or generated configuration into images.

Required `config.properties` transport fields (supply the shared secret through
the read-only file, replacing the placeholder before deployment):

```properties
coordinator=true
node-scheduler.include-coordinator=true
http-server.http.enabled=false
http-server.https.enabled=true
http-server.https.port=8443
http-server.https.keystore.path=/run/tls/server.pem
internal-communication.https.required=true
internal-communication.https.keystore.path=/run/tls/server.pem
internal-communication.https.truststore.path=/run/tls/ca.crt
internal-communication.shared-secret=<operator-generated-per-run-secret>
discovery.uri=https://trino:8443
http-server.log.enabled=false
```

`server.pem` contains this service's unencrypted private key and certificate
chain. `ca.crt` contains public CA material only. Explicit stores avoid Trino's
automatic internal certificate branch. Set `node.internal-address=trino` in
`node.properties`; include `DNS:trino` in the leaf SAN. Keep the existing memory
limits, node identity and data-directory settings.

Create image-owned `/etc/trino/truststore.properties`, with exactly these keys:

```properties
path=/run/tls/trust.p12
type=PKCS12
password-file=/run/tls/truststore-password
```

The PKCS12 store contains the operator's public root certificate. Its password
file contains a fresh 16–128 character alphanumeric password. The entrypoint
validates read-only private permissions, restricted properties syntax, allowed
keys/type, and keytool loading before exec. It emits only
`javax.net.ssl.trustStore`, `javax.net.ssl.trustStoreType` and
`javax.net.ssl.trustStorePassword`. The password consequently exists in Java's
process arguments: do not export process listings in diagnostics. General
`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` and command overrides
remain forbidden. No arbitrary `jvm.config` is accepted.

Set `iceberg.rest-catalog.uri=https://catalog:8181/catalog` and
`s3.endpoint=https://s3:8333` in the operator's Iceberg catalog. Retain static
credentials, path-style access and
`iceberg.rest-catalog.vended-credentials-enabled=false`. JVM trust configures
Iceberg's HTTP client and AWS Apache5; internal Airlift clients use the explicit
internal truststore independently. Inbound truststore configuration alone does
not configure these outbound clients.

Run `CONTAINER_RUNTIME=docker IMAGE=localhost/trino-ubi:dev python3 tests/runtime.py`
on each native architecture. The harness uses OpenSSL and the real image's
keytool, with no additional Python dependency. It issues RSA-3072/SHA-256 test
roots valid for 24 hours and matching-SAN leaves valid for six hours (five-minute
not-before allowance). Wrong-root, correct-CN/wrong-SAN, other-service and expired
leaves are issued before services start; signing keys are then removed. No host
clock changes, trust-all managers or verification downgrades are used.

The native runner uses host networking for ephemeral loopback protocol fixtures;
this is a test arrangement, not a deployment recommendation. It checks both
address families, old port 8080, and JVM-owned listening sockets. REST namespace
requests and signed S3 metadata reads exercise the shipped connector through
SQL against small protocol fixtures. These are client TLS tests, not
Lakekeeper/SeaweedFS compatibility or complete lakehouse acceptance evidence.
Every mutation uses a fresh JVM and valid controls before and after. Generated
certificate metadata and outcomes go to `reports/tls.json`; only sanitized
reports are uploaded. Keys/configuration are removed in `finally`; raw failure
diagnostics remain under ignored `.runtime/diagnostics` on the runner only.

No Phase A completion claim is made until native per-edge negatives and the
separate cross-service Integration gate pass. Password authentication,
authorization, rotation, revocation and multi-node qualification remain separate.

Trino 484's default ANNOUNCE inventory skips discovery announcements when the
coordinator URI equals its own advertised URI. The internal discovery rehearsal
therefore explicitly retains `https://127.0.0.1:8443` as a distinct URI and adds
that exact IP SAN to Trino's test leaf; it does not certify bridge addresses.
The separate self-worker rehearsal keeps that discovery path valid and routes
the advertised Trino name through a TLS-to-TLS mutation relay on 127.0.0.2.
The relay negotiates HTTP/2, verifies the real Trino server with the run CA, and
never records application bytes. The real Trino task client must reject each
mutated relay certificate during a TPCH query. A per-client announcer truststore
keeps discovery valid when testing a wrong self-worker trust bundle. This fixture
routing is solely for independent negative evidence, not an image dependency or
a deployment proxy requirement.

For internal failures the rehearsal enables Airlift 451's per-client request
events on the data tmpfs. The inspected `HttpClientLogLayout` records method,
URI, result/failure class and timings, not headers, bodies or certificate bytes.
The ordinary announcer warning wraps its TLS cause as a generic communication
error, which is insufficient evidence. Acceptance requires the originating
announcer/scheduler request's `SSLHANDSHAKE` result (or a TLS-specific nested
exception), plus successful real operations before and after. Only the parsed
allowlisted result is included in the uploaded manifest.
