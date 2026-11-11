# Configuration and responsibility

The only qualified topology in this increment is one coordinator that also
executes worker tasks: `coordinator=true` and
`node-scheduler.include-coordinator=true`. Multi-node deployment is deferred.
The minimal plugin set serves generated TPCH data and the built-in system
catalog, plus Iceberg for operator-supplied REST catalogs and S3-compatible
storage. Other Iceberg catalog types and file systems are outside this image's
supported target; Lakekeeper/SeaweedFS queries are not yet qualified.

Mount the complete `/etc/trino` directory read-only to replace configuration.
Required files are `config.properties`, `node.properties`, `log.properties` and
`catalog/tpch.properties`. The entrypoint deliberately accepts a subset of Java
properties syntax for config/node/password-authenticator files: one ASCII
`key=value` per line, blank lines and comments beginning with `#`, no duplicate
keys, backslash escapes, control characters, continuations or `${...}` expansion.
Keys and guard values cannot have surrounding whitespace. This prevents a guard
from interpreting a security property differently from Java. Node properties
accept only `node.*` keys. Unknown Trino properties fail in upstream validation.

Default fail-closed requirements (the following are requirements, **not** a
credential-bearing deployment example):

- `http-server.authentication.type=PASSWORD`;
- `http-server.http.enabled=false`, `http-server.https.enabled=true`,
  `http-server.https.port=8443`;
- insecure-over-HTTP authentication remains false;
- `internal-communication.https.required=true` and HTTPS `discovery.uri`;
- a nonempty `internal-communication.shared-secret` supplied in the read-only
  config file, consistently across nodes if later multi-node qualification lands;
- `http-server.https.keystore.path` pointing to an operator-supplied PEM/keystore;
- `password-authenticator.properties` with `password-authenticator.name=file`
  and `file.password-file` pointing to operator-created bcrypt/PBKDF2 hashes.

The main config (which contains the internal secret), TLS file and password file
must be readable by UID 10001 but not writable by it or world-accessible. Use
root ownership with group 0 and mode 0440 on a read-only mount. For these guarded server files, do not supply secrets through environment
variables, image layers or command arguments. The optional catalog example below
uses Trino's environment secret resolver, outside the entrypoint's guarded files. Never
commit generated TLS keys, passwords or password hashes. Provision trust and
client credentials through the deployment's secret manager. Java's Temurin
truststore is retained; custom trust is the operator's responsibility.

The guard proves presence and basic policy, not certificate validity, identity
provider correctness or authorization. Upstream loads and validates material.
Native tests exercise the explicit HTTPS isolated-test profile; full
password success/failure, rotation and multi-node trust qualification remain on
the roadmap. Do not represent guard tests as authentication qualification.

Trino upstream has no authentication by default and permissive access control.
The operator must configure authorization, restrict network ingress/egress,
provide unique node IDs, disable or secure the web UI as appropriate, set heap
and query limits, and enforce read-only root, capability drop and
no-new-privileges at the container runtime. Admission policy must prevent command
or entrypoint overrides if the image guard is part of the deployment's controls.

`TRINO_UBI_ALLOW_INSECURE=true` is a deliberate opt-out, logs a warning on every
start, and is only for isolated tests. It does not relax the non-root, mount or
configuration-syntax guards. The exception now requires the [HTTPS isolated-test profile](TLS.md); plaintext
is refused. `TRINO_HEAP_SIZE` is the only Java sizing override; arbitrary Java
option environment variables and command-line arguments are rejected.

## Iceberg REST and S3 example

**Example only; not shipped as a default catalog.** Create an operator-owned
`/etc/trino/catalog/iceberg.properties` on the read-only configuration mount:

```properties
connector.name=iceberg
iceberg.catalog.type=rest
iceberg.rest-catalog.uri=${ENV:ICEBERG_REST_URI}
iceberg.rest-catalog.warehouse=${ENV:ICEBERG_WAREHOUSE}
iceberg.rest-catalog.security=OAUTH2
iceberg.rest-catalog.oauth2.token=${ENV:ICEBERG_REST_TOKEN}
iceberg.rest-catalog.vended-credentials-enabled=false
fs.s3.enabled=true
s3.endpoint=${ENV:S3_ENDPOINT}
s3.region=${ENV:S3_REGION}
s3.path-style-access=true
s3.aws-access-key=${ENV:S3_ACCESS_KEY_ID}
s3.aws-secret-key=${ENV:S3_SECRET_ACCESS_KEY}
```

Inject credentials from the deployment's secret manager into these environment
variables; never put literal credentials in the catalog, image, repository or
command arguments. Catalog files use Trino's `${ENV:...}` resolver; the strict
entrypoint syntax rules above apply to config/node/password-authenticator files,
not catalog files. No keystore secret-provider plugin is included.

Set `ICEBERG_REST_URI` to the catalog's Iceberg REST base URI (including its API
base path), and `ICEBERG_WAREHOUSE` to its warehouse identifier. Set `S3_ENDPOINT`
to the S3-compatible endpoint and `S3_REGION` to its configured signing region.
Use HTTPS with operator-provisioned trust for both endpoints. The example uses
an operator-provisioned bearer token for REST authentication and static S3
credentials; credential vending is explicitly disabled. Match authentication,
warehouse and authorization to the actual catalog deployment. This does not
configure or qualify Lakekeeper or SeaweedFS.

Property names follow Trino 484's [REST catalog documentation](https://github.com/trinodb/trino/blob/484/docs/src/main/sphinx/object-storage/metastores.md#iceberg-rest-catalog)
and [S3 documentation](https://github.com/trinodb/trino/blob/484/docs/src/main/sphinx/object-storage/file-system-s3.md).
Only startup, connector registration and catalog creation are tested here;
remote authentication, table reads/writes and S3 compatibility require the
separate cross-repository lakehouse integration test.
