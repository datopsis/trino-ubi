# Configuration and responsibility

The only qualified topology in this increment is one coordinator that also
executes worker tasks: `coordinator=true` and
`node-scheduler.include-coordinator=true`. Multi-node deployment is deferred.
The minimal plugin set serves generated TPCH data and the built-in system
catalog; it cannot connect to external databases or object storage.

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
root ownership with group 0 and mode 0440 on a read-only mount. Do not supply
secrets through environment variables, image layers or command arguments. Never
commit generated TLS keys, passwords or password hashes. Provision trust and
client credentials through the deployment's secret manager. Java's Temurin
truststore is retained; custom trust is the operator's responsibility.

The guard proves presence and basic policy, not certificate validity, identity
provider correctness or authorization. Upstream loads and validates material.
The first increment tests real SQL in the explicit insecure profile; full TLS,
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
configuration-syntax guards. Never expose its HTTP port beyond loopback in a
local test. `TRINO_HEAP_SIZE` is the only Java sizing override; arbitrary Java
option environment variables and command-line arguments are rejected.
