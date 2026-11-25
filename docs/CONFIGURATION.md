# Configuration and responsibility

The only qualified topology in this increment is one coordinator that also
executes worker tasks: `coordinator=true` and
`node-scheduler.include-coordinator=true`. Multi-node deployment is deferred.
The minimal plugin set can serve operator-configured generated TPCH data and
the built-in system catalog, with optional OPA authorization; it cannot connect to external databases or object storage.

Mount the complete `/etc/trino` directory read-only to replace configuration.
Required files are `config.properties`, `node.properties` and `log.properties`.
Catalog configuration belongs in an optional `catalog/` directory. No catalog file is shipped by default; the
built-in `system` catalog remains available. To use TPCH, supply
`catalog/tpch.properties` containing `connector.name=tpch`. The entrypoint deliberately accepts a subset of Java
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

## Opt-in OPA authorization

The image ships the official Trino 484 OPA plugin but **does not enable it**.
Without access-control configuration, Trino retains its permissive default
access control. Authentication and the image's TLS guard are separate controls.

To enable OPA, mount `/etc/trino/access-control.properties` read-only alongside
the other operator configuration:

```properties
access-control.name=opa
opa.policy.uri=https://opa.example.com/v1/data/trino/allow
```

Supply the real endpoint and policy yourself. No OPA server, default allow rule,
credentials, or trust anchor is bundled. The endpoint must return an OPA boolean
decision, such as `{"result":false}` for denial. The plugin fails requests closed
when it cannot obtain a policy decision, including an unreachable endpoint.
An outage can therefore make SQL unavailable; plan OPA availability accordingly.
Native CI tests the upstream plugin against a protocol stub, not a deployed OPA
service or the lakehouse authorization service.

OPA becomes a trusted authorization authority. Protect policy administration,
policy distribution, DNS, endpoint integrity and availability. Use HTTPS with
validated server trust and restrict network access; configure client trust or
client authentication through upstream `opa.http-client.*` settings as required.
The HTTP stub in CI is confined to the ephemeral test runner and is not a
production configuration. Trino sends user identity, groups, requested actions,
and resource metadata to OPA. Protect that data and avoid request/response debug
logging. Extra credentials are not forwarded unless explicitly configured.

The operator must author and qualify default-deny policies for the intended
operations. Row filters, column masks and batch endpoints require additional
configuration and are not qualified by this slice. Keep
`opa.allow-permission-management-operations` at its upstream default `false`
unless deliberately reviewed: enabling it bulk-allows grant/role management
operations without asking OPA. The plugin does not supply authentication or
replace runtime hardening. See the [Trino 484 OPA documentation](https://github.com/trinodb/trino/blob/484/docs/src/main/sphinx/security/opa-access-control.md)
and the [trust-boundary diagram](diagrams/opa-trust-boundary.mmd).
