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

- exactly `http-server.authentication.type=PASSWORD` or `JWT`;
- `http-server.http.enabled=false`, `http-server.https.enabled=true`,
  `http-server.https.port=8443`;
- insecure-over-HTTP authentication remains false;
- `internal-communication.https.required=true` and HTTPS `discovery.uri`;
- a nonempty `internal-communication.shared-secret` supplied in the read-only
  config file, consistently across nodes if later multi-node qualification lands;
- `http-server.https.keystore.path` pointing to an operator-supplied PEM/keystore;
- for PASSWORD, `password-authenticator.properties` with `password-authenticator.name=file`
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
Native CI tests real SQL in the explicit insecure profile and the guarded JWT
profile with verified TLS and an ephemeral HTTPS JWKS stub. Rauthy deployment,
browser login, rotation and multi-node trust qualification remain separate work.

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

## Guarded JWT authentication

This profile accepts bearer JWTs obtained by a client from Rauthy or another
trusted issuer. It does not implement an OpenID browser login or token exchange:
Trino's separate OAUTH2 authenticator is outside this profile. The client obtains
the token and submits it as `Authorization: Bearer <token>` (JDBC `accessToken`).
Configure all the common TLS, internal-secret and file protections above, then:

```properties
http-server.authentication.type=JWT
http-server.authentication.jwt.key-file=https://rauthy.example.com/auth/v1/oidc/certs
http-server.authentication.jwt.required-issuer=https://rauthy.example.com/auth/v1
http-server.authentication.jwt.required-audience=trino
http-server.authentication.jwt.principal-field=sub
```

These are illustrative identifiers, not a deployable Rauthy configuration. Use
that deployment's discovery metadata for the exact issuer and JWKS URL, its
client audience, and a stable identity claim aligned with authorization policy.
Issuer, audience and principal-field must be explicitly nonempty and contain no
whitespace; upstream defaults do not satisfy the guard. No password-authenticator
file is needed for JWT. A missing token or invalid signature/claims receives 401.

The key source must be an HTTPS JWKS URL with a host and no embedded credentials,
whitespace or fragment, or an absolute mounted PEM/HMAC key-file path protected
like the TLS/password files above. HTTP URLs, relative paths and dynamic `${KID}`
paths are refused. HTTPS server trust and hostname verification remain enabled.
For a private CA, configure `jwk.http-client.trust-store-path` with an
operator-provisioned truststore (including PEM CA certificates); do not disable
TLS verification. The issuer/JWKS service and its trust roots are authentication
authorities: restrict administration, DNS and network access, and plan key
rotation and outages. Local HMAC keys are secrets; prefer asymmetric JWKS so
verifiers cannot mint tokens. No trust anchor or key is baked into the image.

Only one authenticator is supported. Although upstream supports combinations,
`JWT,PASSWORD` and other lists are refused: fallback could admit identities outside
the required issuer/audience boundary and needs its own policy and qualification.
JWT guards apply even if `TRINO_UBI_ALLOW_INSECURE=true`; that flag cannot relax
this profile. Plaintext HTTP must be explicitly off, HTTPS on at 8443, internal
HTTPS and HTTPS discovery enabled, and the shared secret and TLS material present.
Each missing required setting fails startup with a diagnostic naming the guard.

Both native CI architectures test a valid RS256 token and configured principal
with real SQL, an HTTPS JWKS stub with a per-run CA, and a mounted public key.
Expired, wrong-audience, wrong-issuer, wrong-key, unsigned (`alg=none`),
missing-principal and missing tokens must all return 401. Startup tests remove
every required setting and reject insecure and mixed configurations, including
attempted insecure opt-out. This is stub-based qualification, not evidence of a
live Rauthy deployment or lakehouse T13 completion. See the
[Trino 484 JWT contract](https://github.com/trinodb/trino/blob/484/docs/src/main/sphinx/security/jwt.md).

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
