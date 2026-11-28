# Changelog

## Unreleased

- Add a guarded JWT bearer authentication profile for issuer-provided tokens:
  require HTTPS-only access, protected key material or HTTPS JWKS, explicit
  issuer, audience and principal, and retain internal TLS/shared-secret guards.
  Reject mixed authenticators and insecure opt-out for JWT; preserve PASSWORD.
- Qualify JWT on both native CI architectures with a per-run CA/HTTPS JWKS stub,
  real SQL, negative token cases, mounted public key and missing-setting guards.
  Live Rauthy login and lakehouse T13 remain integration responsibilities.

- Ship the official Trino 484 OPA access-control plugin with a pinned SHA-256,
  verified acquisition and offline assembly; leave it opt-in and preserve all
  upstream JARs and notices.
- Ship no default catalog. Move TPCH catalog configuration to a test-only fixture.
- Extend both native CI runtime suites with OPA load, unconfigured behavior,
  allow, deny and endpoint-outage fail-closed checks; document the trust boundary.

- Apply the owner-approved UBI-installable fix gate: RPM fixes available in the
  build's architecture-specific repositories block; proven unavailable fixes
  remain visible as deferred. Non-RPM fixes and query/evidence errors still block.
- Share UBI BaseOS configuration and verified metadata between lock resolution
  and vulnerability admission; compare RPM epochs, versions and releases with librpm.
- Add six-hour native rechecks and one trusted-main tracking issue, commenting
  only when the deferred set changes; preserve all required CI job names.
- Refresh RPM inputs and verified bundle hashes for amd64 and arm64; update
  libstdc++ from 11.5.0-14.el9 to UBI-published 11.5.0-17.el9_9.

- Enforce LF line endings: `.gitattributes` normalizes text to LF, a local
  pre-commit hook and CI reject any committed CRLF.
### Added

- Trino 484 core plus TPCH on digest-pinned UBI 9.8 Micro, with verified Temurin
  JRE 25 and architecture-specific RPM inputs.
- Non-root, read-only-root runtime contract and fail-closed authentication guard
  with explicit isolated-test opt-out.
- Lock refresh/admission tooling, real SQL runtime tests, native amd64/arm64 CI,
  SPDX SBOMs and blocking Trivy/Grype gates without suppressions.
- Read-only lock proposal workflow and ordered qualification/release roadmap.

### Limitations

- No publishing, signing, release version, tag or production support claim.
- Unsigned upstream Trino archives are verified by locked digest only.
- Full authentication/TLS, multi-node and platform qualification remain pending.
