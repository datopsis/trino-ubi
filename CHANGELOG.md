# Changelog

## Unreleased

### Added

- Official digest-pinned Trino 484 Iceberg plugin for operator-supplied REST
  catalogs and S3-compatible storage with static credentials and path-style
  access; no default Iceberg catalog. Documented an environment-secret example.
- Hardened runtime checks for Iceberg registration and a mounted REST/S3 catalog
  on native amd64/arm64; Lakekeeper/SeaweedFS queries remain separate work.

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
