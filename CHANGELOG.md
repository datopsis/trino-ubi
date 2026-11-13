# Changelog

## Unreleased

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
