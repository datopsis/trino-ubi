# Ordered remaining work

This is an unreleased development increment. Completion requires evidence, not
checked boxes or invented human sign-off. Draft container-hardening criteria
informed the design but are not a dependency or a conformance claim.

1. **Close the initial increment's evidence gaps.** Retain native amd64/arm64
   build, real SQL, restricted runtime, SBOM and both scanner reports. Fixed
   High/Critical upstream findings remain blocking until an upstream update
   removes them. Add positive TLS/password and authorization qualification.
2. **Lakehouse integration in a separate repository.** This image now packages
   Iceberg for REST + S3 with static credentials and path-style access, without
   a default catalog. Native CI covers plugin/catalog startup only. Qualify
   Lakekeeper + SeaweedFS table creation, reads/writes, credentials and endpoint
   behavior in the cross-repository integration test before claiming that stack
   works. Other Iceberg catalog types and file systems remain out of scope.
3. **SCAP evidence.** Choose image-owned rules with rationale, pin content and
   tools, collect results per architecture, and cross-check on a representative
   RHEL host. Keep host/deployment responsibilities explicit; no STIG/FIPS claim.
4. **Release signing and publishing.** Design a separately reviewed workflow
   with immutable version tags, multi-architecture manifests, keyless signatures,
   SBOM/provenance attestations and post-publication verification. The owner must
   establish repository protections, review requirements, registry permissions
   and any environments/secrets. This increment does not change them or publish.
5. **Deeper qualification.** Multi-node coordinator/worker discovery, shared-secret
   mismatch, TLS trust/rotation, authorization denial, graceful draining, resource
   bounds, sustained query load, upgrade/rollback, arbitrary-UID Podman, restricted
   Kubernetes/OpenShift and disconnected operation. Add external connectors only
   with a stated use case, dependency review, licence review and real integration
   tests. Record exact platform versions before claiming support.
6. **Supply-chain improvements.** SBOM coverage checks, source/malware scanning, reproducibility analysis, long-term
   evidence retention and automated security-update proposals.
