# Security policy

No production-supported release exists. Do not use this development increment
as evidence of FIPS validation, STIG certification or platform qualification.

Report vulnerabilities through GitHub private vulnerability reporting if enabled,
or contact the repository owner privately. Do not put credentials or exploit
material in public issues. Enabling private reporting, branch protections or
other repository/org settings is an owner action; this work changes none.

Every native image is scanned with Trivy and Grype using refreshed databases.
Any fixed High/Critical finding fails CI; unfixed findings remain visible in the
complete reports. Missing reports fail too. There are no suppressions. Embedded
upstream JAR findings must be fixed by an upstream update, not silently replaced
or excluded from scans. No report-only job substitutes for the blocking gate.

Trino tarballs/ZIPs are digest-only inputs without publisher-signature assurance.
Temurin JRE and added Red Hat RPM signatures are verified. Preserve the runtime
guard, read-only configuration, UID 10001, explicit writable paths, capability
drop and no-new-privileges contract. See docs/CONFIGURATION.md for deployment
responsibilities and the limits of the authentication guard.
