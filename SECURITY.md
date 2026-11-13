# Security policy

No production-supported release exists. Do not use this development increment
as evidence of FIPS validation, STIG certification or platform qualification.

Report vulnerabilities through GitHub private vulnerability reporting if enabled,
or contact the repository owner privately. Do not put credentials or exploit
material in public issues. Enabling private reporting, branch protections or
other repository/org settings is an owner action; this work changes none.

Every native image is scanned with Trivy and Grype using refreshed databases.
The owner-approved organization policy (2026-11-12) gates fixable High/Critical
findings on fixes installable from the same UBI repositories used for the build.
For positively identified Red Hat RPMs, the gate queries fresh metadata from
`artifacts/ubi.repo`, shared with the RPM lock resolver, for the native architecture
or noarch. This image acquires RPMs from UBI 9 BaseOS and assembles them offline;
it does not use host repositories, RHEL subscription repositories or AppStream.
An available version at or above any scanner-reported vendor fixed version blocks,
using librpm epoch/version/release ordering. RPM names and fixes come from scanner
evidence; there are no CVE, package or date exemptions.

Only a successful query proving the fix absent allows **deferred** admission.
Deferred findings remain vulnerabilities, not remediations. The job summary and
JSON evidence retain each vendor fixed version, decision, candidate versions and
queried repository configuration. Query errors/timeouts, missing or corrupt
repositories, unparsable versions, ambiguous RPM identity/architecture and missing
scanner reports fail closed. Every fixable non-RPM finding (including bundled
JARs and Go/Rust/Python/npm components) continues to block. Unfixed findings remain
visible in the complete reports. Embedded upstream JAR findings must be fixed by
an upstream update, not silently replaced or excluded from scans.

Native CI rechecks every six hours. Only scheduled or manually dispatched runs
on `main` may maintain the single UBI tracking issue; the tracker is skipped on
PRs. Its sole write permission is `issues: write`. It comments only when the
deferred set changes, including removal when a fix becomes installable. It closes
when the set is empty and reopens the same issue if deferrals return. Missing or
failed query evidence fails the tracker without claiming resolution. Scanner
reports and SBOMs are retained for 14 days even when admission blocks. No
report-only job substitutes for the gate, and required job names are unchanged.

Trino tarballs/ZIPs are digest-only inputs without publisher-signature assurance.
UBI manifest, Temurin JRE and added Red Hat RPM signatures are verified. Preserve the runtime
guard, read-only configuration, UID 10001, explicit writable paths, capability
drop and no-new-privileges contract. See docs/CONFIGURATION.md for deployment
responsibilities and the limits of the authentication guard.
