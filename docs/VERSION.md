# Version policy

No container release version or tag is created by this increment. The selected
upstream inputs (Trino 484, Temurin 25.0.5+8 and UBI 9.8) identify dependencies,
not a Datopsis release. OCI labels identify the upstream development build and
Git revision. Notable changes remain under Unreleased in CHANGELOG.md.

Future image releases will use `v<trino-version>-ubi<ubi-version>-<revision>`.
The packaging revision starts at 1 and increases for every newly published
image with the same Trino/UBI pair, including base or Java security updates.
Tags will be immutable; deployments should pin image digests. Repository-only
changes do not create versions or tags. Publication/signing requires a separate
reviewed implementation and owner decision. A tag currently publishes nothing.
