ARG UBI_MINIMAL_IMAGE="registry.access.redhat.com/ubi9/ubi-minimal:9.8@sha256:f26ef64172ea61f5ac5ba4be8c5c738bf8760b22b3e5148ce7b40f7308ab32db"
ARG UBI_MICRO_IMAGE="registry.access.redhat.com/ubi9/ubi-micro:9.8@sha256:d3499a0896e2d6a1642f922615831bc5c2fd513bbb34f3446cabba530d9d54a2"
FROM ${UBI_MICRO_IMAGE} AS micro
FROM ${UBI_MINIMAL_IMAGE} AS builder
ARG TARGETARCH
ARG BUNDLE_SHA256
COPY .artifact-bundle/${TARGETARCH}/ /bundle/
COPY --from=micro / /final/
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# Admission verifies publisher signatures; assembly verifies the locked file set.
RUN test -n "${BUNDLE_SHA256}" \
    && echo "${BUNDLE_SHA256}  /bundle/SHA256SUMS" | sha256sum --check --strict - \
    && cd /bundle && sha256sum --check --strict SHA256SUMS \
    && test "$(find . -type f ! -path ./SHA256SUMS | wc -l)" = "$(wc -l < SHA256SUMS)" \
    && test -z "$(find . ! -type f ! -type d -print -quit)" \
    && rpmkeys --root /final --checksig /bundle/rpms/*.rpm \
    && rpm --root /final --upgrade /bundle/rpms/*.rpm \
    && mkdir -p /final/opt /final/var/lib/trino /final/tmp/trino \
    && cp -a /bundle/trino /final/opt/trino \
    && cp -a /bundle/jre /final/opt/java \
    && ln -s /etc/trino /final/opt/trino/etc \
    && rm -rf /final/etc/yum.repos.d /final/etc/pki/rpm-gpg /final/etc/rhsm /final/etc/dnf \
    && rpm --root /final -qa 'gpg-pubkey*' > /tmp/keys \
    && while read -r key; do rpm --root /final -e "$key"; done < /tmp/keys \
    && find /final -xdev -type f -perm /6000 -exec chmod a-s {} + \
    && chmod -R go-w /final/opt \
    && chown 10001:0 /final/var/lib/trino /final/tmp/trino \
    && chmod 0750 /final/var/lib/trino /final/tmp/trino \
    && printf 'trino:x:10001:0:Trino:/var/lib/trino:/sbin/nologin\n' >> /final/etc/passwd
FROM ${UBI_MICRO_IMAGE}
ARG TRINO_VERSION
ARG SOURCE_REVISION
ARG CREATED
ARG LOCK_SHA256
ARG UBI_MICRO_IMAGE
LABEL org.opencontainers.image.title="Trino on UBI 9" \
      org.opencontainers.image.source="https://github.com/datopsis/trino-ubi" \
      org.opencontainers.image.licenses="Apache-2.0 AND GPL-2.0-with-classpath-exception" \
      org.opencontainers.image.version="${TRINO_VERSION}-development" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      io.datopsis.artifact-lock.sha256="${LOCK_SHA256}" \
      io.datopsis.ubi.runtime="${UBI_MICRO_IMAGE}"
COPY --from=builder /final/ /
# COPY overlays the base; repeat deletions so inherited files cannot reappear.
RUN rm -rf /etc/yum.repos.d /etc/pki/rpm-gpg /etc/rhsm /etc/dnf
COPY --chmod=0555 container/entrypoint.sh /usr/local/bin/trino-entrypoint
COPY --chmod=0555 container/healthcheck.sh /usr/local/bin/trino-healthcheck
COPY --chmod=0444 container/config.properties container/node.properties container/log.properties /etc/trino/
COPY --chmod=0444 container/catalog/ /etc/trino/catalog/
COPY --chmod=0444 LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/trino-ubi/
ENV LANG=C.UTF-8 TZ=UTC JAVA_HOME=/opt/java PATH="/opt/java/bin:/usr/bin:/bin"
USER 10001:0
WORKDIR /opt/trino
EXPOSE 8080 8443
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=120s --retries=3 CMD ["/usr/local/bin/trino-healthcheck"]
ENTRYPOINT ["/usr/local/bin/trino-entrypoint"]
CMD []
