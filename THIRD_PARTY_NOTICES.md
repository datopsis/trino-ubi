# Third-party notices

Repository packaging is Apache-2.0 (LICENSE). Trino 484 is Apache-2.0; its NOTICE
and dependency licence files embedded in JARs are retained. Retained plugins
are the upstream password authenticators and TPCH generator; no connector licence
is asserted to cover the entire dependency graph.

Eclipse Temurin OpenJDK is GPL version 2 with the Classpath Exception and carries
additional component notices. Its `legal/` tree and release metadata are retained
under `/opt/java`. Corresponding sources are available from
<https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8> and
<https://github.com/adoptium/jdk25u>. Review source-delivery obligations before
publishing a release; this increment publishes nothing.

UBI redistribution is governed by Red Hat's UBI terms and each included package's
licence, not this repository's Apache licence. Preserve RPM licence metadata and
installed licence files. See <https://www.redhat.com/en/about/agreements>.

Public verification keys in artifacts/keys are used only to verify build inputs;
no private key, runtime credential or default password is distributed. No
publisher-signature assurance is claimed for the unsigned Trino archives.
