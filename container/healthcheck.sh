#!/usr/bin/env bash
# Liveness only. Readiness and SQL health must be probed with authenticated HTTP
# by the deployment; this probe needs no credentials and works with TLS enabled.
set -euo pipefail
IFS= read -r -d '' executable < /proc/1/cmdline
[[ $executable == /opt/java/bin/java ]]
kill -0 1
