#!/usr/bin/env bash
set -Eeuo pipefail
arch=${1:?usage: scripts/build.sh amd64|arm64}
runtime=${CONTAINER_RUNTIME:-podman}
python3 scripts/artifacts.py fetch --arch "$arch"
readarray -t inputs < <(python3 - "$arch" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path('artifacts/trino.lock.json'); lock=json.loads(p.read_bytes())
for value in (lock['bases']['builder']['reference'], lock['bases']['runtime']['reference'],
              lock['architectures'][sys.argv[1]]['bundle_sha256'], lock['trino']['version'],
              hashlib.sha256(p.read_bytes()).hexdigest()): print(value)
PY
)
for base in "${inputs[0]}" "${inputs[1]}"; do "$runtime" pull --platform "linux/$arch" "$base"; done
"$runtime" build --network=none --pull=false --platform "linux/$arch" \
    --build-arg "TARGETARCH=$arch" --build-arg "UBI_MINIMAL_IMAGE=${inputs[0]}" \
    --build-arg "UBI_MICRO_IMAGE=${inputs[1]}" --build-arg "BUNDLE_SHA256=${inputs[2]}" \
    --build-arg "TRINO_VERSION=${inputs[3]}" --build-arg "LOCK_SHA256=${inputs[4]}" \
    --build-arg "SOURCE_REVISION=$(git rev-parse HEAD)" --build-arg "CREATED=$(git show -s --format=%cI HEAD)" \
    --tag "${IMAGE:-localhost/trino-ubi:dev}" --file Containerfile .
