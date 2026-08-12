#!/bin/bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
target_arch=${1:?usage: generate-sbom.sh ARCH BUILD_DIR OUTPUT_DIR}
build_dir=${2:?usage: generate-sbom.sh ARCH BUILD_DIR OUTPUT_DIR}
output_dir=${3:?usage: generate-sbom.sh ARCH BUILD_DIR OUTPUT_DIR}
[[ ${target_arch} =~ ^[A-Za-z0-9_-]+$ ]] || { echo "invalid target architecture" >&2; exit 1; }
mkdir -p -- "${output_dir}"

cd -- "${project_dir}"
for name in prolewatch prolewatch-makepkg prolewatch-gpg provider-dispatch prolewatch-net prolewatch-build-dispatch; do
  test -x "${build_dir}/${name}"
  GOOS=linux GOARCH="${target_arch}" CGO_ENABLED=0 GOFLAGS="${GOFLAGS:-} -buildvcs=false" \
    go tool github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod app \
      -json -output-version 1.6 -noserial -notimestamp -packages \
      -main "cmd/${name}" -output "${output_dir}/${name}-linux-${target_arch}.cdx.json" .
done
