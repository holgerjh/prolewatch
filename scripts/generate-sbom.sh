#!/bin/bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
target_arch=${1:?usage: generate-sbom.sh ARCH BUILD_DIR OUTPUT_DIR}
build_dir=${2:?usage: generate-sbom.sh ARCH BUILD_DIR OUTPUT_DIR}
output_dir=${3:?usage: generate-sbom.sh ARCH BUILD_DIR OUTPUT_DIR}
[[ ${target_arch} =~ ^[A-Za-z0-9_-]+$ ]] || { echo "invalid target architecture" >&2; exit 1; }
mkdir -p -- "${output_dir}"

cd -- "${project_dir}"
for name in prolewatch prolewatch-makepkg prolewatch-gpg prolewatch-net; do
  test -x "${build_dir}/${name}"
  binary_sha256=$(sha256sum -- "${build_dir}/${name}")
  binary_sha256=${binary_sha256%% *}
  # attest-sbom recognizes CycloneDX only when serialNumber is present. Use a
  # custom UUIDv8 derived from the subject binary so repeated builds retain a
  # stable SBOM instead of accepting cyclonedx-gomod's random default UUID.
  serial_uuid="${binary_sha256:0:8}-${binary_sha256:8:4}-8${binary_sha256:13:3}-8${binary_sha256:17:3}-${binary_sha256:20:12}"
  GOOS=linux GOARCH="${target_arch}" CGO_ENABLED=0 GOFLAGS="${GOFLAGS:-} -buildvcs=false" \
    go tool github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod app \
      -json -output-version 1.6 -notimestamp -serial "urn:uuid:${serial_uuid}" -packages \
      -main "cmd/${name}" -output "${output_dir}/${name}-linux-${target_arch}.cdx.json" .
done
