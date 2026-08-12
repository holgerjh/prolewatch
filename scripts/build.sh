#!/bin/bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
build_dir=${PROLEWATCH_BUILD_DIR:-"${project_dir}/build"}
mkdir -p -- "${build_dir}"
binaries=(prolewatch prolewatch-makepkg prolewatch-gpg provider-dispatch prolewatch-net prolewatch-build-dispatch)
fingerprint_file=${build_dir}/.source-fingerprint
rm -f -- "${fingerprint_file}"
if [[ ${PROLEWATCH_KEEP_BUILD:-0} != 1 ]]; then
  for binary in "${binaries[@]}"; do
    rm -f -- "${build_dir}/${binary}"
  done
fi

source_fingerprint=$("${project_dir}/scripts/source-fingerprint.sh")

build_one() {
  local name=$1
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-buildid=" -o "${build_dir}/${name}" "${project_dir}/cmd/${name}"
}

for binary in "${binaries[@]}"; do
  build_one "${binary}"
done

if [[ $("${project_dir}/scripts/source-fingerprint.sh") != "${source_fingerprint}" ]]; then
  printf 'Source files changed during the build; run make build again.\n' >&2
  exit 1
fi
printf '%s\n' "${source_fingerprint}" >"${fingerprint_file}"
