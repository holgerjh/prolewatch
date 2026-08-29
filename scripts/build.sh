#!/bin/bash
set -euo pipefail
umask 022

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
build_dir=${PROLEWATCH_BUILD_DIR:-"${project_dir}/build"}
mkdir -p -- "${build_dir}"
binaries=(prolewatch prolewatch-makepkg prolewatch-gpg prolewatch-net)
fingerprint_file=${build_dir}/.source-fingerprint
# Remove binaries that are not part of the package so an incremental build
# cannot leave extra executables for packaging to pick up.
obsolete_binaries=(prolewatch-build-dispatch provider-dispatch prolewatch-rootd prolewatch-fetchd prolewatch-providerd prolewatch-sandbox-launch)
staging_dir=$(mktemp -d "${build_dir}/.prolewatch-build.XXXXXX")
trap 'rm -rf -- "${staging_dir}"' EXIT

source_fingerprint=$("${project_dir}/scripts/source-fingerprint.sh")
go_binary=${PROLEWATCH_GO:-$(command -v go)}
[[ ${go_binary} == /* && -x ${go_binary} ]] || {
  printf 'PROLEWATCH_GO must resolve to an absolute executable Go tool.\n' >&2
  exit 1
}
build_home=${PROLEWATCH_BUILD_HOME:-${HOME:-}}
[[ ${build_home} == /* ]] || {
  printf 'A private absolute HOME or PROLEWATCH_BUILD_HOME is required.\n' >&2
  exit 1
}
go_path=$(dirname -- "${go_binary}"):/usr/bin
# A minimum, not a pin. go.mod's directive is the language version this code
# needs; Arch ships the newest Go and go.mod necessarily lags it, so demanding
# equality meant the documented install broke on every Go release - while
# packaging/arch/PKGBUILD.in declared `go>=1.26.6` and promised the opposite.
#
# Byte-for-byte reproduction of a published release artifact does need the exact
# go.mod toolchain. CI gets that by construction: release.yml installs Go with
# `go-version-file: go.mod`, so the version is pinned where reproducibility is
# actually claimed rather than everywhere a user tries to build.
required_go=$(awk '$1 == "go" { print $2; exit }' "${project_dir}/go.mod")
actual_raw=$(env -i HOME="${build_home}" PATH="${go_path}" GOENV=off GOTOOLCHAIN=local "${go_binary}" env GOVERSION)
# GOVERSION carries distribution suffixes: go1.27.0-X:nodwarf5 on Arch, or a
# +suffix elsewhere. Compare the numeric release only.
actual_go=${actual_raw#go}
actual_go=${actual_go%%[-+ ]*}
[[ ${required_go} =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ && ${actual_go} =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || {
  printf 'Cannot read Go versions: go.mod says %s, toolchain reports %s.\n' "${required_go}" "${actual_raw}" >&2
  exit 1
}
if [[ ${actual_go} != "${required_go}" ]] &&
  [[ $(printf '%s\n%s\n' "${required_go}" "${actual_go}" | sort -V | head -1) != "${required_go}" ]]; then
  printf 'Go is too old: go.mod requires %s or newer, found %s.\n' "${required_go}" "${actual_raw}" >&2
  exit 1
fi
go_cache=${PROLEWATCH_GOCACHE:-${build_dir}/.cache/go-build}
module_cache=${PROLEWATCH_GOMODCACHE:-$(env -i HOME="${build_home}" PATH="${go_path}" GOENV=off GOTOOLCHAIN=local "${go_binary}" env GOMODCACHE)}
temporary_root=${TMPDIR:-/tmp}
[[ ${go_cache} == /* && ${module_cache} == /* && ${temporary_root} == /* ]] || {
  printf 'Go cache and temporary paths must be absolute.\n' >&2
  exit 1
}
mkdir -p -- "${go_cache}" "${module_cache}"
proxy=https://proxy.golang.org,direct
sumdb=sum.golang.org
module_mode=${PROLEWATCH_GO_MOD_MODE:-readonly}
[[ ${module_mode} == readonly || ${module_mode} == vendor ]] || {
  printf 'PROLEWATCH_GO_MOD_MODE must be readonly or vendor.\n' >&2
  exit 1
}
if [[ ${PROLEWATCH_OFFLINE:-0} == 1 ]]; then
  proxy=off
  sumdb=off
fi
go_environment=(
  env -i
  HOME="${build_home}"
  PATH="${go_path}"
  TMPDIR="${temporary_root}"
  LANG=C.UTF-8
  LC_ALL=C.UTF-8
  CGO_ENABLED=0
  GOENV=off
  GOTOOLCHAIN=local
  GOWORK=off
  GOFLAGS="-mod=${module_mode}"
  GOCACHE="${go_cache}"
  GOMODCACHE="${module_cache}"
  GOPROXY="${proxy}"
  GOSUMDB="${sumdb}"
  GOPRIVATE=
  GONOPROXY=
  GONOSUMDB=
)
if [[ -n ${GOOS:-} ]]; then
  go_environment+=(GOOS="${GOOS}")
fi
if [[ -n ${GOARCH:-} ]]; then
  go_environment+=(GOARCH="${GOARCH}")
fi
if [[ ${module_mode} == readonly ]]; then
  "${go_environment[@]}" "${go_binary}" mod verify
fi

build_one() {
  local name=$1
  "${go_environment[@]}" "${go_binary}" build -mod="${module_mode}" -trimpath -buildvcs=false -ldflags="-buildid=" \
    -o "${staging_dir}/${name}" "${project_dir}/cmd/${name}"
  chmod 0755 "${staging_dir}/${name}"
}

for binary in "${binaries[@]}"; do
  build_one "${binary}"
done

if [[ $("${project_dir}/scripts/source-fingerprint.sh") != "${source_fingerprint}" ]]; then
  printf 'Source files changed during the build; run make build again.\n' >&2
  exit 1
fi
printf '%s\n' "${source_fingerprint}" >"${staging_dir}/.source-fingerprint"
chmod 0644 "${staging_dir}/.source-fingerprint"
for binary in "${binaries[@]}"; do
  mv -f -- "${staging_dir}/${binary}" "${build_dir}/${binary}"
done
mv -f -- "${staging_dir}/.source-fingerprint" "${fingerprint_file}"
for binary in "${obsolete_binaries[@]}"; do
  rm -f -- "${build_dir}/${binary}"
done
