#!/bin/bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
check_tmp=$(mktemp -d /tmp/prolewatch-release.XXXXXX)
trap 'rm -rf -- "${check_tmp}"' EXIT
coverage_profile=${PROLEWATCH_COVERAGE_PROFILE:-${check_tmp}/coverage.out}

cd -- "${project_dir}"
for command in /usr/bin/bwrap /usr/bin/bsdtar; do
  if [[ ! -x ${command} ]]; then
    printf 'Release checks require %s (Arch: bubblewrap/libarchive; Ubuntu: bubblewrap/libarchive-tools).\n' "${command}" >&2
    exit 1
  fi
done
go mod verify
go tool golang.org/x/vuln/cmd/govulncheck ./...
go test -race ./...
go vet ./...
"$(dirname "$0")/check-import-direction.sh"
go run ./cmd/prolewatch-scenarios
bash -n scripts/*.sh scripts/probes/*.sh
# Release invariant 1: prolewatch adds no passwordless privileged interface.
# Assert the invariant against the tree.
# Not `$(find ... 2>/dev/null)`: under set -e a failing find kills the script
# with its only diagnostic discarded, so the explicit directory checks keep
# gate failures visible.
for required_dir in share packaging; do
  [[ -d ${required_dir} ]] || { printf 'release-check: %s/ is missing\n' "${required_dir}" >&2; exit 1; }
done
privileged_assets=$(find share/ packaging/ -type f \
  \( -name '*.service' -o -name '*.socket' -o -name '*.sysusers' \
     -o -name '*.tmpfiles' -o -name '*.hook' -o -name '*.rules' \))
if [[ -n ${privileged_assets} ]]; then
  printf 'a system unit, socket, sysusers, tmpfiles, hook or udev rule reappeared:\n%s\n' \
    "${privileged_assets}" >&2
  exit 1
fi
if grep -rn 'NOPASSWD\|/etc/sudoers' --include='*.go' --include='*.sh' --include='*.in' . 2>/dev/null \
   | grep -v '^./docs/' | grep -v '^./scripts/release-check.sh:' | grep -q .; then
  echo "a sudoers or NOPASSWD reference reappeared" >&2
  exit 1
fi

# Coverage is measured across every internal package so the gate cannot pass
# while an internal subsystem is entirely untested.
go test ./internal/... -coverprofile="${coverage_profile}"

coverage=$(go tool cover -func="${coverage_profile}" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')
# 72% across every internal package. This is a regression gate, not a target:
# it sits a little below the current figure so ordinary work does not trip it,
# and the way to ratchet is to raise it deliberately after adding tests.
minimum=${PROLEWATCH_MIN_COVERAGE:-72.0}
awk -v actual="${coverage}" -v required="${minimum}" 'BEGIN { if (actual + 0 < required + 0) { printf "internal coverage %.1f%% is below %.1f%%\n", actual, required > "/dev/stderr"; exit 1 } }'

GOOS=linux GOARCH=amd64 PROLEWATCH_BUILD_DIR="${check_tmp}/build" ./scripts/build.sh
test "$(<"${check_tmp}/build/.source-fingerprint")" = "$(./scripts/source-fingerprint.sh)"
./scripts/generate-sbom.sh amd64 "${check_tmp}/build" "${check_tmp}/sbom"
test "$(find "${check_tmp}/sbom" -maxdepth 1 -type f -name '*.cdx.json' | wc -l)" -eq 4
printf 'Release checks passed; internal coverage: %s%%\n' "${coverage}"
