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
go run ./cmd/prolewatch-scenarios
bash -n scripts/*.sh
installer_help=$(./scripts/install-system.sh --help)
[[ ${installer_help} == *'--assume-yes'* && ${installer_help} == *'--update-clean-root'* && ${installer_help} == *'--terminal-style'* ]] || {
  echo "installer help is missing expected options" >&2
  exit 1
}
if ./scripts/install-system.sh --invalid-option >/dev/null 2>&1; then
  echo "installer accepted an invalid option" >&2
  exit 1
fi
go test ./internal/audit -coverprofile="${coverage_profile}"

coverage=$(go tool cover -func="${coverage_profile}" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')
minimum=${PROLEWATCH_MIN_COVERAGE:-80.0}
awk -v actual="${coverage}" -v required="${minimum}" 'BEGIN { if (actual + 0 < required + 0) { printf "security package coverage %.1f%% is below %.1f%%\n", actual, required > "/dev/stderr"; exit 1 } }'

GOOS=linux GOARCH=amd64 PROLEWATCH_BUILD_DIR="${check_tmp}/build" ./scripts/build.sh
test "$(<"${check_tmp}/build/.source-fingerprint")" = "$(./scripts/source-fingerprint.sh)"
./scripts/generate-sbom.sh amd64 "${check_tmp}/build" "${check_tmp}/sbom"
test "$(find "${check_tmp}/sbom" -maxdepth 1 -type f -name '*.cdx.json' | wc -l)" -eq 6
printf 'Release checks passed; internal/audit coverage: %s%%\n' "${coverage}"
