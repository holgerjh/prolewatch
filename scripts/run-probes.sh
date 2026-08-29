#!/usr/bin/env bash
# Run the source-tree probes.
#
# probe-redirect-chains.sh is excluded: it measures live CDN topology and drifts
# by design. Run it by hand when registry behaviour is in question.
#
# With PROLEWATCH_PROBE_STRICT=1, a probe that skips is a failure.
#
# Two probes print SKIP and exit 0 when their prerequisites are absent, which is
# correct in a source tree and wrong for release acceptance: a probe that never
# ran is not evidence that the thing it tests works, and a run that reports
# success without having tested anything is the worst possible acceptance
# record. probe-yay-interception.sh is the one that matters here - it is the
# only check that drives a real yay transaction through the installed hook and
# both wrappers, so every other test in this repository exercises components
# through seams while that one exercises the product.
set -uo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
strict=${PROLEWATCH_PROBE_STRICT:-0}
status=0
skipped=()

probes=("$@")
if [ ${#probes[@]} -eq 0 ]; then
  for probe in "${project_dir}"/scripts/probes/probe-*.sh; do
    case "${probe}" in *redirect-chains*) continue ;; esac
    probes+=("${probe}")
  done
fi

for probe in "${probes[@]}"; do
  name=$(basename -- "${probe}")
  printf '== %s\n' "${name}"
  capture=$(mktemp)
  # tee, not capture-then-print: a contained makepkg probe takes long enough
  # that watching it matters, and PIPESTATUS still carries the real exit code.
  bash "${probe}" 2>&1 | tee "${capture}"
  code=${PIPESTATUS[0]}
  if grep -q '^SKIP:' "${capture}"; then
    skipped+=("${name}")
  fi
  rm -f -- "${capture}"
  if [ "${code}" -ne 0 ]; then
    printf 'FAILED: %s (exit %d)\n' "${name}" "${code}" >&2
    status=1
  fi
done

if [ ${#skipped[@]} -gt 0 ]; then
  printf '\n%d probe(s) skipped: %s\n' "${#skipped[@]}" "${skipped[*]}"
  if [ "${strict}" = "1" ]; then
    printf 'STRICT: a skipped probe is not a pass. Run acceptance where the prerequisites are met.\n' >&2
    status=1
  else
    printf 'This run is not release acceptance. Use `make acceptance-probes` on a disposable Arch system with Prolewatch installed and `prolewatch setup` completed.\n'
  fi
fi

exit "${status}"
