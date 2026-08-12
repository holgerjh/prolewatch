#!/bin/bash
set -euo pipefail
export LC_ALL=C

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

{
  for file in go.mod go.sum; do
    digest=$(sha256sum -- "${project_dir}/${file}")
    printf '%s\0%s\n' "${file}" "${digest%% *}"
  done
  while IFS= read -r -d '' path; do
    relative=${path#"${project_dir}/"}
    digest=$(sha256sum -- "${path}")
    printf '%s\0%s\n' "${relative}" "${digest%% *}"
  done < <(find "${project_dir}/cmd" "${project_dir}/internal" -type f ! -name '*_test.go' -print0 | sort -z)
} | sha256sum | awk '{print $1}'
