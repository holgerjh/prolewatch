#!/bin/bash
# Build the reproducible, vendored source archive a Prolewatch package is built
# from, and print its SHA-256.
#
# One definition of what that archive contains, because two would eventually
# disagree: the AUR release publishes this archive and the maintainer's dev
# package builds from it, and a user who verifies the published one is entitled
# to assume the maintainer built the same thing.
#
# Vendored on purpose. The recipe builds with -mod=vendor, GOPROXY=off and
# GOFLAGS=-buildvcs=false, so the build reaches no network at all: everything it
# compiles is inside the archive whose signature the user just checked.
#
# Usage: source-archive.sh VERSION OUTPUT_DIR
set -euo pipefail
umask 022
export LC_ALL=C

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=${1:?usage: source-archive.sh VERSION OUTPUT_DIR}
output_dir=${2:?usage: source-archive.sh VERSION OUTPUT_DIR}
[[ ${version} =~ ^[A-Za-z0-9@._+]+$ ]] || { echo 'invalid archive version' >&2; exit 1; }
[[ ${output_dir} == /* && -d ${output_dir} && ! -L ${output_dir} ]] || {
  echo 'The output directory must be an existing absolute non-symlink path.' >&2
  exit 1
}

work=$(mktemp -d /tmp/prolewatch-source-archive.XXXXXX)
trap 'rm -rf -- "${work}"' EXIT
epoch=${SOURCE_DATE_EPOCH:-$(git -c safe.directory="${project_dir}" -C "${project_dir}" log -1 --format=%ct)}
[[ ${epoch} =~ ^[0-9]+$ ]] || { echo 'SOURCE_DATE_EPOCH must be numeric.' >&2; exit 1; }

file_list=${work}/files
{
  git -c safe.directory="${project_dir}" -C "${project_dir}" ls-files -z
  git -c safe.directory="${project_dir}" -C "${project_dir}" ls-files --others --exclude-standard -z -- \
    cmd internal packaging scripts share docs testdata
} | sort -zu >"${file_list}"

# Every path component checked, not just the leaf: a symlinked directory
# anywhere above a tracked file would put something outside the tree into an
# archive people are asked to trust.
while IFS= read -r -d '' relative; do
  candidate=${project_dir}
  IFS=/ read -r -a components <<<"${relative}"
  for component in "${components[@]}"; do
    candidate+=/${component}
    [[ ! -L ${candidate} ]] || {
      printf 'Package source has a symlink path component: %s\n' "${relative}" >&2
      exit 1
    }
  done
  [[ -f ${project_dir}/${relative} ]] || {
    printf 'Tracked source is missing or a symlink: %s\n' "${relative}" >&2
    exit 1
  }
done <"${file_list}"

source_parent=${work}/source
source_tree=${source_parent}/prolewatch-${version}
mkdir -p -- "${source_tree}"
tar -cf - --null --no-recursion -C "${project_dir}" --files-from="${file_list}" | tar -xf - -C "${source_tree}"

go_binary=${PROLEWATCH_GO:-$(command -v go)}
[[ ${go_binary} == /* && -x ${go_binary} ]] || { echo 'Cannot resolve an absolute Go tool.' >&2; exit 1; }
go_path=$(dirname -- "${go_binary}"):/usr/bin
module_cache=$(env -i HOME="${HOME}" PATH="${go_path}" GOENV=off GOTOOLCHAIN=local "${go_binary}" env GOMODCACHE)
go_cache=${work}/go-build-cache
mkdir -p -- "${go_cache}"
for step in verify "vendor -o ${source_tree}/vendor"; do
  # shellcheck disable=SC2086
  env -i HOME="${HOME}" PATH="${go_path}" LANG=C.UTF-8 LC_ALL=C.UTF-8 GOENV=off GOTOOLCHAIN=local GOWORK=off \
    GOFLAGS=-mod=readonly GOCACHE="${go_cache}" GOMODCACHE="${module_cache}" \
    GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org \
    "${go_binary}" -C "${source_tree}" mod ${step} >&2
done

archive=${output_dir}/prolewatch-${version}.tar.gz
temporary=$(mktemp "${output_dir}/.prolewatch-source.XXXXXX")
tar -cf - --sort=name --format=posix --pax-option=delete=atime,delete=ctime --mtime="@${epoch}" \
  --owner=0 --group=0 --numeric-owner --mode='u+rwX,go+rX,go-w' -C "${source_parent}" "prolewatch-${version}" \
  | gzip -n >"${temporary}"
chmod 0644 -- "${temporary}"
mv -- "${temporary}" "${archive}"

digest=$(sha256sum -- "${archive}")
printf '%s\n' "${digest%% *}"
