#!/bin/bash
set -euo pipefail
umask 022
export LC_ALL=C

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
dist_dir=${PROLEWATCH_ARCH_DIST_DIR:-${project_dir}/dist/arch}
data_home=${XDG_DATA_HOME:-${HOME:?HOME is required}/.local/share}
key_home=${PROLEWATCH_DEV_GNUPGHOME:-${data_home}/prolewatch/dev-signing-gnupg}
fingerprint_file=${key_home}/fingerprint
signing_key=${PROLEWATCH_SIGNING_KEY:-}
[[ ${key_home} == /* && -d ${key_home} && ! -L ${key_home} ]] || {
  echo 'The development signing key directory must be an existing absolute directory.' >&2
  exit 1
}
key_owner=$(stat -c %u -- "${key_home}")
key_mode=$(stat -c %a -- "${key_home}")
[[ ${key_owner} -eq ${EUID} ]] && (( (8#${key_mode} & 8#077) == 0 )) || {
  echo 'The development signing key directory must be private and owned by the invoking user.' >&2
  exit 1
}
if [[ -z ${signing_key} && -f ${fingerprint_file} && ! -L ${fingerprint_file} ]]; then
  read -r signing_key <"${fingerprint_file}"
fi
[[ ${signing_key} =~ ^[0-9A-F]{40,64}$ ]] || {
  echo "No full signing fingerprint is configured; set PROLEWATCH_SIGNING_KEY or write one to ${fingerprint_file}." >&2
  exit 1
}
GNUPGHOME="${key_home}" gpg --batch --list-secret-keys "${signing_key}" >/dev/null

application_version=$(sed -n 's/^[[:space:]]*ApplicationVersion[[:space:]]*=[[:space:]]*"\([^"]*\)"/\1/p' "${project_dir}/internal/audit/config.go")
[[ ${application_version} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Cannot determine application version.' >&2; exit 1; }
commit_count=$(git -c safe.directory="${project_dir}" -C "${project_dir}" rev-list --count HEAD)
commit=$(git -c safe.directory="${project_dir}" -C "${project_dir}" rev-parse --short=12 HEAD)
source_fingerprint=$("${project_dir}/scripts/source-fingerprint.sh")

epoch=${SOURCE_DATE_EPOCH:-$(git -c safe.directory="${project_dir}" -C "${project_dir}" log -1 --format=%ct)}
[[ ${epoch} =~ ^[0-9]+$ ]] || { echo 'SOURCE_DATE_EPOCH must be numeric.' >&2; exit 1; }
work=$(mktemp -d /tmp/prolewatch-arch-package.XXXXXX)
trap 'rm -rf -- "${work}"' EXIT
package_dir=${work}/package
mkdir -p -- "${package_dir}"
[[ ${dist_dir} == /* && ! -L ${dist_dir} ]] || { echo 'The package output directory must be an absolute non-symlink path.' >&2; exit 1; }
install -d -m 0755 -- "${dist_dir}"
dist_owner=$(stat -c %u -- "${dist_dir}")
dist_mode=$(stat -c %a -- "${dist_dir}")
[[ ${dist_owner} -eq ${EUID} ]] && (( (8#${dist_mode} & 8#022) == 0 )) || {
  echo 'The package output directory must be owned by the invoking user and not group/world-writable.' >&2
  exit 1
}

file_list=${work}/files
{
  git -c safe.directory="${project_dir}" -C "${project_dir}" ls-files -z
  git -c safe.directory="${project_dir}" -C "${project_dir}" ls-files --others --exclude-standard -z -- \
    cmd internal packaging scripts share docs testdata
} | sort -zu >"${file_list}"
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

package_source_fingerprint=$(
  while IFS= read -r -d '' relative; do
    digest=$(sha256sum -- "${project_dir}/${relative}")
    printf '%s\0%s\n' "${relative}" "${digest%% *}"
  done <"${file_list}" | sha256sum | awk '{print $1}'
)
[[ ${package_source_fingerprint} =~ ^[0-9a-f]{64}$ ]] || { echo 'Cannot fingerprint package sources.' >&2; exit 1; }

pkgver=${application_version}.r${commit_count}.g${commit}
dirty=0
if ! git -c safe.directory="${project_dir}" -C "${project_dir}" diff --quiet HEAD --; then
  dirty=1
fi
untracked_status=${work}/untracked-status
git -c safe.directory="${project_dir}" -C "${project_dir}" ls-files --others --exclude-standard -- \
  cmd internal packaging scripts share docs testdata >"${untracked_status}"
if [[ -s ${untracked_status} ]]; then
  dirty=1
fi
if (( dirty )); then
  pkgver+=.d${package_source_fingerprint:0:12}
fi
[[ ${pkgver} =~ ^[A-Za-z0-9@._+]+$ ]] || { echo 'Generated package version is invalid.' >&2; exit 1; }

# The archive itself is built by scripts/source-archive.sh, which the release
# flow also uses. A dev package and a published release therefore compile the
# same bytes, which is the only reason a maintainer testing one says anything
# about the other.
source_sha256=$("${project_dir}/scripts/source-archive.sh" "${pkgver}" "${package_dir}")

"${project_dir}/scripts/render-pkgbuild.sh" dev "${pkgver}" "${source_sha256}" >"${package_dir}/PKGBUILD"

if [[ ${PROLEWATCH_ARCH_CLEAN:-0} == 1 ]]; then
  (cd -- "${package_dir}" && extra-x86_64-build)
  package=$(find "${package_dir}" -maxdepth 1 -type f -name 'prolewatch-dev-*.pkg.tar.zst' -print -quit)
  [[ -n ${package} ]] || { echo 'Clean chroot did not produce the expected package.' >&2; exit 1; }
  GNUPGHOME="${key_home}" gpg --batch --yes --detach-sign --local-user "${signing_key}" -- "${package}"
else
  (cd -- "${package_dir}" && GNUPGHOME="${key_home}" SOURCE_DATE_EPOCH="${epoch}" makepkg --cleanbuild --clean --force --sign --key "${signing_key}")
  package=$(find "${package_dir}" -maxdepth 1 -type f -name 'prolewatch-dev-*.pkg.tar.zst' -print -quit)
  [[ -n ${package} && -f ${package}.sig ]] || { echo 'makepkg did not produce a signed package.' >&2; exit 1; }
fi

install -m 0644 -- "${package}" "${package}.sig" "${dist_dir}/"
printf 'Signed development package created:\n  %s/%s\n' "${dist_dir}" "$(basename -- "${package}")"
printf 'Verify it before installation with:\n  make verify-arch-package PACKAGE=%q\n' "${dist_dir}/$(basename -- "${package}")"
