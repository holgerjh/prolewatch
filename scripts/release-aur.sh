#!/bin/bash
# Produce everything a published Prolewatch release needs: the signed source
# archive users download, and the AUR recipe that verifies it.
#
# This is the trust path. A fresh user runs `yay -S prolewatch`, and what stands
# between them and arbitrary code is:
#
#   1. the AUR recipe declares a release URL and the maintainer's fingerprint;
#   2. makepkg downloads the archive and its detached signature and verifies
#      them before running any of the recipe's own build steps;
#   3. the recipe compiles with -mod=vendor and GOPROXY=off, so everything it
#      builds is inside the archive that was just verified; and
#   4. the built package installs no privileged component, which
#      scripts/verify-arch-package.sh asserts against the artifact.
#
# There is deliberately no step that edits the user's pacman keyring or
# LocalFileSigLevel.
#
# What validpgpkeys does, exactly: with it populated, stock makepkg requires the
# signature to come from one of the listed fingerprints and does not consult
# local GPG ownertrust - the ownertrust branch in verify_signature.sh applies
# only when the array is empty. So the fingerprint pin is the control, and the
# user's decision is comparing that fingerprint against a source other than the
# recipe. Importing the key is not itself a trust decision.
#
# Usage: release-aur.sh VERSION   (VERSION is the tag without the leading v)
set -euo pipefail
umask 022
export LC_ALL=C

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=${1:?usage: release-aur.sh VERSION}
dist_dir=${PROLEWATCH_RELEASE_DIR:-${project_dir}/dist/aur}
data_home=${XDG_DATA_HOME:-${HOME:?HOME is required}/.local/share}
key_home=${PROLEWATCH_RELEASE_GNUPGHOME:-${data_home}/prolewatch/release-signing-gnupg}
fingerprint_file=${key_home}/fingerprint
signing_key=${PROLEWATCH_SIGNING_KEY:-}

[[ ${version} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo 'The release version must be MAJOR.MINOR.PATCH, matching the tag without its leading v.' >&2
  exit 1
}
# The version a user installs and the version the binary reports must be the
# same string, or `prolewatch version` and the package database disagree about
# what is on the system.
application_version=$(sed -n 's/^[[:space:]]*ApplicationVersion[[:space:]]*=[[:space:]]*"\([^"]*\)"/\1/p' "${project_dir}/internal/audit/config.go")
[[ ${application_version} == "${version}" ]] || {
  printf 'ApplicationVersion is %s; releasing %s would ship a package whose binary disagrees with it.\n' \
    "${application_version}" "${version}" >&2
  exit 1
}

[[ ${key_home} == /* && -d ${key_home} && ! -L ${key_home} ]] || {
  printf 'The release signing key directory must be an existing absolute directory: %s\n' "${key_home}" >&2
  exit 1
}
key_owner=$(stat -c %u -- "${key_home}")
key_mode=$(stat -c %a -- "${key_home}")
[[ ${key_owner} -eq ${EUID} ]] && (( (8#${key_mode} & 8#077) == 0 )) || {
  echo 'The release signing key directory must be private and owned by the invoking user.' >&2
  exit 1
}
if [[ -z ${signing_key} && -f ${fingerprint_file} && ! -L ${fingerprint_file} ]]; then
  read -r signing_key <"${fingerprint_file}"
fi
# Exactly 40 characters: a full fingerprint. A short key id is ambiguous, and an
# ambiguous identity in validpgpkeys is not a trust path.
[[ ${signing_key} =~ ^[0-9A-F]{40}$ ]] || {
  printf 'No full 40-character signing fingerprint is configured; set PROLEWATCH_SIGNING_KEY or write one to %s.\n' \
    "${fingerprint_file}" >&2
  exit 1
}
GNUPGHOME="${key_home}" gpg --batch --list-secret-keys "${signing_key}" >/dev/null

# A release is cut from a clean tree. Anything else publishes an archive whose
# contents cannot be reproduced from the tag it claims to be.
git -c safe.directory="${project_dir}" -C "${project_dir}" diff --quiet HEAD -- || {
  echo 'The working tree has uncommitted changes; a release archive must be reproducible from its tag.' >&2
  exit 1
}
untracked=$(git -c safe.directory="${project_dir}" -C "${project_dir}" ls-files --others --exclude-standard -- \
  cmd internal packaging scripts share docs testdata)
[[ -z ${untracked} ]] || {
  printf 'Untracked files would enter the release archive:\n%s\n' "${untracked}" >&2
  exit 1
}

install -d -m 0755 -- "${dist_dir}"
dist_dir=$(cd -- "${dist_dir}" && pwd -P)
rm -f -- "${dist_dir}/prolewatch-${version}.tar.gz" "${dist_dir}/prolewatch-${version}.tar.gz.sig" \
  "${dist_dir}/PKGBUILD" "${dist_dir}/.SRCINFO"

source_sha256=$("${project_dir}/scripts/source-archive.sh" "${version}" "${dist_dir}")
archive=${dist_dir}/prolewatch-${version}.tar.gz
GNUPGHOME="${key_home}" gpg --batch --yes --detach-sign --local-user "${signing_key}" -- "${archive}"
GNUPGHOME="${key_home}" gpg --batch --verify -- "${archive}.sig" "${archive}"

"${project_dir}/scripts/render-pkgbuild.sh" aur "${version}" "${source_sha256}" "${signing_key}" >"${dist_dir}/PKGBUILD"
(cd -- "${dist_dir}" && makepkg --printsrcinfo >.SRCINFO)

cat <<SUMMARY
Release ${version} prepared in ${dist_dir}

  prolewatch-${version}.tar.gz      sha256 ${source_sha256}
  prolewatch-${version}.tar.gz.sig  signed by ${signing_key}
  PKGBUILD, .SRCINFO                for the AUR repository

Publish in this order, because the recipe names the archive by URL:
  1. tag v${version} and upload both archive files to that release;
  2. push PKGBUILD and .SRCINFO to the AUR repository;
  3. on a clean Arch system, import and trust the key, then run
     'yay -S prolewatch' and 'prolewatch setup'.

Step 3 is the acceptance run, not a formality: it is the only step that
exercises installation ownership, pacman trust, subordinate IDs and hook
activation together.
SUMMARY
