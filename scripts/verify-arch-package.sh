#!/bin/bash
# Verify a built development package before installing it.
#
# Release invariant 1 is that Prolewatch installs no privileged component. A
# package is where that invariant could be broken - by a systemd unit, sysusers
# or tmpfiles fragment, a libalpm hook, a setuid bit, or a sudoers drop-in in the
# payload. The invariant is asserted against the artifact rather than trusted to
# the PKGBUILD.
set -euo pipefail

package=${1:-}
[[ -n ${package} && ${package} == /* && -f ${package} && ! -L ${package} ]] || {
  echo 'Usage: make verify-arch-package PACKAGE=/absolute/path/to/prolewatch-dev.pkg.tar.zst' >&2
  exit 1
}
[[ -f ${package}.sig && ! -L ${package}.sig ]] || { echo 'Detached package signature is missing.' >&2; exit 1; }
basename=${package##*/}
[[ ${basename} == prolewatch-dev-*.pkg.tar.zst ]] || { echo 'Unexpected development package name.' >&2; exit 1; }

policy=$(pacman-conf LocalFileSigLevel 2>/dev/null || true)
[[ ${policy} == *Required* && ${policy} == *TrustedOnly* && ${policy} != *Optional* && ${policy} != *TrustAll* && ${policy} != *Never* ]] || {
  printf 'Pacman does not require trusted signatures for local files: %s\n' "${policy:-unknown}" >&2
  printf 'Set LocalFileSigLevel = Required TrustedOnly in /etc/pacman.conf.\n' >&2
  exit 1
}
pacman-key --verify "${package}.sig" "${package}"

metadata=$(mktemp -d /tmp/prolewatch-package-verify.XXXXXX)
trap 'rm -rf -- "${metadata}"' EXIT
bsdtar -xOf "${package}" .PKGINFO >"${metadata}/PKGINFO"
grep -Fx 'pkgname = prolewatch-dev' "${metadata}/PKGINFO" >/dev/null
arch=$(sed -n 's/^arch = //p' "${metadata}/PKGINFO")
[[ ${arch} == "$(uname -m)" || ${arch} == any ]] || {
  printf 'Package architecture %s does not match %s.\n' "${arch}" "$(uname -m)" >&2
  exit 1
}

# No privileged component, asserted against the payload.
#
# An exact allow-list, not a deny-list of known-bad paths. A deny-list can only
# reject the mechanisms someone thought to name, and the same review that added
# /etc/ld.so.preload and systemd's sleep and shutdown hooks to the surface
# registry found this script would have passed a package carrying any of them.
# Release invariant 1 says Prolewatch installs no privileged component; the only
# way to assert that against an artifact is to enumerate what the artifact is
# allowed to contain and reject everything else.
listing=${metadata}/listing
bsdtar -tf "${package}" >"${listing}"
allowed=${metadata}/allowed
{
  # pacman metadata. .INSTALL is deliberately absent: a scriptlet is a
  # privileged surface even when it is empty.
  printf '%s\n' .PKGINFO .BUILDINFO .MTREE
  # The payload the PKGBUILD declares, and nothing else.
  printf '%s\n' usr/bin/prolewatch usr/bin/prolewatch-makepkg usr/bin/prolewatch-gpg usr/bin/prolewatch-net
  printf 'usr/share/prolewatch/%s\n' default-config.json prolewatch.lua review-prompt.md verdict.schema.json
  printf '%s\n' etc/prolewatch/config.json
  printf 'usr/share/doc/prolewatch/%s\n' README.md SECURITY.md architecture.md
  printf 'usr/share/licenses/prolewatch/%s\n' LICENSE THIRD_PARTY_NOTICES
} | sort >"${allowed}"

unexpected=""
while IFS= read -r member; do
  # Directory entries carry no code and are created by any payload path.
  case "${member}" in */) continue ;; esac
  if ! grep -qxF "${member}" "${allowed}"; then
    unexpected="${unexpected}${member}"$'\n'
  fi
done <"${listing}"
if [[ -n ${unexpected} ]]; then
  printf 'Package carries members the PKGBUILD does not declare:\n%s' "${unexpected}" >&2
  exit 1
fi

# Character 3 of the mode string is owner-execute and character 6 is
# group-execute. Checking only the first is how a setgid binary passes a check
# whose error message says "setuid or setgid".
if bsdtar -tvf "${package}" | grep -qE '^-.{2}[sS]|^-.{5}[sS]'; then
  printf 'Package contains a setuid or setgid file.\n' >&2
  exit 1
fi

# The payload the product needs, asserted the same way as the payload it forbids.
# A package can be perfectly free of privileged integration and still be unable
# to run: omitting etc/prolewatch/config.json produced an installation whose
# every command failed on the file it reads first.
while IFS= read -r required; do
  if ! grep -qx "${required}" "${listing}"; then
    printf 'Package is missing a required payload file: %s\n' "${required}" >&2
    exit 1
  fi
done <<'REQUIRED'
usr/bin/prolewatch
usr/bin/prolewatch-makepkg
usr/bin/prolewatch-gpg
usr/bin/prolewatch-net
usr/share/prolewatch/default-config.json
usr/share/prolewatch/prolewatch.lua
usr/share/prolewatch/review-prompt.md
usr/share/prolewatch/verdict.schema.json
etc/prolewatch/config.json
REQUIRED

printf 'Signature, pacman policy, and architecture are valid.\n'
printf 'Payload carries only the members the PKGBUILD declares: no scriptlet, unit, hook, loader or service directory, and no setuid bit.\n'
printf 'Payload carries every file the installed commands need, including etc/prolewatch/config.json.\n'
printf 'Install through the authenticated package-manager boundary:\n'
printf '  sudo pacman -U -- %q\n' "${package}"
