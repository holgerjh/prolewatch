#!/bin/bash
# Render packaging/arch/PKGBUILD.in for one distribution channel.
#
# AUR recipes use a signed release archive.
# Development recipes use a local archive.
# Both use the same packaging functions.
#
# Usage:
#   render-pkgbuild.sh aur VERSION SHA256 FINGERPRINT
#   render-pkgbuild.sh dev PKGVER  SHA256
set -euo pipefail
export LC_ALL=C

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
template=${project_dir}/packaging/arch/PKGBUILD.in
channel=${1:?usage: render-pkgbuild.sh CHANNEL VERSION SHA256 [FINGERPRINT]}
version=${2:?usage: render-pkgbuild.sh CHANNEL VERSION SHA256 [FINGERPRINT]}
sha256=${3:?usage: render-pkgbuild.sh CHANNEL VERSION SHA256 [FINGERPRINT]}
fingerprint=${4:-}

# Release assets are hosted in the upstream GitHub repository.
release_url=https://github.com/holgerjh/prolewatch/releases/download

[[ ${version} =~ ^[A-Za-z0-9@._+]+$ ]] || { echo 'invalid package version' >&2; exit 1; }
[[ ${sha256} =~ ^[0-9a-f]{64}$ ]] || { echo 'invalid source sha256' >&2; exit 1; }

case ${channel} in
  aur)
    [[ ${fingerprint} =~ ^[0-9A-F]{40}$ ]] || {
      echo 'The AUR channel needs the full 40-character maintainer fingerprint.' >&2
      exit 1
    }
    pkgname=prolewatch
    archive="prolewatch-\${pkgver}.tar.gz"
    # sed expands \n into a newline in the generated recipe.
    source="\"${archive}::${release_url}/v\${pkgver}/${archive}\"\\n        \"${archive}.sig::${release_url}/v\${pkgver}/${archive}.sig\""
    # makepkg checks the detached signature against validpgpkeys.
    sums="'${sha256}'\\n             'SKIP'"
    keys="'${fingerprint}'"
    ;;
  dev)
    pkgname=prolewatch-dev
    # Keep ${pkgver} expandable in the generated recipe.
    source="\"prolewatch-\${pkgver}.tar.gz\""
    sums="'${sha256}'"
    keys=""
    ;;
  *)
    echo "unknown channel: ${channel}" >&2
    exit 1
    ;;
esac

# The '|' delimiter allows '/' in source URLs.
sed -e "s|@PKGNAME@|${pkgname}|g" \
    -e "s|@PKGVER@|${version}|g" \
    -e "s|@SOURCE@|${source}|" \
    -e "s|@SHA256SUMS@|${sums}|" \
    -e "s|@VALIDPGPKEYS@|${keys}|" \
    -- "${template}"
