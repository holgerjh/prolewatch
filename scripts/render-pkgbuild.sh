#!/bin/bash
# Render packaging/arch/PKGBUILD.in for one distribution channel.
#
# One template, two channels. The recipe that a fresh user builds from the AUR
# and the recipe a maintainer builds from a working tree differ only in where
# the source comes from and how its authenticity is established; everything that
# decides what lands on the system is shared, so the two cannot drift into
# installing different things.
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

# The release URL is part of the trust path and is therefore fixed here rather
# than passed in: a caller that could choose it could point a published recipe
# at a host the maintainer never released from.
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
    # \n rather than a real newline: sed replacements are single-line.
    source="\"${archive}::${release_url}/v\${pkgver}/${archive}\"\\n        \"${archive}.sig::${release_url}/v\${pkgver}/${archive}.sig\""
    # SKIP for the signature: a checksum of a signature proves nothing that the
    # signature itself does not, and makepkg refuses to build when the detached
    # signature does not verify against validpgpkeys.
    sums="'${sha256}'\\n             'SKIP'"
    keys="'${fingerprint}'"
    ;;
  dev)
    pkgname=prolewatch-dev
    # Double quotes: ${pkgver} has to expand, which it does not inside single
    # quotes - and a recipe naming a file that does not exist fails late and
    # confusingly.
    source="\"prolewatch-\${pkgver}.tar.gz\""
    sums="'${sha256}'"
    keys=""
    ;;
  *)
    echo "unknown channel: ${channel}" >&2
    exit 1
    ;;
esac

# '|' as the delimiter: the substituted values contain '/'.
sed -e "s|@PKGNAME@|${pkgname}|g" \
    -e "s|@PKGVER@|${version}|g" \
    -e "s|@SOURCE@|${source}|" \
    -e "s|@SHA256SUMS@|${sums}|" \
    -e "s|@VALIDPGPKEYS@|${keys}|" \
    -- "${template}"
