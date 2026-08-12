#!/bin/bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=${1:?usage: package-release.sh VERSION ARCH BUILD_DIR DIST_DIR}
target_arch=${2:?usage: package-release.sh VERSION ARCH BUILD_DIR DIST_DIR}
build_dir=${3:?usage: package-release.sh VERSION ARCH BUILD_DIR DIST_DIR}
dist_dir=${4:?usage: package-release.sh VERSION ARCH BUILD_DIR DIST_DIR}
[[ ${version} =~ ^v?[0-9][A-Za-z0-9._+-]*$ ]] || { echo "invalid release version" >&2; exit 1; }
[[ ${target_arch} =~ ^[A-Za-z0-9_-]+$ ]] || { echo "invalid target architecture" >&2; exit 1; }
epoch=${SOURCE_DATE_EPOCH:-$(git -c safe.directory="${project_dir}" -C "${project_dir}" log -1 --format=%ct)}
archive="${dist_dir}/prolewatch-${version}-linux-${target_arch}.tar.gz"
mkdir -p -- "${dist_dir}"
temporary=$(mktemp "${dist_dir}/.prolewatch-release.XXXXXX")
trap 'rm -f -- "${temporary}"' EXIT

binaries=(prolewatch prolewatch-makepkg prolewatch-gpg provider-dispatch prolewatch-net prolewatch-build-dispatch)
for name in "${binaries[@]}"; do
  test -x "${build_dir}/${name}"
  cp -- "${build_dir}/${name}" "${dist_dir}/${name}-linux-${target_arch}"
done

tar --sort=name --format=posix --pax-option=delete=atime,delete=ctime --mtime="@${epoch}" \
  --owner=0 --group=0 --numeric-owner -C "${build_dir}" -cf - "${binaries[@]}" \
  -C "${project_dir}" README.md LICENSE NOTICE THIRD_PARTY_NOTICES COMMERCIAL-LICENSE.md CONTRIBUTING.md SECURITY.md \
  ARTWORK-LICENSE.md \
  docs scripts/install-system.sh scripts/uninstall-system.sh share \
  | gzip -n >"${temporary}"
chmod 0644 "${temporary}"
mv -- "${temporary}" "${archive}"
