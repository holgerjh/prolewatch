#!/usr/bin/env bash
# Exercise the installed yay hook and makepkg wrapper through a real yay -B
# transaction with a checksum-bound public source. Run this on a disposable
# Arch acceptance system after installing Prolewatch and completing
# `prolewatch setup` prerequisites.
set -uo pipefail

for tool in yay git jq prolewatch; do
  if ! command -v "$tool" >/dev/null; then
    printf 'SKIP: probe needs %s\n' "$tool"
    exit 0
  fi
done
for path in /usr/bin/prolewatch-makepkg /usr/bin/prolewatch-gpg /usr/share/prolewatch/prolewatch.lua; do
  if [ ! -f "$path" ]; then
    printf 'SKIP: installed payload is missing %s\n' "$path"
    exit 0
  fi
done
if ! prolewatch config-check >/dev/null; then
  printf 'SKIP: install a valid system configuration before running this probe\n'
  exit 0
fi

# Arch commonly mounts /tmp as a RAM-backed tmpfs. The real build workspace is
# subject to Prolewatch's disk-reserve policy, so putting this probe there makes
# a healthy guard refuse a VM whose tmpfs is smaller than that reserve. Honour
# the acceptance guide's TMPDIR; when it is unset, use the caller's current
# filesystem rather than silently selecting /tmp.
probe_tmp=${TMPDIR:-$PWD}
if [ ! -d "$probe_tmp" ] || [ ! -w "$probe_tmp" ]; then
  printf 'FAIL: probe workspace is not a writable directory: %s\n' "$probe_tmp" >&2
  exit 1
fi
work=$(mktemp -d "$probe_tmp/prolewatch-yay-interception.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
config="$work/config/yay"
state="$work/state"
cache="$work/cache"
origin="$work/origin.git"
checkout="$work/checkout"
mkdir -p "$config" "$state" "$cache"
install -m0600 /usr/share/prolewatch/prolewatch.lua "$config/prolewatch.lua"
printf '%s\n' 'require("prolewatch")' > "$config/init.lua"

git init --bare --quiet "$origin"
git clone --quiet "$origin" "$checkout"
git -C "$checkout" config user.name 'Prolewatch probe'
git -C "$checkout" config user.email 'probe@invalid.example'
# A source-less package proves wrapper interception and nothing about the source
# lifecycle at the centre of the design. The fixture is therefore a real,
# extractable public source, pinned by both repository commit and checksum.
# Loopback cannot be used here: production policy deliberately rejects it.
cat > "$checkout/PKGBUILD" <<'PKGBUILD'
pkgname=prolewatch-yay-interception-probe
pkgver=1
pkgrel=1
arch=('any')
source=("probe-source.tar.gz::https://github.com/octocat/Hello-World/archive/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d.tar.gz")
sha256sums=('39a4b97b9d108782fa7466b07160a2c9227a7da07725ad4110c41be6014e4160')
package() {
  install -Dm0644 /dev/null "$pkgdir/usr/share/prolewatch-yay-interception-probe/payload"
}
PKGBUILD
git -C "$checkout" add PKGBUILD
git -C "$checkout" commit --quiet -m fixture
git -C "$checkout" branch -M main
git -C "$checkout" push --quiet -u origin main

# A stale archive and a detached signature, in the directory the build writes
# to. yay's build directory is a persistent cache - cleanAfter is off by default
# - so on an ordinary upgrade the previous version is still sitting there. The
# build must audit what makepkg planned, not what the directory happens to hold.
: > "$checkout/prolewatch-yay-interception-probe-0-1-any.pkg.tar.zst"
: > "$checkout/prolewatch-yay-interception-probe-0-1-any.pkg.tar.zst.sig"

effective=$(XDG_CONFIG_HOME="$work/config" XDG_CACHE_HOME="$cache" yay -Pg)
if ! jq -e '.makepkgbin == "/usr/bin/prolewatch-makepkg" and .gpgbin == "/usr/bin/prolewatch-gpg"' <<<"$effective" >/dev/null; then
  printf 'FAIL: yay did not load both wrapper paths\n' >&2
  exit 1
fi

if ! (cd "$checkout" && XDG_CONFIG_HOME="$work/config" XDG_CACHE_HOME="$cache" XDG_STATE_HOME="$state" yay -B --noconfirm .); then
  printf 'FAIL: yay -B transaction did not complete\n' >&2
  exit 1
fi

report_dir="$state/prolewatch/reports"
if ! compgen -G "$report_dir/*.json" >/dev/null; then
  printf 'FAIL: transaction produced no audit reports\n' >&2
  exit 1
fi
if ! jq -s -e 'any(.[]; .package_base == "prolewatch-yay-interception-probe" and ((.sandbox_runs // []) | length > 0))' "$report_dir"/*.json >/dev/null; then
  printf 'FAIL: no content-bound report carries trusted sandbox enforcement\n' >&2
  exit 1
fi

# The declared source must reach the post report's manifest. It lives in the
# transaction source store rather than the checkout, so a post scan that reads
# only the checkout reports it absent and hard-blocks - which is what every
# ordinary AUR package looked like before the post scan learned both roots.
if ! jq -s -e 'any(.[]; .phase == "post" and ((.manifest // []) | any(.path == "probe-source.tar.gz")))' "$report_dir"/*.json >/dev/null; then
  printf 'FAIL: the acquired source is missing from the post report manifest\n' >&2
  exit 1
fi
if jq -s -e 'any(.[]; (.findings // []) | any(.rule_id == "extractable-source-missing"))' "$report_dir"/*.json >/dev/null; then
  printf 'FAIL: an acquired source was reported absent\n' >&2
  exit 1
fi

# The stale archive beside the build output must not have been reviewed, bound,
# or quarantined: yay was never going to install it.
if jq -s -e 'any(.[]; (.artifact_bindings // []) | any(.path | test("probe-0-1-any")))' "$report_dir"/*.json >/dev/null; then
  printf 'FAIL: a stale cached archive was bound as output of this build\n' >&2
  exit 1
fi
if [ ! -f "$checkout/prolewatch-yay-interception-probe-0-1-any.pkg.tar.zst" ]; then
  printf 'FAIL: a stale cached archive was quarantined or rewritten\n' >&2
  exit 1
fi

printf 'PASS: yay loaded both wrappers, the transaction recorded sandbox enforcement, the acquired source reached the report, and only the planned package was audited\n'
