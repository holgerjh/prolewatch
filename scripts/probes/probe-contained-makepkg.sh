#!/usr/bin/env bash
# Check that makepkg can run under the containment model.
#
# Target model (docs/architecture.md): host /usr read-only, tmpfs $HOME, the
# package worktree the only writable path, namespaces unshared, no clean root.
#
# Compares three configurations:
#   control  - no sandbox at all (proves the canaries measure something)
#   bwrap    - bwrap with an isolated user namespace
#   mapped   - a pre-created userns with both the caller's uid and a subuid
#              mapped to 0, joined by bwrap --userns
#
# The discriminator is `install -o root -g root` in package(). Under fakeroot,
# chown to an unmapped uid returns EINVAL rather than EPERM, and libfakeroot
# only swallows EPERM - so the call escapes to the kernel and the build fails.
set -uo pipefail

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
HOST_HOME="$HOME"
SUBUID="$(awk -F: -v u="$(id -un)" -v n="$(id -u)" '$1==u||$1==n{print $2; exit}' /etc/subuid 2>/dev/null)"
SUBGID="$(awk -F: -v u="$(id -un)" -v n="$(id -u)" '$1==u||$1==n{print $2; exit}' /etc/subgid 2>/dev/null)"
pass=0; fail=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
note(){ printf '       %s\n' "$1"; }

mkdir -p "$WORK/pkg"
cat > "$WORK/pkg/PKGBUILD" <<'PKGBUILD'
pkgname=prolewatch-probe
pkgver=1
pkgrel=1
arch=('any')
source=('payload.txt')
sha256sums=('SKIP')

build() {
  : > "$srcdir/canaries"
  if [ -n "${PROBE_HOST_HOME:-}" ] && [ -r "$PROBE_HOST_HOME" ]; then
    echo "home=visible" >> "$srcdir/canaries"
  else
    echo "home=hidden" >> "$srcdir/canaries"
  fi
  if timeout 4 bash -c 'echo > /dev/tcp/1.1.1.1/53' 2>/dev/null; then
    echo "net=reachable" >> "$srcdir/canaries"
  else
    echo "net=blocked" >> "$srcdir/canaries"
  fi
  echo built > "$srcdir/artifact.txt"
}

package() {
  install -Dm0644 "$srcdir/artifact.txt" "$pkgdir/usr/share/prolewatch-probe/artifact.txt"
  install -Dm0644 "$srcdir/canaries"     "$pkgdir/usr/share/prolewatch-probe/canaries"
  # The discriminator: explicit ownership, as many real PKGBUILDs do.
  install -Dm0755 -o root -g root "$srcdir/artifact.txt" "$pkgdir/usr/bin/prolewatch-probe"
}
PKGBUILD
echo "probe payload" > "$WORK/pkg/payload.txt"

MK=(/usr/bin/makepkg -f --nodeps --noconfirm --nocheck --nosign)
BWRAP_COMMON=(--unshare-pid --unshare-ipc --unshare-uts --unshare-net --unshare-cgroup
  --die-with-parent --new-session
  --ro-bind /usr /usr --ro-bind /etc /etc
  --symlink usr/bin /bin --symlink usr/bin /sbin --symlink usr/lib /lib --symlink usr/lib /lib64
  --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run --tmpfs /probehome)

run() { # $1 mode
  local mode="$1" src="$WORK/$1" dest="$WORK/out-$1"
  cp -r "$WORK/pkg" "$src"; mkdir -p "$dest"
  case "$mode" in
    control)
      ( cd "$src" && env PROBE_HOST_HOME="$HOST_HOME" PKGDEST="$dest" "${MK[@]}" ) >"$WORK/$mode.log" 2>&1 ;;
    bwrap)
      bwrap --unshare-user "${BWRAP_COMMON[@]}" \
        --bind "$src" /build --bind "$dest" /pkgdest --chdir /build \
        --clearenv --setenv HOME /probehome --setenv PATH /usr/bin --setenv LANG C.UTF-8 \
        --setenv PKGDEST /pkgdest --setenv PROBE_HOST_HOME "$HOST_HOME" \
        "${MK[@]}" >"$WORK/$mode.log" 2>&1 ;;
    mapped)
      [ -n "$SUBUID" ] && [ -n "$SUBGID" ] \
        || { echo "no complete subordinate-ID delegation" >"$WORK/$mode.log"; return 90; }
      # The whole subordinate range, not uid 0 alone: an unmapped id fails
      # chown with EINVAL, which is the failure this mode exists to fix, so a
      # narrow map just moves the breakage from uid 0 to uid 65534. This is the
      # map internal/contain builds; keeping them identical is the point.
      local U G; U="$(id -u)"; G="$(id -g)"
      unshare --user \
        --map-users "0:$SUBUID:$U" --map-users "$U:$U:1" \
        --map-users "$((U+1)):$((SUBUID+U+1)):$((65536-U-1))" \
        --map-groups "0:$SUBGID:$G" --map-groups "$G:$G:1" \
        --map-groups "$((G+1)):$((SUBGID+G+1)):$((65536-G-1))" \
        --setuid "$U" --setgid "$G" -- sleep 300 &
      local nspid=$!; sleep 0.5
      exec 9<"/proc/$nspid/ns/user" || { kill $nspid; return 91; }
      bwrap --userns 9 "${BWRAP_COMMON[@]}" \
        --bind "$src" /build --bind "$dest" /pkgdest --chdir /build \
        --clearenv --setenv HOME /probehome --setenv PATH /usr/bin --setenv LANG C.UTF-8 \
        --setenv PKGDEST /pkgdest --setenv PROBE_HOST_HOME "$HOST_HOME" \
        "${MK[@]}" >"$WORK/$mode.log" 2>&1
      local rc=$?; exec 9<&-; kill $nspid 2>/dev/null; wait $nspid 2>/dev/null; return $rc ;;
  esac
}

check_canaries() { # $1 mode  $2 expect-contained(yes|no)
  local c="$WORK/$1/src/canaries"
  [ -r "$c" ] || { bad "$1: no canary file (build() never ran)"; return; }
  note "canaries: $(tr '\n' ' ' < "$c")"
  if [ "$2" = yes ]; then
    grep -q home=hidden  "$c" && ok "$1: real home NOT visible to build code" || bad "$1: build read the real home"
    grep -q net=blocked  "$c" && ok "$1: no ambient network"                   || bad "$1: build reached the network"
  else
    grep -q home=visible "$c" && ok "$1: control sees the real home (canary is meaningful)" \
                              || bad "$1: control could not see home - canary proves nothing"
  fi
}

echo; echo "=== 1. control: no sandbox ==="
run control && ok "makepkg completed" || { bad "makepkg failed - probe environment broken"; tail -15 "$WORK/control.log"; }
check_canaries control no

echo; echo "=== 2. bwrap --unshare-user  (what build.go:688 does today) ==="
if run bwrap; then
  bad "makepkg completed - expected the fakeroot/chown failure; re-check this finding"
else
  ok "makepkg fails as predicted (this is the finding, not a probe bug)"
  note "$(grep -m1 -i 'cannot change ownership\|ERROR' "$WORK/bwrap.log" | sed 's/^ *//')"
  note "chown to an unmapped uid returns EINVAL; libfakeroot only swallows EPERM"
fi
check_canaries bwrap yes

echo; echo "=== 3. bwrap --userns with uid 0 mapped from /etc/subuid ==="
rc=0; run mapped || rc=$?
case $rc in
  0)  ok "makepkg completed" ;;
  90) bad "no complete subordinate-ID delegation for $(id -un) - run once: sudo usermod --add-subids -- \"$(id -un)\"" ;;
  91) bad "could not open the helper user namespace" ;;
  *)  bad "makepkg FAILED"; note "$(grep -m1 -i 'cannot change ownership\|ERROR' "$WORK/mapped.log" | sed 's/^ *//')" ;;
esac
if [ $rc -eq 0 ]; then
  check_canaries mapped yes
  p=$(find "$WORK/out-mapped" -name '*.pkg.tar*' | head -1)
  if [ -n "$p" ]; then
    ok "package produced: $(basename "$p")"
    own=$(bsdtar -tvf "$p" | awk '/usr\/bin\/prolewatch-probe$/{for(i=1;i<=NF;i++) if($i ~ /^[a-z]+\/[a-z]+$/ || ($i=="root" && $(i+1)=="root")) {print $i" "$(i+1); exit}}')
    case "$own" in
      "root root"|"root/root "*|"root/root") ok "explicit 'install -o root -g root' recorded root:root" ;;
      *) bad "ownership wrong: '${own:-none}'"; note "$(bsdtar -tvf "$p" | grep 'usr/bin/prolewatch-probe$')" ;;
    esac
  else bad "no package archive produced"; fi
fi

echo; printf '=== %d passed, %d failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
