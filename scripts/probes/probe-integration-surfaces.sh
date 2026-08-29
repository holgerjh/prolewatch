#!/usr/bin/env bash
# Check the gate's enumeration against a real package built by makepkg.
#
# The fixture carries one member for every registered integration path. The
# probe checks that each is found and classified, stripping removes them, and
# pacman parses the result.
#
# It is the enumeration that has to be exhaustive: a gate that reports only the
# scriptlet prints "no scriptlet" over the channel an attacker who has read the
# design would use.
set -uo pipefail
pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
note() { printf '       %s\n' "$1"; }

for tool in makepkg bsdtar pacman go; do
  command -v "$tool" >/dev/null || { echo "probe needs $tool"; exit 0; }
done

# Resolve the checkout before changing directory: BASH_SOURCE is relative.
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)

W=$(mktemp -d /tmp/prolewatch-surfaces.XXXXXX)
trap 'rm -rf -- "$W"' EXIT
cd "$W"

# Fixture paths come from the shipping registry so the probe covers every
# registered class without maintaining a second list.
#
# The registry-versus-platform question - is every directory pacman actually
# executes hooks from registered? - is answered by a Go test that asks
# pacman-conf, because it needs no package build. This probe answers the
# question that does: does a real package carrying one file per class get every
# one of them enumerated, stripped, and still parse afterwards.
mapfile -t PREFIXES < <(cd "$REPO" && go run ./cmd/prolewatch internal-gate-prefixes)
[ "${#PREFIXES[@]}" -gt 0 ] || { bad "the binary reported no surface prefixes"; exit 1; }
note "registry reports ${#PREFIXES[@]} surface prefixes"

{
  echo 'pkgname=prolewatch-surface-probe'
  echo 'pkgver=1'
  echo 'pkgrel=1'
  echo "arch=('any')"
  echo 'install=prolewatch-surface-probe.install'
  echo 'package() {'
  echo '  install -Dm0644 /dev/null "$pkgdir/usr/share/probe/ordinary-file"'
  for prefix in "${PREFIXES[@]}"; do
    echo "  install -Dm0644 /dev/null \"\$pkgdir/${prefix}probe.conf\""
  done
  echo '}'
} > PKGBUILD
printf 'post_install() { echo probe; }\n' > prolewatch-surface-probe.install

makepkg -f --nodeps --noconfirm --nosign >/dev/null 2>&1 \
  && ok "built a package carrying one file per registered prefix, plus a scriptlet" \
  || { bad "fixture build failed"; exit 1; }
PKG=$(ls "$PWD"/*.pkg.tar.zst | head -1)

# Enumerate through the shipping code path, not a reimplementation of it.
FOUND=$(cd "$REPO" && go run ./cmd/prolewatch internal-gate-enumerate "$PKG" 2>/dev/null)
[ -n "$FOUND" ] || { bad "enumeration produced no output"; exit 1; }

missing=""
for prefix in "${PREFIXES[@]}"; do
  grep -Fq "\"${prefix}probe.conf\"" <<<"$FOUND" || missing="$missing ${prefix}probe.conf"
done
grep -Fq '".INSTALL"' <<<"$FOUND" || missing="$missing .INSTALL"
[ -z "$missing" ] && ok "every surface class was enumerated" \
  || bad "not enumerated:$missing"

# An ordinary file must not be reported: over-reporting trains people to strip
# things they need, which breaks installs and discredits the gate.
grep -Fq 'usr/share/probe/ordinary-file' <<<"$FOUND" \
  && bad "an ordinary payload file was reported as a privileged surface" \
  || ok "ordinary files are not reported"

count=$(grep -o '"Member"' <<<"$FOUND" | wc -l)
note "enumerated $count surfaces"
[ "$count" -eq "$(( ${#PREFIXES[@]} + 1 ))" ] && ok "count matches: ${#PREFIXES[@]} prefixes plus the scriptlet" \
  || bad "count is $count, expected $(( ${#PREFIXES[@]} + 1 ))"

# Every enumerated surface must carry an activation, because that one field
# decides whether the install stops for an answer or the surface is listed and
# passed. An entry without one is a registry entry nobody classified; the gate
# treats that as a question rather than silently letting it through, and this
# probe says so out loud rather than letting the default hide it.
# grep -o prints one match per line, which is what makes counting work: the
# enumeration is compact JSON on a single line.
CLASSES=$(grep -o '"Member": *"[^"]*", *"Kind": *"[^"]*", *"Activation": *"[^"]*"' <<<"$FOUND")
classified=$(grep -c . <<<"$CLASSES")
[ "$classified" -eq "$count" ] && ok "all $count enumerated surfaces declare an activation" \
  || bad "$classified of $count enumerated surfaces declare an activation"
grep -q '"Activation": *""' <<<"$CLASSES" \
  && bad "an enumerated surface has an empty activation" \
  || ok "no enumerated surface has an empty activation"
grep '"Member": *"\.INSTALL"' <<<"$CLASSES" | grep -Fq 'automatic' \
  && ok "the install scriptlet is classified as automatic root execution" \
  || bad "the install scriptlet is not classified as automatic root execution"

# Strip them all and confirm nothing privileged survives and pacman still reads it.
STRIP=$(grep -o '"Member": *"[^"]*"' <<<"$FOUND" | sed 's/.*: *"//; s/"$//')
(cd "$REPO" && go run ./cmd/prolewatch internal-gate-filter "$PKG" "$W/filtered.pkg.tar.zst" $STRIP >/dev/null 2>&1) \
  && ok "the rewrite accepted every surface as a strip target" \
  || bad "the rewrite rejected a surface it had itself enumerated"

if [ -f "$W/filtered.pkg.tar.zst" ]; then
  REMAIN=$(cd "$REPO" && go run ./cmd/prolewatch internal-gate-enumerate "$W/filtered.pkg.tar.zst" 2>/dev/null)
  [ "$REMAIN" = "[]" ] && ok "no privileged surface survived the strip" \
    || bad "surfaces survived: $REMAIN"
  bsdtar -tf "$W/filtered.pkg.tar.zst" | grep -q 'usr/share/probe/ordinary-file' \
    && ok "ordinary payload survived the strip" || bad "the strip removed ordinary payload"
  pacman -Qp "$W/filtered.pkg.tar.zst" >/dev/null 2>&1 \
    && ok "pacman parses the rewritten package" || bad "pacman cannot read the rewritten package"
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
