#!/usr/bin/env bash
# Check what package-controlled code runs during `makepkg --verifysource`.
#
# This matters because verification-like makepkg modes are not data-only:
# callers must keep them contained and offline whenever they process an
# untrusted PKGBUILD.
#
# makepkg *sources* the PKGBUILD, so top-level statements run in every
# invocation, including --verifysource and before any phase function.
set -uo pipefail
pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
note() { printf '       %s\n' "$1"; }

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
M="$W/markers"; : > "$M"
mkdir -p "$W/p"; cd "$W/p"
cat > PKGBUILD <<P
echo TOPLEVEL >> "$M"
pkgname=prolewatch-vs-probe
pkgver=1
pkgrel=1
arch=('any')
source=('local.txt')
sha256sums=('SKIP')
pkgver()  { echo PKGVER  >> "$M"; echo 1; }
prepare() { echo PREPARE >> "$M"; }
build()   { echo BUILD   >> "$M"; }
package() { echo PACKAGE >> "$M"; install -Dm0644 /etc/hostname "\$pkgdir/u/x"; }
P
echo local > local.txt

run() { : > "$M"; makepkg "$@" --nodeps --noconfirm >/dev/null 2>&1; tr '\n' ' ' < "$M"; }

echo; echo "=== what executes in each makepkg mode ==="
vs=$(run --verifysource); nb=$(run --nobuild -f)
printf '  %-22s %s\n' "--verifysource:" "${vs:-(nothing)}"
printf '  %-22s %s\n' "--nobuild:" "${nb:-(nothing)}"

echo; echo "=== assertions ==="
grep -q TOPLEVEL <<<"$vs" \
  && ok "top-level PKGBUILD code DOES run during --verifysource" \
  || bad "top-level code did not run - re-check, makepkg sources the PKGBUILD"
grep -q PKGVER <<<"$vs" \
  && bad "pkgver() runs during --verifysource - the acquisition window is wider than assumed" \
  || ok "pkgver() does NOT run during --verifysource (the named suspect is cleared)"
for f in PREPARE BUILD PACKAGE; do
  grep -q "$f" <<<"$vs" && bad "$f() ran during --verifysource" || ok "$f() does not run during --verifysource"
done
grep -q PKGVER <<<"$nb" \
  && ok "pkgver() runs later, during the build path (where egress is already closed)" \
  || note "pkgver() did not run in --nobuild either; VCS sources may differ"

echo
note "CONSEQUENCE: attacker-controlled shell executes while the exact-URL"
note "allowance is open. It is bounded by (a) running inside the same"
note "containment as the build, and (b) the allowance permitting only the"
note "declared source= URLs, which are fixed GETs - no query parameters, so"
note "the exfiltration channel is request count and timing, not content."
note "Acquisition MUST run inside the sandbox, not before it."

echo; printf '=== %d passed, %d failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
