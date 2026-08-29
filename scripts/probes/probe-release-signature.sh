#!/usr/bin/env bash
# Does the AUR trust path enforce what the documentation says it enforces?
#
# The claim is specific: with validpgpkeys populated, makepkg accepts a
# signature from exactly the listed fingerprint, and does not consult local GPG
# ownertrust. The documentation previously said the opposite - that an untrusted
# key stops the build - and that was wrong on the target toolchain, which is
# what this probe exists to keep from happening again.
#
# Everything here is local: a throwaway key, a throwaway archive, no network.
set -uo pipefail
pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
note() { printf '       %s\n' "$1"; }

for tool in gpg makepkg sha256sum; do
  command -v "$tool" >/dev/null || { printf 'SKIP: probe needs %s\n' "$tool"; exit 0; }
done

W=$(mktemp -d /tmp/prolewatch-release-signature.XXXXXX)
trap 'rm -rf -- "$W"' EXIT
mkdir -p "$W/signer" "$W/user" "$W/build"
chmod 700 "$W/signer" "$W/user"

cat > "$W/params" <<'PARAMS'
%echo generating throwaway probe key
Key-Type: eddsa
Key-Curve: Ed25519
Name-Real: Prolewatch Probe
Name-Email: probe@invalid.example
Expire-Date: 0
%no-protection
%commit
PARAMS
GNUPGHOME="$W/signer" gpg --batch --gen-key "$W/params" >/dev/null 2>&1 || { bad "cannot generate a probe key"; exit 1; }
FPR=$(GNUPGHOME="$W/signer" gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr:/{print $10; exit}')
[ -n "$FPR" ] || { bad "cannot read the probe fingerprint"; exit 1; }
GNUPGHOME="$W/signer" gpg --batch --export "$FPR" > "$W/pub.gpg"

# The user imports the key and never certifies it: ownertrust stays unknown.
GNUPGHOME="$W/user" gpg --batch --import "$W/pub.gpg" >/dev/null 2>&1
validity=$(GNUPGHOME="$W/user" gpg --batch --with-colons --list-keys "$FPR" | awk -F: '/^pub:/{print $2; exit}')
note "imported key validity as the user sees it: '${validity}'"
[ "$validity" != "u" ] && [ "$validity" != "f" ] \
  && ok "the probe key is not locally trusted, which is the case under test" \
  || bad "the probe key is already trusted; the test would prove nothing"

printf 'release payload\n' > "$W/build/prolewatch-1.0.0.tar.gz"
GNUPGHOME="$W/signer" gpg --batch --yes --detach-sign --local-user "$FPR" -- "$W/build/prolewatch-1.0.0.tar.gz" 2>/dev/null
SUM=$(sha256sum "$W/build/prolewatch-1.0.0.tar.gz" | cut -d' ' -f1)

recipe() {
  cat > "$W/build/PKGBUILD" <<PKG
pkgname=prolewatch-signature-probe
pkgver=1.0.0
pkgrel=1
arch=('any')
source=("prolewatch-1.0.0.tar.gz" "prolewatch-1.0.0.tar.gz.sig")
sha256sums=('${SUM}' 'SKIP')
validpgpkeys=('${1}')
package() { :; }
PKG
}

# 1. The declared fingerprint is accepted although ownertrust is unknown. This
#    is the property the documentation must describe, and previously did not.
recipe "$FPR"
if (cd "$W/build" && GNUPGHOME="$W/user" makepkg --verifysource --nodeps >/dev/null 2>&1); then
  ok "a signature from the declared fingerprint is accepted without local ownertrust"
  note "so importing the key is not the trust decision; comparing the fingerprint is"
else
  bad "the declared fingerprint was rejected, so the documented mechanism is wrong again"
fi

# 2. Any other fingerprint is refused, which is what makes the pin a control.
recipe "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
if (cd "$W/build" && GNUPGHOME="$W/user" makepkg --verifysource --nodeps >/dev/null 2>&1); then
  bad "a signature from an undeclared key was accepted"
else
  ok "a signature from an undeclared fingerprint is refused"
fi

# 3. And the archive itself is still covered: tampering fails the checksum.
recipe "$FPR"
printf 'x' >> "$W/build/prolewatch-1.0.0.tar.gz"
if (cd "$W/build" && GNUPGHOME="$W/user" makepkg --verifysource --nodeps >/dev/null 2>&1); then
  bad "a modified archive was accepted"
else
  ok "a modified archive is refused"
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
