#!/usr/bin/env bash
# Check that the stream filter produces a package that verifies clean once
# installed, not merely one that pacman -Qp parses.
#
# A parse check does not detect a removed archive member that remains listed in
# .MTREE. pacman -Qkk verifies the installed package and therefore asserts that
# the archive strip set and .MTREE filter set are identical.
#
# Installs into throwaway --root trees inside a user namespace mapping the full
# subordinate range, so uid 65534 exists and non-root ownership can round-trip.
# Touches no host package database and needs no privilege.
#
# FOOTGUN, if you are debugging this: the verification namespace must map the
# WHOLE subordinate range plus the caller's own uid. Mapping only uid 0 and the
# caller leaves 65534 unmapped, pacman cannot chown to it, and -Qkk reports a
# UID mismatch that looks exactly like a filter defect. Check the uid_map before
# believing an ownership finding here.
set -uo pipefail
pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
note() { printf '       %s\n' "$1"; }

SUBUID=$(awk -F: -v u="$(id -un)" -v n="$(id -u)" '$1==u||$1==n{print $2; exit}' /etc/subuid 2>/dev/null)
SUBGID=$(awk -F: -v u="$(id -un)" -v n="$(id -u)" '$1==u||$1==n{print $2; exit}' /etc/subgid 2>/dev/null)
[ -n "$SUBUID" ] && [ -n "$SUBGID" ] || { echo "  no complete subordinate-ID delegation for $(id -un)"; exit 1; }
W=$(mktemp -d); trap 'rm -rf "$W" 2>/dev/null' EXIT

mkdir -p "$W/p"; cd "$W/p"
cat > PKGBUILD <<'P'
pkgname=prolewatch-stream-probe
pkgver=1
pkgrel=1
arch=('any')
install=prolewatch-stream-probe.install
package() {
  install -Dm0644 /etc/hostname "$pkgdir/usr/share/pw/root-owned"
  install -Dm0644 -o 65534 -g 65534 /etc/hostname "$pkgdir/usr/share/pw/nobody-owned"
  install -Dm0644 "$startdir/evil.hook"    "$pkgdir/usr/share/libalpm/hooks/zz-evil.hook"
  install -Dm0644 "$startdir/evil.service" "$pkgdir/usr/lib/systemd/system/evil.service"
}
P
printf 'post_install() { echo x; }\n' > prolewatch-stream-probe.install
printf '[Trigger]\nOperation=Install\nType=Package\nTarget=*\n[Action]\nWhen=PostTransaction\nExec=/usr/bin/evil\n' > evil.hook
printf '[Unit]\nDescription=evil\n' > evil.service
makepkg -f --nodeps --noconfirm --nosign >/dev/null 2>&1 \
  && ok "built fixture with a scriptlet, a hook, a unit, and a non-root-owned file" \
  || { bad "fixture build failed"; exit 1; }
ORIG=$(ls "$PWD"/*.pkg.tar.zst | head -1)

STRIP=".INSTALL usr/share/libalpm/hooks/zz-evil.hook usr/lib/systemd/system/evil.service"
python3 - "$ORIG" "$W/filtered.pkg.tar" $STRIP <<'PY'
import sys, tarfile, io, gzip, subprocess
src_path, out_path = sys.argv[1], sys.argv[2]
STRIP = set(sys.argv[3:])
raw = subprocess.run(['zstd', '-dc', src_path], capture_output=True).stdout

def norm(p):                      # NOT lstrip('./') - that is a character set
    return p[2:].rstrip('/') if p.startswith('./') else p.rstrip('/')

names = [m.name for m in tarfile.open(fileobj=io.BytesIO(raw)).getmembers()]
members = tarfile.open(fileobj=io.BytesIO(raw)).getmembers()
dirs  = {norm(m.name) for m in members if m.isdir()}
files = {norm(m.name) for m in members if not m.isdir()}
surviving_files = files - STRIP
# Prune, deepest first, any directory with no surviving file beneath it.
prune = {d for d in dirs if not any(f.startswith(d + '/') for f in surviving_files)}
DROP = STRIP | prune
print(f"  strip: {sorted(STRIP)}")
print(f"  prune: {sorted(prune)}")

src = tarfile.open(fileobj=io.BytesIO(raw))
buf = io.BytesIO()
dst = tarfile.open(fileobj=buf, mode='w', format=tarfile.GNU_FORMAT)
for m in src.getmembers():
    if norm(m.name) in DROP:
        continue
    if m.name == '.MTREE':
        text = gzip.decompress(src.extractfile(m).read()).decode()
        kept = []
        for line in text.splitlines(keepends=True):
            s = line.rstrip('\n')
            if s.startswith(('#', '/set', '/unset')) or not s.strip():
                kept.append(line); continue
            if norm(s.split(' ', 1)[0]) in DROP:
                continue
            kept.append(line)
        blob = gzip.compress(''.join(kept).encode(), mtime=0)
        m.size = len(blob)
        dst.addfile(m, io.BytesIO(blob)); continue
    dst.addfile(m, src.extractfile(m) if m.isreg() else None)
dst.close()
open(out_path, 'wb').write(buf.getvalue())
PY
zstd -q -f "$W/filtered.pkg.tar" -o "$W/filtered.pkg.tar.zst"

leftover=""
for m in $STRIP; do
  bsdtar -xOf "$W/filtered.pkg.tar.zst" .MTREE | zcat \
    | awk -v want="./$m" '{p=$1; if (p==want) found=1} END{exit !found}' && leftover="$leftover $m"
done
[ -z "$leftover" ] && ok ".MTREE lists no stripped member" \
  || bad ".MTREE still lists:$leftover (strip set and filter set disagree)"
[ "$(bsdtar -xOf "$W/filtered.pkg.tar.zst" .MTREE | zcat | grep -c md5digest)" \
  -eq "$(bsdtar -xOf "$ORIG" .MTREE | zcat | grep -c md5digest)" ] \
  && ok ".MTREE options unchanged (no regeneration drift)" || bad ".MTREE options drifted"

echo; echo "  === installed verification (pacman -Qkk in a throwaway root) ==="
U=$(id -u); G=$(id -g)
res=$(unshare --user \
        --map-users "0:$SUBUID:$U" --map-users "$U:$U:1" --map-users "$((U+1)):$((SUBUID+U+1)):$((65536-U-1))" \
        --map-groups "0:$SUBGID:$G" --map-groups "$G:$G:1" --map-groups "$((G+1)):$((SUBGID+G+1)):$((65536-G-1))" \
        --setuid 0 --setgid 0 -- bash -c '
  W='"$W"'; mkdir -p $W/a/var/lib/pacman $W/b/var/lib/pacman $W/cache
  printf "[options]\nArchitecture = auto\nSigLevel = Never\n" > $W/pacman.conf
  P() { r=$1; shift; pacman --root $W/$r --dbpath $W/$r/var/lib/pacman \
        --cachedir $W/cache --config $W/pacman.conf "$@"; }
  P a --noconfirm --nodeps --noscriptlet -U '"$ORIG"' >/dev/null 2>&1
  echo "CONTROL:$(P a -Qkk prolewatch-stream-probe 2>&1 | tail -1)"
  P b --noconfirm --nodeps --noscriptlet -U $W/filtered.pkg.tar.zst >/dev/null 2>&1
  echo "FILTERED:$(P b -Qkk prolewatch-stream-probe 2>&1 | tail -1)"
  echo "OWN:$(stat -c %u:%g $W/b/usr/share/pw/nobody-owned 2>/dev/null)"
  echo "HOOK:$([ -e $W/b/usr/share/libalpm/hooks/zz-evil.hook ] && echo present || echo absent)"
' 2>&1)
note "$(grep CONTROL: <<<"$res" | sed 's/CONTROL://')"
note "$(grep FILTERED: <<<"$res" | sed 's/FILTERED://')"
grep -q 'CONTROL:.*0 altered files' <<<"$res" \
  && ok "control package verifies clean (baseline)" || bad "control package does not verify clean"
grep -q 'FILTERED:.*0 altered files' <<<"$res" \
  && ok "stream-filtered package verifies clean under pacman -Qkk" \
  || bad "stream-filtered package has altered files"
grep -q 'OWN:65534:65534' <<<"$res" \
  && ok "non-root ownership survived the filter (65534:65534)" \
  || bad "ownership lost: $(grep OWN: <<<"$res")"
grep -q 'HOOK:absent' <<<"$res" && ok "stripped hook absent from the installed tree" || bad "hook installed"

echo; printf '=== %d passed, %d failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
