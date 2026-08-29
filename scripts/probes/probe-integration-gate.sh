#!/usr/bin/env bash
# Check the privileged-integration gate against yay 13 and pacman.
#
# Answers four questions:
#   1. does pacman -U support --noscriptlet?
#   2. does yay forward it?
#   3. does the yay Lua API expose a hook between build completion and
#      pacman -U, where the gate would naturally live?
#   4. can Prolewatch instead strip .INSTALL from the archive it already hands
#      back to yay, which is equivalent for that package and needs no yay
#      cooperation at all?
#
# Runs no installation and needs no root.
set -uo pipefail
pass=0; fail=0; warn=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
wrn()  { printf '  \033[33mWARN\033[0m %s\n' "$1"; warn=$((warn+1)); }
note() { printf '       %s\n' "$1"; }

echo; echo "=== 1. what pacman flags can actually suppress ==="
pacman -U --help 2>&1 | grep -q -- --noscriptlet \
  && ok "pacman -U supports --noscriptlet (covers .INSTALL only)" || bad "pacman -U has no --noscriptlet"
if pacman -U --help 2>&1 | grep -q -- "--nohooks"; then
  ok "pacman has --nohooks"
else
  wrn "pacman has NO --nohooks - libalpm hooks cannot be suppressed by any flag"
fi
if man pacman.conf 2>/dev/null | col -b | grep -q "in addition to the system hook directory"; then
  wrn "--hookdir ADDS directories; it does not replace them"
  note "$(man pacman.conf 2>/dev/null | col -b | grep -m1 -A2 '^ *HookDir' | tail -2 | tr -s ' ')"
else
  note "could not read pacman.conf(5); verify --hookdir semantics manually"
fi
if strings /usr/lib/libalpm.so 2>/dev/null | grep -q "/usr/share/libalpm/hooks/"; then
  ok "system hook dir is compiled into libalpm - always searched, not configurable away"
  note "a package installing usr/share/libalpm/hooks/*.hook gets root execution"
  note "on every SUBSEQUENT transaction, regardless of --noscriptlet"
fi

echo; echo "=== 2. yay pass-through ==="
yay --help 2>&1 | grep -q -- --noscriptlet \
  && ok "yay recognises --noscriptlet and forwards it to pacman" \
  || bad "yay does not list --noscriptlet"
note "yay $(yay --version 2>/dev/null | head -1)"

echo; echo "=== 3. yay Lua hook points ==="
TD=$(mktemp -d); mkdir -p "$TD/yay"
cat > "$TD/yay/init.lua" <<'LUA'
local candidates = {
  "AURPreInstall","AURPostDownload","AURPreDownload","AURPostInstall",
  "AURPreBuild","AURPostBuild","PreInstall","PostInstall",
  "PreTransaction","PostTransaction","PrePacman","PostPacman",
  "AURPreMakepkg","AURPostMakepkg","BogusEventName",
}
local good = {}
for _, n in ipairs(candidates) do
  if pcall(function() yay.create_autocmd(n, {desc="probe", callback=function() end}) end) then
    good[#good+1] = n
  end
end
io.stderr:write("PROBE events: " .. table.concat(good, " ") .. "\n")
LUA
event_output=$(XDG_CONFIG_HOME="$TD" timeout 20 yay --version 2>&1)
events=$(sed -n 's/^PROBE events: //p' <<<"$event_output")
cat > "$TD/yay/init.lua" <<'LUA'
yay.opt.definitely_not_a_real_option_xyz = "x"
LUA
bogus_output=$(XDG_CONFIG_HOME="$TD" timeout 20 yay --version 2>&1)
bogus_status=$?
rm -rf "$TD"
note "accepted events: ${events:-none}"
case " $events " in
  *" BogusEventName "*) wrn "yay accepts arbitrary event names - list above is not authoritative" ;;
  *) ok "yay validates event names (bogus name rejected)" ;;
esac
if [[ " $events " == *" AURPostBuild "* || " $events " == *" PrePacman "* ]]; then
  ok "a hook exists between build completion and pacman -U"
else
  wrn "NO hook between build completion and pacman -U"
  note "the gate must live in the prolewatch-makepkg wrapper instead"
fi
if [ "$bogus_status" -ne 0 ] && grep -q 'definitely_not_a_real_option_xyz' <<<"$bogus_output"; then
  ok "yay rejects a configuration containing an unknown yay.opt key"
else
  bad "yay did not reject an unknown yay.opt key with an attributable error"
  note "status=$bogus_status output=$(tr '\n' ' ' <<<"$bogus_output")"
fi

echo; echo "=== 4. archive rewrite as the enforcement mechanism ==="
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir -p "$W/p"; cd "$W/p"
cat > PKGBUILD <<'P'
pkgname=prolewatch-sc-probe
pkgver=1
pkgrel=1
arch=('any')
install=prolewatch-sc-probe.install
package() { install -Dm0644 /etc/hostname "$pkgdir/usr/share/sc-probe/x"; }
P
printf 'post_install() {\n  echo "this would run as root"\n}\n' > prolewatch-sc-probe.install
if makepkg -f --nodeps --noconfirm --nosign >/dev/null 2>&1; then
  ok "built a package carrying an install scriptlet"
else
  bad "could not build the fixture package"; cd /; printf '\n=== %d passed, %d failed, %d warnings ===\n' "$pass" "$fail" "$warn"; exit 1
fi
PKG=$(ls ./*.pkg.tar.zst | head -1)
if bsdtar -xOf "$PKG" .INSTALL 2>/dev/null | grep -q post_install; then
  ok "scriptlet is extractable for display before install"
  note "$(bsdtar -xOf "$PKG" .INSTALL | head -1)"
else
  bad "could not extract .INSTALL for display"
fi
mkdir -p "$W/x" && bsdtar -C "$W/x" -xf "$PKG" 2>/dev/null
members=$(bsdtar -tf "$PKG" | grep -v '^\.INSTALL$')
rm -f "$W/x/.INSTALL"
( cd "$W/x" && bsdtar --format=gnutar -czf "$W/stripped.pkg.tar.gz" $members ) 2>/dev/null
if bsdtar -tf "$W/stripped.pkg.tar.gz" | grep -q '^\.INSTALL$'; then
  bad ".INSTALL survived the rewrite"
else
  ok ".INSTALL removed by rewriting the archive"
fi
if out=$(pacman -Qp "$W/stripped.pkg.tar.gz" 2>&1) && [ -n "$out" ]; then
  ok "pacman still parses the rewritten package: $out"
  note "equivalent to --noscriptlet for this package, and needs no yay cooperation"
  note "CAVEAT: .MTREE is now stale; regenerate it or accept that pacman -Qkk will differ"
else
  bad "pacman rejects the rewritten package: $out"
fi

echo; echo "=== 5. stripping EVERY privileged surface, not just .INSTALL ==="
mkdir -p "$W/q"; cd "$W/q"
cat > PKGBUILD <<'P'
pkgname=prolewatch-integration-probe
pkgver=1
pkgrel=1
arch=('any')
install=prolewatch-integration-probe.install
package() {
  install -Dm0644 /etc/hostname "$pkgdir/usr/share/pw-probe/x"
  install -Dm0644 "$startdir/evil.hook"    "$pkgdir/usr/share/libalpm/hooks/zz-evil.hook"
  install -Dm0644 "$startdir/evil.service" "$pkgdir/usr/lib/systemd/system/evil.service"
  install -Dm0644 "$startdir/evil.conf"    "$pkgdir/usr/lib/sysusers.d/evil.conf"
}
P
printf 'post_install() { echo scriptlet; }\n' > prolewatch-integration-probe.install
printf '[Trigger]\nOperation=Install\nType=Package\nTarget=*\n[Action]\nWhen=PostTransaction\nExec=/usr/bin/evil\n' > evil.hook
printf '[Unit]\nDescription=evil\n' > evil.service
printf 'u evil - "evil"\n' > evil.conf
if ! makepkg -f --nodeps --noconfirm --nosign >/dev/null 2>&1; then
  bad "could not build the multi-surface fixture"; cd /
  printf '\n=== %d passed, %d failed, %d warnings ===\n' "$pass" "$fail" "$warn"; exit 1
fi
P2=$(ls ./*.pkg.tar.zst | head -1)
found=$(bsdtar -tf "$P2" | grep -cE '^\.INSTALL$|libalpm/hooks/.+|systemd/system/.+|sysusers\.d/.+')
[ "$found" -ge 4 ] && ok "all four fixture surfaces enumerable from the archive listing ($found)" \
                   || bad "only $found surfaces found in the listing"

ORIG_SET=$(bsdtar -xOf "$P2" .MTREE | zcat | grep -m1 '^/set')
note "original .MTREE: $ORIG_SET"

rewrite() { # $1 = fakeroot|plain
  rm -rf "$W/r"; mkdir "$W/r"
  local body='cd "'"$W"'/r" && bsdtar -xpf "'"$PWD/$P2"'"
    rm -f .INSTALL usr/share/libalpm/hooks/zz-evil.hook usr/lib/systemd/system/evil.service usr/lib/sysusers.d/evil.conf
    find usr -depth -type d -empty -delete 2>/dev/null
    rm -f .MTREE
    LANG=C bsdtar -czf .MTREE --format=mtree --options="!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link" $(find . -mindepth 1 -printf "%P\n" | grep -v "^\.MTREE$" | sort)
    LANG=C bsdtar -cf - --format=gnutar .PKGINFO .MTREE .BUILDINFO $(find . -mindepth 1 -maxdepth 1 -not -name ".*" -printf "%P\n") | zstd -q -o "'"$W"'/out-'"$1"'.pkg.tar.zst"'
  if [ "$1" = fakeroot ]; then fakeroot -- bash -c "$body" >/dev/null 2>&1
  else bash -c "$body" >/dev/null 2>&1; fi
}

note "regeneration vs streaming: see below"

rewrite plain
plain_set=$(bsdtar -xOf "$W/out-plain.pkg.tar.zst" .MTREE 2>/dev/null | zcat 2>/dev/null | grep -m1 '/set')
grep -q 'uid=0 gid=0' <<<"$plain_set" \
  && bad "expected ownership loss without fakeroot but it survived - re-check" \
  || ok "extract+repack as the ordinary user LOSES ownership ($plain_set)"

rewrite fakeroot
fr_set=$(bsdtar -xOf "$W/out-fakeroot.pkg.tar.zst" .MTREE 2>/dev/null | zcat 2>/dev/null | grep -m1 '/set')
grep -q 'uid=0 gid=0' <<<"$fr_set" \
  && ok "extract+repack under fakeroot preserves ownership ($fr_set)" \
  || bad "fakeroot rewrite did not preserve ownership: $fr_set"
orig_md5=$(bsdtar -xOf "$P2" .MTREE | zcat | grep -c md5digest)
new_md5=$(bsdtar -xOf "$W/out-fakeroot.pkg.tar.zst" .MTREE | zcat | grep -c md5digest)
if [ "$orig_md5" -ne "$new_md5" ]; then
  ok "but regeneration is NOT byte-faithful: md5digest lines $orig_md5 -> $new_md5"
  note "matching makepkg's exact bsdtar --options string is a silent-failure risk"
  note "=> stream-filter instead: no extract, no fakeroot, no regeneration"
else
  wrn "regeneration matched the original option string on this makepkg version"
  note "it is still version-coupled; streaming avoids the coupling entirely"
fi
left=$(bsdtar -tf "$W/out-fakeroot.pkg.tar.zst" | grep -cE '^\.INSTALL$|libalpm/hooks/.+|systemd/system/.+|sysusers\.d/.+')
[ "$left" -eq 0 ] && ok "all four fixture surfaces removed by the rewrite" || bad "$left surface(s) survived"
out=$(pacman -Qp "$W/out-fakeroot.pkg.tar.zst" 2>&1) && [ -n "$out" ] \
  && ok "pacman parses the rewritten package: $out" || bad "pacman rejects it: $out"

note "one mechanism covers every surface; --noscriptlet covers only .INSTALL"

cd /
echo; printf '=== %d passed, %d failed, %d warnings ===\n' "$pass" "$fail" "$warn"
[ "$fail" -eq 0 ]
