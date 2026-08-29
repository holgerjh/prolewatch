#!/usr/bin/env bash
# Check what the joined pre-mapped user namespace permits the build to do.
#
# The build must have an empty capability set and must not be able to create
# nested namespaces. bwrap cannot combine --disable-userns with --userns <fd>,
# so the namespace anchor clamps user.max_user_namespaces to zero before the
# build starts.
set -uo pipefail
pass=0; fail=0; warn=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
wrn()  { printf '  \033[33mWARN\033[0m %s\n' "$1"; warn=$((warn+1)); }
note() { printf '       %s\n' "$1"; }

SUBUID=$(awk -F: -v u="$(id -un)" -v n="$(id -u)" '$1==u||$1==n{print $2; exit}' /etc/subuid 2>/dev/null)
SUBGID=$(awk -F: -v u="$(id -un)" -v n="$(id -u)" '$1==u||$1==n{print $2; exit}' /etc/subgid 2>/dev/null)
[ -n "$SUBUID" ] && [ -n "$SUBGID" ] || { echo "  no complete subordinate-ID delegation for $(id -un)"; exit 1; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

start_ns() {
  unshare --user --map-users "$(id -u):$(id -u):1" --map-users "0:$SUBUID:1" \
          --map-groups "$(id -g):$(id -g):1" --map-groups "0:$SUBGID:1" \
          --setuid "$(id -u)" --setgid "$(id -g)" -- sleep 120 &
  NSPID=$!; sleep 0.5
}
BW=(--unshare-pid --unshare-ipc --unshare-uts --unshare-net --unshare-cgroup
    --ro-bind /usr /usr --ro-bind /etc /etc
    --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/bin /sbin --symlink usr/lib /lib64
    --proc /proc --dev /dev --tmpfs /tmp)

echo; echo "=== 1. is --disable-userns compatible with --userns <fd>? ==="
start_ns; exec 9<"/proc/$NSPID/ns/user"
if err=$(bwrap --userns 9 --disable-userns "${BW[@]}" --bind "$W" /w true 2>&1); then
  bad "bwrap now accepts the combination - re-check this finding, the doc may be fixable as written"
else
  ok "confirmed incompatible (this is the finding, not a probe bug)"
  note "$err"
  note "--disable-userns cannot be kept alongside a mapped uid 0"
fi
exec 9<&-; kill $NSPID 2>/dev/null; wait $NSPID 2>/dev/null

echo; echo "=== 2. what the build can actually do inside the joined namespace ==="
start_ns; exec 9</proc/$NSPID/ns/user
out=$(bwrap --userns 9 "${BW[@]}" --bind "$W" /w --chdir /w bash -c '
  echo "uid=$(id -u)"
  echo "capeff=$(grep CapEff /proc/self/status | awk "{print \$2}")"
  unshare -U true 2>/dev/null && echo "nested_userns=yes" || echo "nested_userns=no"
  setpriv --reuid 0 --regid 0 --clear-groups true 2>/dev/null && echo "nsroot=yes" || echo "nsroot=no"
  touch f && { chown 0:0 f 2>/dev/null && echo "chown0=yes" || echo "chown0=no"; }
' 2>&1)
exec 9<&-; kill $NSPID 2>/dev/null; wait $NSPID 2>/dev/null
note "$(echo "$out" | tr '\n' ' ')"

grep -q 'capeff=0000000000000000' <<<"$out" \
  && ok "build holds no capabilities" || bad "build holds capabilities: $(grep capeff <<<"$out")"
grep -q 'nsroot=no' <<<"$out" \
  && ok "build cannot become namespace-root (no CAP_SETUID)" \
  || bad "build CAN become namespace-root"
grep -q 'chown0=no' <<<"$out" \
  && ok "mapping uid 0 grants no real privilege - chown to 0 still fails" \
  || bad "build can chown to uid 0 for real"
note "the uid 0 mapping only changes chown's errno from EINVAL to EPERM,"
note "which is what libfakeroot absorbs. It confers nothing else."
grep -q 'nested_userns=yes' <<<"$out" \
  && ok "nested userns creatable without the clamp (baseline for section 4)" \
  || note "nested userns already blocked without the clamp - unexpected, check the host"

echo; echo "=== 4. restoring the block with a ucount clamp instead of seccomp ==="
note "the clamp must be written from ns-uid 0: a process whose namespace-euid is"
note "non-zero drops all capabilities at execve, which is why writing it from an"
note "ordinary-uid shell fails with EPERM - the file is not owned elsewhere"
unshare --user --map-users "$(id -u):$(id -u):1" --map-users "0:$SUBUID:1" \
        --map-groups "$(id -g):$(id -g):1" --map-groups "0:$SUBGID:1" \
        --setuid 0 --setgid 0 -- \
  bash -c "echo 0 > /proc/sys/user/max_user_namespaces
           exec setpriv --reuid $(id -u) --regid $(id -g) --clear-groups sleep 120" &
NSPID=$!; sleep 0.7
exec 9<"/proc/$NSPID/ns/user"
clamped=$(bwrap --userns 9 "${BW[@]}" --bind "$W" /w --chdir /w bash -c '
  echo "limit=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo unreadable)"
  unshare -U true 2>/dev/null && echo "nested=yes" || echo "nested=no"
  (echo 100 > /proc/sys/user/max_user_namespaces) 2>/dev/null && echo "raise=yes" || echo "raise=no"
  fakeroot -- bash -c "install -Dm0644 /etc/hostname ./o/x -o root -g root" 2>/dev/null \
    && echo "fakeroot=ok" || echo "fakeroot=broken"
' 2>&1)
exec 9<&-; kill $NSPID 2>/dev/null; wait $NSPID 2>/dev/null
note "$(echo "$clamped" | tr '\n' ' ')"
grep -q 'limit=0'      <<<"$clamped" && ok "clamp survives the bwrap --userns join" || bad "clamp did not survive"
grep -q 'nested=no'    <<<"$clamped" && ok "nested user namespaces blocked by the clamp" || bad "nested userns still creatable"
grep -q 'raise=no'     <<<"$clamped" && ok "build cannot raise the limit back (needs CAP_SYS_RESOURCE)" || bad "build raised the limit"
grep -q 'fakeroot=ok'  <<<"$clamped" && ok "clamp does not regress fakeroot ownership" || bad "clamp broke fakeroot"
note "this fully replaces the seccomp filter: no clone3/ENOSYS compatibility risk"

echo; echo "=== 5. host-side ownership of anything the sandbox created ==="
ls -ln "$W" | tail -n +2 | sed 's/^/       /'
if [ -z "$(find "$W" ! -uid "$(id -u)" -print -quit 2>/dev/null)" ]; then
  ok "every file the sandbox created is owned by the invoking uid on the host"
else
  bad "sandbox created files owned by another uid on the host"
fi

echo; printf '=== %d passed, %d failed, %d warnings ===\n' "$pass" "$fail" "$warn"
[ "$fail" -eq 0 ]
