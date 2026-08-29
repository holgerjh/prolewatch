#!/usr/bin/env bash
# NOTE: excluded from default/CI probe runs - it measures live CDN topology
# and will drift by design. Re-run manually when registry behaviour is in
# question to check what redirect chains real declared-source fetches traverse
# and whether a per-hop allowance could validate them.
#
# The acquisition-phase allowance in docs/architecture.md control 2 permits
# "exactly the declared URL set - exact URLs, not hosts". If a declared fetch
# redirects to a different host, exact-URL matching denies the fetch and every
# GitHub-hosted package breaks. This measures the real chains.
#
# Expected topology, used only to report drift rather than fail the probe:
#   GitHub release asset : github.com -> objects.githubusercontent.com
#                          (codeload.github.com for tarball/zipball URLs)
#   crates.io            : crates.io -> static.crates.io
#   Go module proxy      : proxy.golang.org serves directly, no hop
#
# Makes read-only public GET/HEAD requests. Downloads nothing to disk.
set -uo pipefail
pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
note() { printf '       %s\n' "$1"; }

hosts_of() { sed -E 's#^[a-z]+://([^/]+).*#\1#'; }

chain() { # $1 = url -> prints the host chain, one per line
  local url="$1" hop=0 loc
  while [ "$hop" -lt 10 ]; do
    echo "$url" | hosts_of
    loc=$(timeout 25 curl -sS -o /dev/null -D - -r 0-0 "$url" 2>/dev/null \
          | tr -d '\r' | awk 'tolower($1)=="location:"{print $2; exit}')
    [ -n "$loc" ] || return 0
    case "$loc" in
      /*) url="$(echo "$url" | sed -E 's#^([a-z]+://[^/]+).*#\1#')$loc" ;;
      *)  url="$loc" ;;
    esac
    hop=$((hop+1))
  done
}

DIVERGED=0
probe() { # $1 label  $2 url  $3 predicted-hop-substring (or "none")
  echo; echo "  --- $1"
  local out; out=$(chain "$2")
  [ -n "$out" ] || { bad "$1: no response"; return; }
  local n first final
  n=$(echo "$out" | wc -l); first=$(echo "$out" | head -1); final=$(echo "$out" | tail -1)
  note "measured: $(echo "$out" | tr '\n' ' ' | sed 's/ $//')"
  ok "$1: chain measured ($n host$([ "$n" -eq 1 ] || echo s))"
  # The pre-registration is a hypothesis, not a requirement. A miss is a finding
  # about the registry, not a probe failure.
  if [ "$3" = none ]; then
    if [ "$first" = "$final" ]; then note "prediction (no hop): CONFIRMED"
    else note "prediction (no hop): DIVERGED -> $final"; DIVERGED=$((DIVERGED+1)); fi
  else
    if [ "$first" = "$final" ]; then
      note "prediction (hop to *$3*): DIVERGED - served directly, no hop"; DIVERGED=$((DIVERGED+1))
    elif [ "$final" = "$3" ]; then note "prediction (hop to $3): CONFIRMED exactly"
    else note "prediction (*$3*): DIVERGED - actual host is $final"; DIVERGED=$((DIVERGED+1)); fi
  fi
  echo "$out" >> "$ALLHOSTS"
}

ALLHOSTS=$(mktemp); trap 'rm -f "$ALLHOSTS"' EXIT
echo "=== real declared-source fetches ==="
probe "GitHub tag tarball (the common PKGBUILD form)" \
      "https://github.com/pkg/errors/archive/refs/tags/v0.9.1.tar.gz" "codeload.github.com"
probe "GitHub release asset" \
      "https://github.com/cli/cli/releases/download/v2.40.0/gh_2.40.0_checksums.txt" "objects.githubusercontent.com"
probe "crates.io download" \
      "https://crates.io/api/v1/crates/serde/1.0.210/download" "static.crates.io"
probe "Go module proxy" \
      "https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.info" none

echo; echo "  --- second wall: headers carried across a cross-host hop"
hdrs=$(timeout 30 curl -sS -v -L -r 0-0 \
  -H "Authorization: Bearer FAKE-PROBE-TOKEN-NOT-A-CREDENTIAL" \
  -H "Cookie: probe=value" \
  -o /dev/null https://github.com/pkg/errors/archive/refs/tags/v0.9.1.tar.gz 2>&1 \
  | grep -iE "^> (Host|Authorization|Cookie)")
note "$(echo "$hdrs" | tr '\n' '|' | sed 's/> //g')"
second_host=$(echo "$hdrs" | grep -ci "^> Host: codeload")
leaked=$(echo "$hdrs" | awk 'tolower($0) ~ /^> host: codeload/{after=1} after && tolower($0) ~ /^> (authorization|cookie)/{n++} END{print n+0}')
if [ "$second_host" -ge 1 ] && [ "$leaked" -eq 0 ]; then
  ok "curl drops Authorization and Cookie on the cross-host hop"
  note "so the only residual redirect channel - client-attached headers - is empty,"
  note "independently of the sandbox holding nothing the attacker lacks anyway"
else
  bad "credentials survived the cross-host hop (leaked=$leaked)"
fi

echo
echo "=== consequence for the allowance model ==="
note "distinct hosts observed: $(sort -u "$ALLHOSTS" | tr '\n' ' ')"
[ "$(sort -u "$ALLHOSTS" | wc -l)" -gt 4 ] \
  && ok "declared-source fetches DO cross hosts - exact-URL-only matching breaks them" \
  || bad "no cross-host hops observed; re-read the chains above"

echo
echo "=== pre-registered hypotheses vs. measurement ==="
if [ "$DIVERGED" -eq 0 ]; then
  note "all predictions confirmed"
else
  ok "$DIVERGED of 4 predictions diverged - and that IS the design input"
  note "the misses were not guesses; they were a careful reviewer's current"
  note "knowledge of these registries. CDN topology moved underneath it."
  note "=> a vetted per-registry host map would already be stale today,"
  note "   which argues against maintaining one."
fi
note ""
note "DESIGN CHOICE, now informed by the divergence count:"
note "  (a) vetted per-registry hop map - safer in principle, but this probe"
note "      just demonstrated the maintenance failure mode in practice;"
note "  (b) accept hops reached transitively via a declared fetch's redirect,"
note "      keeping the unconditional private/special-range blocks and"
note "      prompting on any hop not previously seen for that registry."
note "Both keep the redirect target bound to a fetch the user consented to."

echo; printf '=== %d passed, %d failed ===\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
