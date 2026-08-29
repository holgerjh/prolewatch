#!/usr/bin/env bash
# Enforce the package layering in docs/architecture.md as a build gate.
#
# A layering that lives only in a document is a convention, and conventions rot.
# This makes it a gate, so a reviewer can bound what the containment path is able
# to reach by reading import boundaries rather than every file.
#
# Layering, lowest first. A package may import anything BELOW it and nothing
# at or above it.
#
#   safe/      boundary primitives for attacker-controlled bytes
#   contain/   process containment: namespaces, the clamp, bwrap invocation
#   egress/    the egress broker and its policy
#   brief/     inspection, enumeration, the archive stream filter
#   ui/        terminal rendering, prompts, reports, the dashboard
#
set -uo pipefail
MODULE=$(awk '/^module /{print $2; exit}' go.mod)
LAYERS=(safe contain egress brief ui)
fail=0

rank() { local i=0; for l in "${LAYERS[@]}"; do [ "$l" = "$1" ] && { echo $i; return; }; i=$((i+1)); done; echo -1; }

present=()
for l in "${LAYERS[@]}"; do [ -d "internal/$l" ] && present+=("$l"); done

if [ ${#present[@]} -eq 0 ]; then
  echo "check-import-direction: none of the target packages exist yet."
  echo "  expected under internal/: ${LAYERS[*]}"
  echo "  This gate is inert until the split lands - by design, so that it is"
  echo "  already wired in when the first package appears. It is NOT a pass."
  exit 0
fi

echo "check-import-direction: layering ${LAYERS[*]} (lowest first)"
for l in "${present[@]}"; do
  lr=$(rank "$l")
  # go list is authoritative; fall back to grep if the tree does not build yet.
  imports=$(go list -deps "./internal/$l/..." 2>/dev/null \
            || grep -rhoE "\"$MODULE/internal/[a-z]+" "internal/$l" 2>/dev/null | tr -d '"')
  for other in "${LAYERS[@]}"; do
    [ "$other" = "$l" ] && continue
    orank=$(rank "$other")
    [ "$orank" -lt "$lr" ] && continue          # importing downward is allowed
    if grep -q "^$MODULE/internal/$other$" <<<"$imports" 2>/dev/null \
       || grep -q "$MODULE/internal/$other" <<<"$imports" 2>/dev/null; then
      echo "  VIOLATION: internal/$l imports internal/$other (same or higher layer)"
      fail=1
    fi
  done
  [ "$fail" -eq 0 ] && echo "  ok: internal/$l"
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "The layering is a security property, not a style preference: it is what"
  echo "lets a reviewer bound what the containment path can reach without reading"
  echo "every file. Move the shared type down a layer rather than importing up."
  exit 1
fi
echo "check-import-direction: ok (${#present[@]}/${#LAYERS[@]} packages present)"
