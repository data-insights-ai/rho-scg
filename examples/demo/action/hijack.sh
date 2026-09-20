#!/usr/bin/env bash
# Moves the v1 tag of scg-demo-action onto the hijacked commit (or back).
# Run inside a checkout of the demo action with push rights.
#   ./hijack.sh on    -> v1 points at the hijacked commit
#   ./hijack.sh off   -> v1 points at the honest commit again
set -euo pipefail
case "${1:-}" in
  on)  target=$(git rev-list -n1 hijacked) ;;
  off) target=$(git rev-list -n1 "$(git log --format=%H --grep='v1: honest' | tail -1)") ;;
  *) echo "usage: $0 on|off" >&2; exit 2 ;;
esac
git tag -f v1 "$target"
git push -f origin v1
echo "v1 -> $target"
