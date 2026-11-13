#!/usr/bin/env bash
#
# run-benchmark.sh -- one-command runner for the RedPilot black-box benchmark.
#
#   ./run-benchmark.sh                 # the newest capstone (Chronos, depth-22) with per-flaw controls
#   ./run-benchmark.sh <boss>          # a single boss, e.g. ./run-benchmark.sh pangaea
#   ./run-benchmark.sh <boss> --controls
#   ./run-benchmark.sh families        # every randomized held-out family
#   ./run-benchmark.sh all             # every boss + every family (the full regression)
#   ./run-benchmark.sh list            # list the available bosses
#
# The only runtime dependency is `cryptography`; the repo ships stub httpx/pydantic shims,
# so no web or database stack is needed. Set PYTHON=/path/to/python3 to override the interpreter.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT/backend"
export PYTHONPATH="tests/verification_infrastructure/shims:tests/verification_infrastructure:."
HB="tests/verification_infrastructure/hardened_benchmark"
PY="${PYTHON:-python3}"

BOSSES=(boss helios obsidian citadel aegis vault obelisk rampart leviathan sentinel pantheon olympus cosmos pangaea chronos)

if ! "$PY" -c "import cryptography" 2>/dev/null; then
  echo "error: the 'cryptography' package is required. Install it with:  pip install cryptography" >&2
  exit 1
fi

one() { echo; echo "==== boss: $1 ===="; "$PY" "$HB/run_$1.py" "${@:2}"; }
families() { for f in "$HB"/gauntlet_families*.py "$HB"/gauntlet_providers.py; do echo; echo "---- $(basename "$f") ----"; "$PY" "$f"; done; }

case "${1:-chronos}" in
  list)     printf '%s\n' "${BOSSES[@]}" ;;
  families) families ;;
  all)      for b in "${BOSSES[@]}"; do one "$b"; done; families ;;   # finds + families; add --controls per boss for the load-bearing proof
  *)        one "$1" "${@:2}" ;;
esac
