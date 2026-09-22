#!/usr/bin/env bash
# phase0_produce_metadata.sh
# Produces per-trace metadata for every *.trace in $OBJECTIVE_DIR. This phase feeds the
# LLM-prompt triaging pipeline: it pre-bakes the differential result ONCE so that later
# phases can do pure text analysis (grep the `.log` files) and so the Python triager can
# classify from the cached `.json` WITHOUT re-executing every trace (diff_analyzer.py's
# get_diff() reads metadata_diff_T.json when present; see there). Re-run this whenever the
# corpus or the fuzzer binary changes so the cache stays fresh. Run from the repo root:
#   ./evaluation-ddyf/phase0_produce_metadata.sh
#
# Protocol-agnostic: the binary and the two PUT names come from the environment, so
# the same script serves the SSH and TLS pipelines. Defaults are the SSH pipeline.
#
#   PUFFIN_PATH   fuzzer binary            (default: target/release/sshpuffin)
#   FIRST_PUT     first PUT name           (default: libssh0114)   e.g. openssl340
#   SECOND_PUT    second PUT name          (default: wolfssh150)   e.g. wolfssl580
#   OBJECTIVE_DIR directory of *.trace     (default: ./objective)
#   PARALLELISM   xargs workers            (default: 20)
#   ASAN_OPTIONS  sanitizer opts           (default: detect_leaks=0 — the harness
#                                           links ASAN even against non-ASAN vendors)
#
# Output per trace T (the <put> in the prefix is derived from FIRST_PUT/SECOND_PUT, so
# diff_analyzer.py's `metadata_*_<trace>.log` glob co-locates them on sort):
#   metadata_diff_T.log            differential-execute -S      (human/grep security oracle)
#   metadata_diff_T.json           differential-execute --json  (classifier cache; read by
#                                  diff_analyzer.py get_diff() instead of re-executing)
#   metadata_<FIRST_PUT>_T.log     --put <FIRST_PUT>  display-execute -tckp
#   metadata_<SECOND_PUT>_T.log    --put <SECOND_PUT> display-execute -tckp

set -euo pipefail

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"

BINARY="${PUFFIN_PATH:-target/release/sshpuffin}"
FIRST_PUT="${FIRST_PUT:-libssh0114}"
SECOND_PUT="${SECOND_PUT:-wolfssh150}"
PARALLELISM="${PARALLELISM:-20}"
OBJECTIVE_DIR="${OBJECTIVE_DIR:-./objective}"

if [ ! -x "$BINARY" ]; then
  echo "ERROR: fuzzer binary not found / not executable at '$BINARY' (set PUFFIN_PATH)" >&2
  exit 1
fi

echo "=== Phase 0: producing metadata logs ==="
echo "  Binary:      $BINARY"
echo "  PUTs:        $FIRST_PUT vs $SECOND_PUT"
echo "  Objective:   $OBJECTIVE_DIR"
echo "  Parallelism: $PARALLELISM"
echo ""

# `-not -name ".*"` excludes LibAFL's hidden companion files (`.<name>.trace`, 1-byte
# lock/sidecars): a bare `*.trace` glob matches them too, which would double-count the corpus
# and waste a metadata triple on each marker. This mirrors diff_analyzer.py's VALID regex
# (`^[^.]…`), so Phase 0 and the classifier agree on what a real trace is.
N_TRACES=$(find "$OBJECTIVE_DIR" -name "*.trace" -not -name ".*" | wc -l)
echo "  Traces found: $N_TRACES"
echo ""

find "$OBJECTIVE_DIR" -name "*.trace" -not -name ".*" \
| xargs -P "$PARALLELISM" -I{} bash -c '
  BINARY="$1"
  FIRST_PUT="$2"
  SECOND_PUT="$3"
  T="$4"
  DIR="$(dirname "$T")"
  BASE="$(basename "$T")"

  DIFF="$DIR/metadata_diff_$BASE.log"
  DIFF_JSON="$DIR/metadata_diff_$BASE.json"
  PUT1="$DIR/metadata_${FIRST_PUT}_$BASE.log"
  PUT2="$DIR/metadata_${SECOND_PUT}_$BASE.log"

  # Skip if all four artifacts already exist
  if [ -f "$DIFF" ] && [ -f "$DIFF_JSON" ] && [ -f "$PUT1" ] && [ -f "$PUT2" ]; then
    exit 0
  fi

  "$BINARY" differential-execute "$FIRST_PUT" "$SECOND_PUT" "$T" -S \
    > "$DIFF" 2>&1 || true

  # Machine-readable diff, consumed by diff_analyzer.py get_diff() as a classification
  # cache (avoids a second live differential-execute per trace during triaging). stderr is
  # NOT merged here — it must stay valid JSON on stdout.
  "$BINARY" differential-execute --json "$FIRST_PUT" "$SECOND_PUT" "$T" \
    > "$DIFF_JSON" 2>/dev/null || true

  "$BINARY" --put "$FIRST_PUT" display-execute "$T" -tckp \
    > "$PUT1" 2>&1 || true

  "$BINARY" --put "$SECOND_PUT" display-execute "$T" -tckp \
    > "$PUT2" 2>&1 || true
' _ "$BINARY" "$FIRST_PUT" "$SECOND_PUT" {}

echo ""
echo "=== Phase 0 complete ==="
N_DIFF=$(find "$OBJECTIVE_DIR" -name "metadata_diff_*.log" | wc -l)
N_PUT1=$(find "$OBJECTIVE_DIR" -name "metadata_${FIRST_PUT}_*.log" | wc -l)
N_PUT2=$(find "$OBJECTIVE_DIR" -name "metadata_${SECOND_PUT}_*.log" | wc -l)
echo "  Diff logs:          $N_DIFF / $N_TRACES"
echo "  $FIRST_PUT logs:    $N_PUT1 / $N_TRACES"
echo "  $SECOND_PUT logs:   $N_PUT2 / $N_TRACES"

if [ "$N_DIFF" -ne "$N_TRACES" ] || [ "$N_PUT1" -ne "$N_TRACES" ] || [ "$N_PUT2" -ne "$N_TRACES" ]; then
  echo ""
  echo "WARNING: log count mismatch — some traces may have failed. Check for missing logs:"
  find "$OBJECTIVE_DIR" -name "*.trace" -not -name ".*" | while read -r T; do
    BASE="$(basename "$T")"
    DIR="$(dirname "$T")"
    for PREFIX in "metadata_diff_" "metadata_${FIRST_PUT}_" "metadata_${SECOND_PUT}_"; do
      [ -f "$DIR/${PREFIX}${BASE}.log" ] || echo "  MISSING: $DIR/${PREFIX}${BASE}.log"
    done
  done | head -20
fi
