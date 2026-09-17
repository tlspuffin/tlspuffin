#!/usr/bin/env bash
# phase0_produce_metadata.sh
# Produces three metadata log files per trace in ./objective/.
# Run from the repository root: ./evaluation-ddyf/phase0_produce_metadata.sh
#
# Output per trace T:
#   metadata_diff_T.log          differential-execute -S
#   metadata_openssl340_T.log    --put openssl340 display-execute -tckp
#   metadata_libressl421_T.log   --put libressl421 display-execute -tckp

set -euo pipefail

BINARY="${BINARY:-./target/release/tlspuffin}"
PARALLELISM="${PARALLELISM:-20}"
OBJECTIVE_DIR="${OBJECTIVE_DIR:-./objective}"

if [ ! -x "$BINARY" ]; then
  echo "ERROR: tlspuffin binary not found at $BINARY" >&2
  exit 1
fi

echo "=== Phase 0: producing metadata logs ==="
echo "  Binary:      $BINARY"
echo "  Objective:   $OBJECTIVE_DIR"
echo "  Parallelism: $PARALLELISM"
echo ""

N_TRACES=$(find "$OBJECTIVE_DIR" -name "*.trace" | wc -l)
echo "  Traces found: $N_TRACES"
echo ""

find "$OBJECTIVE_DIR" -name "*.trace" \
| xargs -P "$PARALLELISM" -I{} bash -c '
  BINARY="$1"
  T="$2"
  DIR="$(dirname "$T")"
  BASE="$(basename "$T")"

  DIFF="$DIR/metadata_diff_$BASE.log"
  OSSL="$DIR/metadata_openssl340_$BASE.log"
  LIBRE="$DIR/metadata_libressl421_$BASE.log"

  # Skip if all three logs already exist
  if [ -f "$DIFF" ] && [ -f "$OSSL" ] && [ -f "$LIBRE" ]; then
    exit 0
  fi

  "$BINARY" differential-execute openssl340 libressl421 "$T" -S \
    > "$DIFF" 2>&1 || true

  "$BINARY" --put openssl340 display-execute "$T" -tckp \
    > "$OSSL" 2>&1 || true

  "$BINARY" --put libressl421 display-execute "$T" -tckp \
    > "$LIBRE" 2>&1 || true
' _ "$BINARY" {}

echo ""
echo "=== Phase 0 complete ==="
N_DIFF=$(find "$OBJECTIVE_DIR" -name "metadata_diff_*.log" | wc -l)
N_OSSL=$(find "$OBJECTIVE_DIR" -name "metadata_openssl340_*.log" | wc -l)
N_LIBRE=$(find "$OBJECTIVE_DIR" -name "metadata_libressl421_*.log" | wc -l)
echo "  Diff logs:     $N_DIFF / $N_TRACES"
echo "  OpenSSL logs:  $N_OSSL / $N_TRACES"
echo "  LibreSSL logs: $N_LIBRE / $N_TRACES"

if [ "$N_DIFF" -ne "$N_TRACES" ] || [ "$N_OSSL" -ne "$N_TRACES" ] || [ "$N_LIBRE" -ne "$N_TRACES" ]; then
  echo ""
  echo "WARNING: log count mismatch — some traces may have failed. Check for missing logs:"
  find "$OBJECTIVE_DIR" -name "*.trace" | while read -r T; do
    BASE="$(basename "$T")"
    DIR="$(dirname "$T")"
    for PREFIX in metadata_diff_ metadata_openssl340_ metadata_libressl421_; do
      [ -f "$DIR/${PREFIX}${BASE}.log" ] || echo "  MISSING: $DIR/${PREFIX}${BASE}.log"
    done
  done | head -20
fi
