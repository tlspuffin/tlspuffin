#!/usr/bin/env bash
# phase0_produce_metadata.sh
# Produces three metadata log files per trace in ./objective/.
# Run from the repository root: ./evaluation-ddyf/phase0_produce_metadata.sh
#
# Output per trace T:
#   metadata_diff_T.log          differential-execute -S
#   metadata_libssh0114_T.log    --put libssh0114-asan display-execute -t true -c true -k true -p true
#   metadata_wolfssh_T.log       --put wolfssh-asan display-execute -t true -c true -k true -p true

set -euo pipefail

export LD_LIBRARY_PATH="/nix/store/k0rqiflg1vkn1kj96br5pfxj40p3srz4-zstd-1.5.7/lib:${LD_LIBRARY_PATH:-}"
export ASAN_OPTIONS="verify_asan_link_order=1:detect_leaks=0:abort_on_error=1"

BINARY="${BINARY:-./sshpuffin_diff}"
PARALLELISM="${PARALLELISM:-20}"
OBJECTIVE_DIR="${OBJECTIVE_DIR:-./objective}"

if [ ! -x "$BINARY" ]; then
  echo "ERROR: sshpuffin_diff binary not found at $BINARY" >&2
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
  PUT1="$DIR/metadata_libssh0114_$BASE.log"
  PUT2="$DIR/metadata_wolfssh_$BASE.log"

  # Skip if all three logs already exist
  if [ -f "$DIFF" ] && [ -f "$PUT1" ] && [ -f "$PUT2" ]; then
    exit 0
  fi

  "$BINARY" differential-execute libssh0114-asan wolfssh-asan "$T" -S \
    > "$DIFF" 2>&1 || true

  "$BINARY" --put libssh0114-asan display-execute "$T" -tckp \
    > "$PUT1" 2>&1 || true

  "$BINARY" --put wolfssh-asan display-execute "$T" -tckp \
    > "$PUT2" 2>&1 || true
' _ "$BINARY" {}

echo ""
echo "=== Phase 0 complete ==="
N_DIFF=$(find "$OBJECTIVE_DIR" -name "metadata_diff_*.log" | wc -l)
N_PUT1=$(find "$OBJECTIVE_DIR" -name "metadata_libssh0114_*.log" | wc -l)
N_PUT2=$(find "$OBJECTIVE_DIR" -name "metadata_wolfssh_*.log" | wc -l)
echo "  Diff logs:     $N_DIFF / $N_TRACES"
echo "  libssh0114 logs:  $N_PUT1 / $N_TRACES"
echo "  wolfssh logs: $N_PUT2 / $N_TRACES"

if [ "$N_DIFF" -ne "$N_TRACES" ] || [ "$N_PUT1" -ne "$N_TRACES" ] || [ "$N_PUT2" -ne "$N_TRACES" ]; then
  echo ""
  echo "WARNING: log count mismatch — some traces may have failed. Check for missing logs:"
  find "$OBJECTIVE_DIR" -name "*.trace" | while read -r T; do
    BASE="$(basename "$T")"
    DIR="$(dirname "$T")"
    for PREFIX in metadata_diff_ metadata_libssh0114_ metadata_wolfssh_; do
      [ -f "$DIR/${PREFIX}${BASE}.log" ] || echo "  MISSING: $DIR/${PREFIX}${BASE}.log"
    done
  done | head -20
fi
