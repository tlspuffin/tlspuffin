# Phase 0 — Static Data Producer

**Role:** Data production agent. You generate metadata logs for every trace. No analysis, no classification, no code writing — only running commands and saving output files.

**Model:** Haiku-class or equivalent (low capability). This phase is pure I/O.

**Parallelism:** Run as many traces in parallel as the machine allows. Use `xargs -P N` or a shell loop with `&`. Suggested: `PARALLELISM=20`.

---

## What to produce

For every trace file `T` found under `./objective/` (any subdirectory), produce three log files **in the same directory as the trace**:

| Log file | Command |
|---|---|
| `metadata_diff_T.log` | `./target/release/tlspuffin differential-execute openssl340 libressl421 T -S` |
| `metadata_openssl340_T.log` | `./target/release/tlspuffin --put openssl340 display-execute T -tckp` |
| `metadata_libressl421_T.log` | `./target/release/tlspuffin --put libressl421 display-execute T -tckp` |

Both stdout and stderr must be captured to the log file (`> log 2>&1`).

---

## Shell script

```bash
#!/usr/bin/env bash
# phase0_produce_metadata.sh
# Produces three metadata log files per trace in ./objective/.
# Run from the repository root.

set -euo pipefail
BINARY="./target/release/tlspuffin"
PARALLELISM=20
OBJECTIVE_DIR="./objective"

find "$OBJECTIVE_DIR" -name "*.trace" | xargs -P "$PARALLELISM" -I{} bash -c '
  T="$1"
  DIR="$(dirname "$T")"
  BASE="$(basename "$T")"

  # Skip if all three logs already exist and are newer than the trace
  DIFF="$DIR/metadata_diff_$BASE.log"
  OSSL="$DIR/metadata_openssl340_$BASE.log"
  LIBRE="$DIR/metadata_libressl421_$BASE.log"

  if [ -f "$DIFF" ] && [ -f "$OSSL" ] && [ -f "$LIBRE" ]; then
    echo "SKIP $BASE (logs exist)"
    exit 0
  fi

  echo "Processing $BASE"

  '"$BINARY"' differential-execute openssl340 libressl421 "$T" -S \
    > "$DIFF" 2>&1 || true

  '"$BINARY"' --put openssl340 display-execute "$T" -tckp \
    > "$OSSL" 2>&1 || true

  '"$BINARY"' --put libressl421 display-execute "$T" -tckp \
    > "$LIBRE" 2>&1 || true
' _ {}

echo "Phase 0 complete."
find "$OBJECTIVE_DIR" -name "metadata_diff_*.log" | wc -l
```

Save as `evaluation-ddyf/phase0_produce_metadata.sh` and run from the repo root:
```bash
chmod +x evaluation-ddyf/phase0_produce_metadata.sh
./evaluation-ddyf/phase0_produce_metadata.sh
```

---

## Verification

After the script completes, verify coverage:

```bash
# Count traces
N_TRACES=$(find ./objective -name "*.trace" | wc -l)

# Count log triplets (each trace should have 3 logs)
N_DIFF=$(find ./objective -name "metadata_diff_*.log" | wc -l)
N_OSSL=$(find ./objective -name "metadata_openssl340_*.log" | wc -l)
N_LIBRE=$(find ./objective -name "metadata_libressl421_*.log" | wc -l)

echo "Traces: $N_TRACES"
echo "Diff logs: $N_DIFF / $N_TRACES"
echo "OpenSSL logs: $N_OSSL / $N_TRACES"
echo "LibreSSL logs: $N_LIBRE / $N_TRACES"
```

Expected: all three counts equal `N_TRACES`.

After Phase 0 completes, the Orchestrator runs **Phase 0.5** (empty-criteria bootstrap pass) before any metadata is read. Phase 0.5 is a token-cheap mechanical pass that produces a first cut of the bucket scaffold by running the triaging script with no buckets and clustering the resulting difference-pattern table. See `PHASE_0_5_BOOTSTRAP.md` for the protocol.

---

## What to do if a command fails

`tlspuffin` may exit with a non-zero code for traces where a PUT fails — this is expected. The `|| true` in the script ensures the loop continues regardless. The log file will contain the error output, which is useful for Phase 1 analysis.

Do not retry. Do not investigate failures. Log the output and move on.

---

## What NOT to do

- Do not read or analyse the log contents.
- Do not create bucket conditions.
- Do not write any bug reports.
- Do not modify `sort_objectives_ossl_libre.py`.

Your only job is to ensure all three log files exist for every trace.
