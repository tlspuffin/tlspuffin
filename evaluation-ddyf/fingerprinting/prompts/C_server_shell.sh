#!/usr/bin/env bash
# Launch C — server shell, NO AI. Run after the scripts from Launch B exist.
# Run inside a detached tmux so it survives ssh disconnects:
#   tmux new -s fp
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Everything below assumes you are inside: nix-shell ./shell.nix
export LIBAFL_EDGES_MAP_SIZE=262144

# 1. Add presets for all 26 versions (review the printed diff before continuing).
python evaluation-ddyf/fingerprinting/presets_gen.py

# 2. Build every PUT + the harness. Caps the range to whatever builds; STOPS (does not
#    patch Rust) if the harness fails for a version — ask the human then.
bash evaluation-ddyf/fingerprinting/build_all.sh

# 3. Seeds for differential fuzzing.
./target/release/tlspuffin seed --fingerprinting   # client+honest seeds only (no server-attacker)

# 4. FRESH VALIDATION CAMPAIGN (short) over the 4 appendix versions, incl. 5.1.1.
#    Used by Launch A to confirm the pipeline reproduces clusters A0/A1/B.
#    NOTE: discover.sh takes positional pairs as "VERSION,VERSION" (not preset names),
#    and CORES is a libafl core SPEC ("0-9" = 10 cores), not a count.
TIMEOUT=45m CORES=0-9 \
  bash evaluation-ddyf/fingerprinting/discover.sh \
    5.0.0,5.1.0  5.0.0,5.1.1  5.0.0,5.2.0 \
    5.1.0,5.1.1  5.1.0,5.2.0  5.1.1,5.2.0
# --> Tell Launch A (Claude) to validate now. Do NOT proceed until it passes.

# 5. FULL DISCOVERY over the buildable contiguous range (adjacent pairs, sequential).
TIMEOUT=1h CORES=0-9 \
  bash evaluation-ddyf/fingerprinting/discover.sh   # adjacent pairs of all built versions

# 6. Run the deterministic pipeline: triage -> signatures -> clusters -> tree.
bash evaluation-ddyf/fingerprinting/run_all.sh

# Outputs land in evaluation-ddyf/fingerprinting/:
#   signatures.csv, clusters.json, tree.json, tree.dot, report.md, RESULTS.md
