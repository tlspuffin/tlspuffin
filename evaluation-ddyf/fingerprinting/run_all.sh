#!/usr/bin/env bash

# run_all.sh
# Orchestrate the phases end-to-end; resumable.

set -euo pipefail

if [[ -z "${IN_NIX_SHELL:-}" ]]; then
    echo "Warning: Not in nix-shell. It is recommended to run this inside nix-shell ./shell.nix"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/../.."

echo "=== Phase 1: Presets & Builds ==="
python3 "$DIR/presets_gen.py"
# NOTE: To actually build all, uncomment the following line.
# It can take a long time and might fail on the first unsupported version.
# "$DIR/build_all.sh"

echo "=== Phase 2: Discovery Campaigns ==="
# NOTE: By default this runs on adjacent pairs of all 26 versions.
# "$DIR/discover.sh"

echo "=== Phase 3: Triage ==="
if [ -f "$DIR/triage.py" ]; then
    python3 "$DIR/triage.py"
else
    echo "triage.py not found, skipping."
fi

echo "=== Phase 4: Signatures & Clustering ==="
if [ -f "$DIR/signatures.py" ]; then
    python3 "$DIR/signatures.py"
else
    echo "signatures.py not found, skipping."
fi

echo "=== Phase 5: Build Tree ==="
if [ -f "$DIR/build_tree.py" ]; then
    python3 "$DIR/build_tree.py"
else
    echo "build_tree.py not found, skipping."
fi

echo "All available phases executed."
