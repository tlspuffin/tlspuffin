#!/usr/bin/env bash
set -euo pipefail

# We must rebuild the harness with a larger edges map because compiling 26 C PUTs
# exceeds the default libafl map size of 2,097,152.
export LIBAFL_EDGES_MAP_DEFAULT_SIZE=16777216
export LIBAFL_EDGES_MAP_SIZE=16777216
export LIBAFL_EDGES_MAP_ALLOCATED_SIZE=16777216

echo "Rebuilding harness with enlarged edges map..."
cargo build --release --bin tlspuffin --features cputs

echo "Generating seeds..."
./target/release/tlspuffin seed --fingerprinting

echo "Launching parallel campaigns..."
bash launch_parallel_campaigns.sh

# pkill any lingering brokers that ignored timeout
pkill -u $USER -f 'target/release/tlspuffin' || true

echo "Campaigns finished. Running triage..."
python evaluation-ddyf/fingerprinting/triage.py

echo "Running signatures..."
python evaluation-ddyf/fingerprinting/signatures.py

echo "Building tree..."
python evaluation-ddyf/fingerprinting/build_tree.py

echo "Pipeline fully complete!"
