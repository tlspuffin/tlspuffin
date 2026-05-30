#!/usr/bin/env bash

# launch_parallel_campaigns.sh
# Run 5-core, 1-hour campaigns for all adjacent working pairs in batches of 7.

set -euo pipefail

TIMEOUT=3600
CORES_PER_CAMPAIGN=4
CONCURRENCY=10
BASE_PORT=1337

# All 26 stable 5.x tags — 5.2.1 resurrected (AllowClaim fix only applied >=5.5.0).
VERSIONS=(
    "5.0.0" "5.1.0" "5.1.1" "5.2.0" "5.2.1" "5.3.0" "5.4.0" "5.5.0"
    "5.5.1" "5.5.2" "5.5.3" "5.5.4" "5.6.0" "5.6.2" "5.6.3" "5.6.4"
    "5.6.6" "5.7.0" "5.7.2" "5.7.4" "5.7.6" "5.8.0" "5.8.2" "5.8.4"
    "5.9.0" "5.9.1"
)

PAIRS=()
for ((i = 0; i < ${#VERSIONS[@]} - 1; i++)); do
    PAIRS+=("${VERSIONS[$i]},${VERSIONS[$i+1]}")
done

# We have 24 pairs. We run them in batches.
total_pairs=${#PAIRS[@]}
echo "Total pairs to run: $total_pairs"

batch_index=0
for ((i = 0; i < total_pairs; i+=CONCURRENCY)); do
    echo "========================================="
    echo "Starting batch $((batch_index + 1))"
    echo "========================================="
    
    pids=()
    for ((j = 0; j < CONCURRENCY; j++)); do
        idx=$((i + j))
        if [ $idx -ge $total_pairs ]; then
            break
        fi
        
        pair="${PAIRS[$idx]}"
        
        # Cores range: 0-4, 5-9, 10-14, ...
        core_start=$((j * CORES_PER_CAMPAIGN))
        core_end=$((core_start + CORES_PER_CAMPAIGN - 1))
        cores_str="${core_start}-${core_end}"
        
        port=$((BASE_PORT + idx * 10))
        
        echo "Launching $pair on cores $cores_str (port $port)"
        
        # Launch discover.sh in the background with the specific CORES string
        TIMEOUT=$TIMEOUT CORES=$cores_str BASE_PORT=$port \
            ./evaluation-ddyf/fingerprinting/discover.sh "$pair" &
        
        pids+=($!)
    done
    
    echo "Waiting for batch $((batch_index + 1)) to complete..."
    wait "${pids[@]}" || true
    echo "Batch $((batch_index + 1)) completed."
    
    batch_index=$((batch_index + 1))
done

echo "All batches completed."
