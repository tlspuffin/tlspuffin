#!/usr/bin/env bash

# discover.sh
# Run discovery campaigns for fingerprinting.

set -euo pipefail

# TIMEOUT: passed to `timeout` (e.g. 3600, 45m, 1h). CORES: a libafl core SPEC,
# NOT a count -- "0-9" means 10 cores; "10" would mean the single core id #10.
TIMEOUT=${TIMEOUT:-1h}
CORES=${CORES:-0-9}
BASE_PORT=${BASE_PORT:-1337}
PORT_STEP=${PORT_STEP:-10}

# All 26 stable 5.x tags. 5.2.1 is included: fix = ["AllowClaim"] only applies
# to 5.5.0+ (see presets_gen.py), so 5.2.1 compiles cleanly without the patch.
VERSIONS=(
    "5.0.0" "5.1.0" "5.1.1" "5.2.0" "5.2.1" "5.3.0" "5.4.0" "5.5.0"
    "5.5.1" "5.5.2" "5.5.3" "5.5.4" "5.6.0" "5.6.2" "5.6.3" "5.6.4"
    "5.6.6" "5.7.0" "5.7.2" "5.7.4" "5.7.6" "5.8.0" "5.8.2" "5.8.4"
    "5.9.0" "5.9.1"
)

# Move to repo root
cd "$(dirname "$0")/../.." || exit 1

PAIRS=()

if [ $# -gt 0 ]; then
    # explicit pair list like 5.0.0,5.1.0
    for p in "$@"; do
        PAIRS+=("${p/,/ }")
    done
else
    # generate adjacent pairs
    for ((i = 0; i < ${#VERSIONS[@]} - 1; i++)); do
        PAIRS+=("${VERSIONS[$i]} ${VERSIONS[$i+1]}")
    done
fi

port=$BASE_PORT

for pair in "${PAIRS[@]}"; do
    read -r v1 v2 <<< "$pair"
    
    # wolfssl preset names omit dots (no -asan suffix for fingerprinting campaigns)
    v1_name="wolfssl${v1//./}"
    v2_name="wolfssl${v2//./}"
    title="fpp-${v1}-${v2}"
    
    # Check if experiment already has objectives
    # The dir will have fpp-V1-V2 in the name
    existing_traces=0
    shopt -s nullglob
    for exp_dir in experiments/*"${title}"*; do
        if [ -d "$exp_dir/objective" ]; then
            count=$(find "$exp_dir/objective" -maxdepth 1 -name "*.trace" 2>/dev/null | wc -l)
            if [ "$count" -gt 0 ]; then
                existing_traces=1
                break
            fi
        fi
    done
    shopt -u nullglob
    
    if [ "$existing_traces" -eq 1 ]; then
        echo "Skipping $v1 vs $v2 ($title): objectives already exist."
        continue
    fi
    
    echo "Running $v1 vs $v2 ($title) on port $port with cores $CORES..."
    # Sequential: each campaign gets the full CORES spec. Port is stepped by a fixed
    # amount (not by core count) to avoid TIME_WAIT collisions between runs.
    timeout $TIMEOUT ./target/release/tlspuffin -p $port --cores "$CORES" differential-experiment "$v1_name" "$v2_name" -t "$title" || true

    port=$((port + PORT_STEP))
done
