#!/bin/bash

tlspuffin="$(dirname "$0")/.."
crash_dir="$tlspuffin/$1"
echo "Crash dir: $crash_dir"
echo "Running tlspufin binary: ${tlspuffin}/target/release/tlspuffin"

export ASAN_OPTIONS=detect_leaks=0
find "$crash_dir" -name "*.trace" -exec sh -c 'target/release/tlspuffin execute $1 2> $1.log' _ {} \;

echo "Running asanalyzer..."
python3 tools/asanalyzer.py -d 3 $crash_dir/*.log
