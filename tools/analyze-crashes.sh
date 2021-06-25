#!/bin/bash

tlspuffin="$(dirname "$0")/.."
crash_dir="$tlspuffin/experiments/$1/crashes"

find "$crash_dir" -name "*.trace" -exec sh -c 'target/x86_64-unknown-linux-gnu/debug/tlspuffin execute $1 2>$1.log' _ {} \;
echo "'$crash_dir/*.log'"
python3 tools/asanalyzer.py -d 3 $crash_dir/*.log
