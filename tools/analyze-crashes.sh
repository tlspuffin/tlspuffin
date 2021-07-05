#!/bin/bash

tlspuffin="$(dirname "$0")/.."
crash_dir="$tlspuffin/$1"

export ASAN_OPTIONS=detect_leaks=0

find "$crash_dir" -name "*.trace" -exec sh -c 'target-asan/x86_64-unknown-linux-gnu/debug/tlspuffin execute $1 2>$1.log' _ {} \;

python3 tools/asanalyzer.py -d 3 $crash_dir/**/crashes/*.log
