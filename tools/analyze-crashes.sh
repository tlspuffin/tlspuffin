#!/bin/bash

rm crashes/*.log
find ./crashes -name "*.trace" -exec sh -c 'target/x86_64-unknown-linux-gnu/debug/tlspuffin execute $1 2>$1.log' _ {} \;
python3 tools/asanalyzer.py -d 3 'crashes/*.log'
