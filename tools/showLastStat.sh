#!/bin/bash

## This script shows the last client and global entry of an experiment stats.json file

# Execute reduceStats.sh script:
./tools/reduceStats.sh "$1"

output="./experiments/$1/log/stats-sampled.json"
if [ ! -f "$output" ]; then
  output="./experiments/$1/stats-sampled.json"
fi
tail -n 2 "$output" | jq