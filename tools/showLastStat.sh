#!/bin/bash

## This script shows the last client and global entry of an experiment stats.json file
  base="."
  for arg in "$@"; do
    if [[ "$arg" == "--dir="* ]]; then
      # store in tlspuffin what's after "--binary":
      base="${arg#--dir=}"
      options="$arg"
    else
      exp=$arg
    fi
  done

# Execute reduceStats.sh script:
./tools/reduceStats.sh "$exp" "$options"

output="$base/experiments/$exp/log/stats-sampled.json"
if [ ! -f "$output" ]; then
  output="$base/experiments/$exp/stats-sampled.json"
fi
tail -n 2 "$output" | jq