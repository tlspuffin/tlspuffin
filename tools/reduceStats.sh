#!/bin/bash

## This script reduces the size of the stats.json file by sampling a ratio of entries. It creates a new file called
## stats-sampled.json.

# Argument 1: experiment folder <experiment>
# input file will be at ./experiments/<experiment>/log/stats.json
# output file will be at ./experiments/<experiment>/log/stats-sampled.json
input="./experiments/$1/log/stats.json"
output="./experiments/$1/log/stats-sampled.json"
# if stat_file does not exists then look for the file at $exp/stats.json (as in older versions of puffin)
if [ ! -f "$input" ]; then
  input="./experiments/$1/stats.json"
  output="./experiments/$1/stats-sampled.json"
fi

max_size=$((100 * 1024 * 1024))  # 100MB in bytes

# Step 1: Get input file size
input_size=$(stat -c %s "$input")

# Step 2: Estimate sampling factor N
# We reserve a little margin (~90%) to be safe
N=$((input_size / (max_size * 90 / 100)))
N=$((N > 1 ? N : 1))  # Ensure N >= 1

echo "Input size: $(du -h "$input" | cut -f1). Estimated N: $N. "

# Step 3: Use awk to keep first line and every Nth line after that. remove last line as it can be ill-formatted
perl -pe 's/(\{"type":"global")/\n$1/g' "$input"| awk -v N="$N" 'NR==1 || ((NR-1) % N == 0)' | head -n -1  > "$output"

output_size=$(du -h "$output" | cut -f1)
output_lines=$(wc -l < "$output")

echo "Final file size: $output_size. Output size: $output_size. Output lines: $output_lines. "
