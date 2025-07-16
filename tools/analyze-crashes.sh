#!/bin/bash

# This script analyzes crash traces in a given directory using the tlspuffin binary.
# Usage:
USE="./analyze-crashes.sh <crash_dir> [--release] [--put=<option>] [--verbose] [--binary=<path_to_tlspuffin>]"

## Argument parsing
target="debug"
crash_dir=""
verbose=""
base="."

tlspuffin_dir="$(dirname "$0")/.."
# Parse arguments
for arg in "$@"; do
  if [[ "$arg" == "--release" ]]; then
    target="release"
  elif [[ "$arg" == "--put="* ]]; then
    options="$arg"
  elif [[ "$arg" == "--binary="* ]]; then
    # store in tlspuffin what's after "--binary":
    tlspuffin="${arg#--binary=}"
  elif [[ "$arg" == "--verbose" ]]; then
    verbose="--verbose"
  elif [[ "$arg" == "--dir="* ]]; then
    tlspuffin_dir="${arg#--dir=}"
  elif [[ "$arg" == "--help" ]]; then
    echo "Usage:"
    echo $USE
    exit 0
  else
    crash_dir_rel="$arg"
  fi
done
crash_dir="${tlspuffin_dir}/$crash_dir_rel"

if [ -z "$tlspuffin" ]; then
  tlspuffin="${tlspuffin_dir}/target/${target}/tlspuffin"
  if [ ! -f "$tlspuffin" ]; then
    echo "Error: tlspuffin binary not found at ${tlspuffin}. Please build it first."
    echo "Usage:"
    echo $USE
    exit 1
  fi
fi

echo "Puffin binary was built at:"
stat -c "%w %n" ${tlspuffin}
echo "Using options: ${options} ${verbose} and directory ${crash_dir}"

# Print available PUTs
${tlspuffin} --put X  |& tail -n 1 | head -n 1 | awk -F'\t' '{print $2}'
if ! ${tlspuffin} ${options} seed > /dev/null 2>&1; then
    echo "Error: tlspuffin binary crashed, possibly because PUT was not found."
    echo "Usage:"
    echo $USE
exit 1
fi

# Exit if the directory does not exist or is empty
if [ ! -d "$crash_dir" ] || [ -z "$(ls -A "$crash_dir")" ]; then
    echo "Directory $crash_dir does not exist or is empty."
    echo "Usage:"
    echo $USE
  exit 1
fi


export ASAN_OPTIONS=detect_leaks=0
export TIMEFORMAT="%Rs"
export RUST_LOG=warn

find "$crash_dir" -name "*.trace" -print0 | while IFS= read -r -d '' trace_file; do
    # if verbose argument is not empty!
    if [ -z $verbose ]; then
      "${tlspuffin}" ${options} execute "${trace_file}" > /dev/null 2> "${trace_file}.log"
    else
      echo "Processing: ${trace_file}"
      ## If execution time above exceeds 0,5s, print a warning
      start_time=$(date +%s.%N)
      "${tlspuffin}" "${options}" execute "${trace_file}" 2> "${trace_file}.log"
      end_time=$(date +%s.%N)
      elapsed_time=$(echo "$end_time - $start_time" | bc)
      if (( $(echo "$elapsed_time > 0.5" | bc -l) )); then
          echo "Warning: Execution time for ${trace_file} exceeded 0.5 seconds: ${elapsed_time}s" >&2
      fi
    fi
done

echo "Running asanalyzer..."
python3 $(dirname $0)/asanalyzer.py -d 3 $crash_dir/*.log ${verbose}
