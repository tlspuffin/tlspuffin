#!/bin/bash

# This script runs flamegraph on the fuzzer.
# Usage:
USE="./fuzz_perf.sh [--release] [--put=<option>] [--verbose] [--binary=<path_to_tlspuffin>]"

## Argument parsing
target="debug"
verbose=""
base="."

tlspuffin_dir="$(dirname "$0")/../.."
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
  fi
done

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
echo "Using options: ${options} ${verbose}"

timeout 10s perf record --call-graph dwarf -- ${tlspuffin} --port 2430 experiment -t flamegrah -d flamegraph
perf script | "${tlspuffin_dir}/tools/profile/stackcollapse-perf.pl" \
            | "${tlspuffin_dir}/tools/profile/rust-unmangle" \
            | "${tlspuffin_dir}/tools/profile/flamegraph.pl" > flame.svg

# xdg-open flame.svg
