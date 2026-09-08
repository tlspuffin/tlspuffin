#!/bin/bash
# Usage :
# ./exec_perf.sh protocol seeds/seed_a.trace [--release]


puffins_dir="$(dirname "$0")/../.."
protocol=$1
trace="$puffins_dir/$2"
# If an option --release is passed, set the variable target to "release"
if [[ "$3" == "--release" ]]; then
    target="release"
else
    target="debug"
fi
my_puffin="${puffins_dir}/target/${target}/${protocol}puffin"
echo "To execute: $trace"
echo "Puffin binary was built at:"
stat -c "%w %n" ${my_puffin}

perf record --call-graph dwarf -- ${my_puffin} execute ${trace}
perf script | "${puffins_dir}/tools/profile/stackcollapse-perf.pl" \
            | "${puffins_dir}/tools/profile/rust-unmangle" \
            | "${puffins_dir}/tools/profile/flamegraph.pl" > flame.svg

# xdg-open flame.svg
