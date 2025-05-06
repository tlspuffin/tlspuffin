#!/bin/bash

tlspuffin_dir="$(dirname "$0")/../.."
to_execute="$tlspuffin_dir/$1"
# If an option --release is passed, set the variable target to "release"
if [[ "$2" == "--release" ]]; then
    target="release"
else
    target="debug"
fi
tlspuffin="${tlspuffin_dir}/target/${target}/tlspuffin"
echo "To execute: $to_execute"
echo "Puffin binary was built at:"
stat -c "%w %n" ${tlspuffin}

perf record --call-graph dwarf -- ${tlspuffin} execute ${to_execute}
perf script | "${tlspuffin_dir}/tools/profile/stackcollapse-perf.pl" \
            | "${tlspuffin_dir}/tools/profile/rust-unmangle" \
            | "${tlspuffin_dir}/tools/profile/flamegraph.pl" > flame.svg

# xdg-open flame.svg
