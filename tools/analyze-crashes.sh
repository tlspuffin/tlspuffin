#!/bin/bash

# If an option --release is passed, set the variable target to "release"
if [[ "$2" == "--release" ]]; then
    target="release"
else
    target="debug"
fi
tlspuffin_dir="$(dirname "$0")/.."
tlspuffin=${tlspuffin_dir}/target/${target}/tlspuffin
crash_dir="${tlspuffin_dir}/$1"
# Exit if the directory does not exist or is empty
if [ ! -d "$crash_dir" ] || [ -z "$(ls -A "$crash_dir")" ]; then
    echo "Directory $crash_dir does not exist or is empty."
    exit 1
fi
echo "Crash dir: ${crash_dir}"
echo "Puffin binary was built at:"
stat -c "%w %n" ${tlspuffin}


#./tools/../target/release/tlspuffin --put X  |& tail -n 1 | head -n 1
export ASAN_OPTIONS=detect_leaks=0
export TIMEFORMAT="%Rs"
export RUST_LOG=warn

#find "$crash_dir" -name "*.trace" -exec sh -c 'ls $1; date +"%T"; RUST_LOG=warn target/${target}/tlspuffin execute $1 2> $1.log' _ {} \;
find "$crash_dir" -name "*.trace" -print0 | while IFS= read -r -d '' trace_file; do
    echo "Processing: ${trace_file}"
    ## If execution time above exceeds 0,5s, print a warning
    time "${tlspuffin}" execute "${trace_file}" 2> "${trace_file}.log"

#    if [ $? -ne 0 ]; then
#        echo "Warning: Processing $trace_file failed with status $?" >&2
#    fi
done

#./tools/../target/release/tlspuffin --put X  |& tail -n 1 | head -n 1

echo "Running asanalyzer..."

python3 $(dirname $0)/asanalyzer.py -d 3 $crash_dir/*.log
