#!/bin/bash

export LIBAFL_EDGES_MAP_SIZE=262144

# echo 'Cleaning previous data'
cargo clean
rm -rf objectives seeds corpus experiments


echo 'Building fuzzer'
./tools/mk_vendor make wolfssl:wolfssl510
./tools/mk_vendor make openssl:openssl340
cargo build --release --bin tlspuffin --features cputs

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential

TIMEOUT='5h'
RUNS=50
CORES="0-3"
PORT=2000

for i in $(seq 1 $RUNS);
do
    echo "Run number $i"
    # Creating a new named pipe with a random number
    PIPENAME="pipe$RANDOM"
    mkfifo $PIPENAME

    # Run the campaign and get the objective folder path
    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl510 openssl340 --title "test$i" 2>&1 | tee -i $PIPENAME &
    OBJECTIVES="$(grep -oP "objective_dir: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    # removing pipe
    rm $PIPENAME

    echo "Triaging objectives in $OBJECTIVES"
    python -m DDYF.find_known_cves $OBJECTIVES


    # removing traces that are not interesting to save disk space
    rm -rf $OBJECTIVES/trash
    rm -rf $OBJECTIVES/../corpus
done


