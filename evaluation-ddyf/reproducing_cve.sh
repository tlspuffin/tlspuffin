#!/bin/bash
set -euo pipefail

SEQ=0


export LIBAFL_EDGES_MAP_SIZE=262144

echo 'Cleaning previous data'
cargo clean
rm -rf objectives seeds corpus experiments


echo 'Building fuzzer'
./tools/mk_vendor make wolfssl:wolfssl510
./tools/mk_vendor make openssl:openssl340
cargo build --release --bin tlspuffin --features cputs

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential



TIMEOUT='5h'
START=$((1+10*$SEQ))
END=$((10+10*$SEQ))

FIRST_CORE=24
START_CORE=$(($FIRST_CORE + 8*SEQ))
END_CORE=$(($FIRST_CORE + 8 + 8*SEQ - 1))
CORES="$START_CORE-$END_CORE"
PORT=$((10000 + $SEQ))

echo "Running campaigns $START to $END on cores $CORES using port $PORT"

# Creating a new named pipe with a random number
PIPENAME="pipe$PORT"

for i in $(seq $START $END);
do
    echo "Run number $i"
    mkfifo $PIPENAME

    # Run the campaign and get the objective folder path
    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl510 openssl340 --title "test$i" 2>&1 | tee -i $PIPENAME &
    OBJECTIVES="$(grep -oP "objective_dir: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    # removing pipe
    rm $PIPENAME

    echo "Triaging objectives in $OBJECTIVES"
    python -m evaluation-ddyf.find_known_cves $OBJECTIVES

    # removing traces that are not interesting to save disk space
    rm -rf $OBJECTIVES/trash
    rm -rf $OBJECTIVES/../corpus
done
