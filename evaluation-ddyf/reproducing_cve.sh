#!/bin/bash
set -euo pipefail

START=${1:-1}
END=${2:-50}
START_CORE=${3:-0}
INIT=${4:-1}


export LIBAFL_EDGES_MAP_SIZE=262144

if [ $INIT -eq 1 ]
then
    echo 'Cleaning previous data'
    cargo clean
    rm -rf objectives seeds corpus experiments


    echo 'Building fuzzer'
    ./tools/mk_vendor make wolfssl:wolfssl510
    ./tools/mk_vendor make openssl:openssl340
    cargo build --release --bin tlspuffin --features cputs

    echo 'Generate seeds for diff fuzzing'
    ./target/release/tlspuffin seed --differential
fi

TIMEOUT='5h'
CORE_PER_EXP=8


END_CORE=$(($START_CORE + CORE_PER_EXP - 1))
CORES="$START_CORE-$END_CORE"
PORT=$((10000 + $START_CORE))

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
