#!/usr/bin/env bash
set -euo pipefail

START=${1:-1}
END=${2:-50}
START_CORE=${3:-0}
INIT=${4:-1}


export LIBAFL_EDGES_MAP_SIZE=262144

TIMEOUT=${5:-5h}
CORE_PER_EXP=8


END_CORE=$(($START_CORE + CORE_PER_EXP - 1))
CORES="$START_CORE-$END_CORE"
PORT=$((10000 + $START_CORE))

echo "Running campaigns $START to $END on cores $CORES using port $PORT"

# Creating a new named pipe with a random number
PIPENAME="pipe_$PORT"

for i in $(seq $START $END);
do
    echo "Run number $i"
    mkfifo $PIPENAME

    # Run the campaign and get the objective folder path
    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment openssl340 wolfssl510 --title "test$i" 2>&1 | tee -i $PIPENAME &
    OBJECTIVES="$(grep -oP "objective_dir: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    # removing pipe
    rm $PIPENAME

    find $OBJECTIVES -name ".*" | xargs -r -L 1000 rm

    # find_known_cves sorts the objectives into one bucket per known CVE and is the
    # module matching the PUTs of this benchmark (openssl340 vs wolfssl510)
    echo "Triaging objectives in $OBJECTIVES"
    python -m evaluation-ddyf.find_known_cves $OBJECTIVES

    rm -rf $OBJECTIVES/../corpus
    rm -rf $OBJECTIVES/../log
done
