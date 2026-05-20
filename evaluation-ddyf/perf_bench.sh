#!/bin/bash
set -euo pipefail

export LIBAFL_EDGES_MAP_SIZE=262144

TIMEOUT='1h'
CORES="0-3"
CORE_COUNT=4
PORT=2000
PIPENAME="pipe_1"
OUTFILE=results_perfs.csv
RUNS=10

get_execution_number () {
  local total_exec=$(tail -c 10000 $1 | grep -oP "total_execs\":\K([0-9]*)" | tail -n 1)

  echo "$2: $total_exec execs in $TIMEOUT"

  echo "$2,$total_exec,$TIMEOUT,$CORE_COUNT" >> $OUTFILE
}

clean () {
    rm -rf objective seeds corpus $PIPENAME
}

clean_and_reset_pipe () {
    clean
    mkfifo $PIPENAME
}


echo 'Cleaning previous data'
cargo clean
rm -rf objective seeds corpus experiments


echo 'Building fuzzer'
./tools/mk_vendor make wolfssl:wolfssl580
./tools/mk_vendor make openssl:openssl340
cargo build --release --bin tlspuffin --features cputs

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential

echo "Run,Executions,Timeout,Core count" > $OUTFILE


for i in $(seq 1 $RUNS);
do
    mkfifo $PIPENAME

    # run classical fuzzing campaigns
    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES --put wolfssl580 experiment --title "perf_wolfssl" 2>&1 | tee -i $PIPENAME &
    wolf_run="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    clean_and_reset_pipe

    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES --put openssl340 experiment --title "perf_openssl" 2>&1 | tee -i $PIPENAME &
    ossl_run="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    clean_and_reset_pipe

    # Run the diff fuzzing campaigns
    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl580 openssl340 --title "perf_ossl_vs_wolf" 2>&1 | tee -i $PIPENAME &
    diff_run="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    clean_and_reset_pipe

    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment openssl340 openssl340 --title "perf_ossl_vs_ossl" 2>&1 | tee -i $PIPENAME &
    diff_run_same_ossl="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    clean_and_reset_pipe

    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl580 wolfssl580 --title "perf_wolf_vs_wolf" 2>&1 | tee -i $PIPENAME &
    diff_run_same_wolf="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    rm -rf objective seeds corpus $PIPENAME



    get_execution_number "$wolf_run" "wolfSSL run"
    get_execution_number "$ossl_run" "OpenSSL run"
    get_execution_number "$diff_run" "OpenSSL vs wolfSSL"
    get_execution_number "$diff_run_same_ossl" "OpenSSL vs OpenSSL"
    get_execution_number "$diff_run_same_wolf" "wolfSSL vs wolfSSL"

done
