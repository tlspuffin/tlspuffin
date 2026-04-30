#!/bin/bash

export LIBAFL_EDGES_MAP_SIZE=262144

TIMEOUT='1h'
CORES="0-3"
PORT=2000

get_execution_number () {
  local total_exec=$(tail -c 10000 $1 | grep -oP "total_execs\":\K([0-9]*)" | tail -n 1)

  echo "$2: $total_exec execs in $TIMEOUT"
}



echo 'Cleaning previous data'
cargo clean
rm -rf objectives seeds corpus experiments


echo 'Building fuzzer'
./tools/mk_vendor make wolfssl:wolfssl580
./tools/mk_vendor make openssl:openssl340
cargo build --release --bin tlspuffin --features cputs

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential


PIPENAME="pipe_1"
mkfifo $PIPENAME

# run classical fuzzing campaigns
timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES --put wolfssl580 experiment --title "perf_wolfssl" 2>&1 | tee -i $PIPENAME &
wolf_run="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

rm -rf objectives seeds corpus experiments

timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES --put openssl340 experiment --title "perf_openssl" 2>&1 | tee -i $PIPENAME &
ossl_run="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

# Run the diff fuzzing campaigns
timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl580 openssl340 --title "perf_ossl_vs_wolf" 2>&1 | tee -i $PIPENAME &
diff_run="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

rm -rf objectives seeds corpus experiments

timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment openssl340 openssl340 --title "perf_ossl_vs_ossl" 2>&1 | tee -i $PIPENAME &
diff_run_same_ossl="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

rm -rf objectives seeds corpus experiments

timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl580 wolfssl580 --title "perf_wolf_vs_wolf" 2>&1 | tee -i $PIPENAME &
diff_run_same_wolf="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

rm -rf objectives seeds corpus experiments


rm $PIPENAME

get_execution_number "$wolf_run" "wolfSSL run"
get_execution_number "$ossl_run" "OpenSSL run"
get_execution_number "$diff_run" "Differential run OpenSSL vs wolfSSL"
get_execution_number "$diff_run_same_ossl" "Differential run OpenSSL vs OpenSSL"
get_execution_number "$diff_run_same_wolf" "Differential run wolfSSL vs wolfSSL"
