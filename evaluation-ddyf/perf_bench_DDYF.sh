#!/bin/bash

export LIBAFL_EDGES_MAP_SIZE=262144

TIMEOUT='10s'
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

# Run the diff fuzzing campaign
timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl580 openssl340 --title "perf_ossl_vs_wolf" 2>&1 | tee -i $PIPENAME &
diff_run="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment openssl340 openssl340 --title "perf_ossl_vs_ossl" 2>&1 | tee -i $PIPENAME &
diff_run_same_ossl="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl580 wolfssl580 --title "perf_wolf_vs_wolf" 2>&1 | tee -i $PIPENAME &
diff_run_same_wolf="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"


rm $PIPENAME

get_execution_number "$diff_run" "Differential run OpenSSL vs wolfSSL"
get_execution_number "$diff_run_same_ossl" "Differential run OpenSSL vs OpenSSL"
get_execution_number "$diff_run_same_wolf" "Differential run wolfSSL vs wolfSSL"
