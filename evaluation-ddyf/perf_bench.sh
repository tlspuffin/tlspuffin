#!/usr/bin/env bash
set -euo pipefail

FIRST_CORE=${1:-0}
NB_WORKERS=${2:-1}
RUNS_PER_WORKER=${3:-10}
TIMEOUT=${4:-1h}

export LIBAFL_EDGES_MAP_SIZE=262144

PUT_A='openssl340'
PUT_B='wolfssl580'

OUTFILE=results_perfs.csv
# Logs and per-worker results live outside experiments/, which only holds campaigns
LOGDIR='perf_logs'

TOTAL_RUNS=$(($NB_WORKERS * $RUNS_PER_WORKER))
LAST_CORE=$(($FIRST_CORE + $NB_WORKERS - 1))

echo "Running $TOTAL_RUNS runs of 5 campaigns of $TIMEOUT ($NB_WORKERS workers x $RUNS_PER_WORKER runs) on cores $FIRST_CORE-$LAST_CORE"

get_execution_number () {
    local total_exec=$(tail -c 10000 $1 | grep -oP "total_execs\":\K([0-9]*)" | tail -n 1)

    echo "$2: $total_exec execs in $TIMEOUT"

    # one core per campaign, always: the column is kept for perfs_stats.py
    echo "$2,$total_exec,$TIMEOUT,1" >> $3
}

# Runs one campaign on the given cores/port and echoes the path of its stats file.
# The campaign output goes to stderr (the worker log), so that only the path is
# captured by the caller's command substitution.
run_campaign () {
    local CORES=$1
    local PORT=$2
    local PIPENAME=$3
    local TITLE=$4
    shift 4

    rm -f $PIPENAME
    mkfifo $PIPENAME

    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES "$@" --title "$TITLE" 2>&1 | tee -i $PIPENAME >&2 &

    local STATS
    STATS="$(grep -oP "stats_file: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    rm -f $PIPENAME

    echo "$STATS"
}

# One worker: RUNS_PER_WORKER repetitions of the 5 configurations, on its own
# core, broker port, named pipe and results file.
run_perf_campaigns () {
    local WORKER=$1
    local START_CORE=$2
    local OUT=$3

    local CORES="$START_CORE"
    local PORT=$((2000 + $START_CORE))
    local PIPENAME="pipe_$PORT"

    # The experiment folder is named after the title and the current time, with a
    # one second resolution: without a per-worker suffix, workers starting the same
    # campaign at the same time would claim the same folder and abort.
    local S="_w$WORKER"

    echo "Worker $WORKER: $RUNS_PER_WORKER runs on core $CORES using port $PORT"

    local i wolf_run ossl_run diff_run diff_run_same_ossl diff_run_same_wolf
    for i in $(seq 1 $RUNS_PER_WORKER); do
        echo "Run number $i"

        # run classical fuzzing campaigns
        wolf_run=$(run_campaign "$CORES" "$PORT" "$PIPENAME" "perf_wolfssl$S" --put $PUT_B experiment)
        ossl_run=$(run_campaign "$CORES" "$PORT" "$PIPENAME" "perf_openssl$S" --put $PUT_A experiment)

        # Run the diff fuzzing campaigns
        diff_run=$(run_campaign "$CORES" "$PORT" "$PIPENAME" "perf_ossl_vs_wolf$S" differential-experiment $PUT_B $PUT_A)
        diff_run_same_ossl=$(run_campaign "$CORES" "$PORT" "$PIPENAME" "perf_ossl_vs_ossl$S" differential-experiment $PUT_A $PUT_A)
        diff_run_same_wolf=$(run_campaign "$CORES" "$PORT" "$PIPENAME" "perf_wolf_vs_wolf$S" differential-experiment $PUT_B $PUT_B)

        get_execution_number "$wolf_run" "wolfSSL run" "$OUT"
        get_execution_number "$ossl_run" "OpenSSL run" "$OUT"
        get_execution_number "$diff_run" "OpenSSL vs wolfSSL" "$OUT"
        get_execution_number "$diff_run_same_ossl" "OpenSSL vs OpenSSL" "$OUT"
        get_execution_number "$diff_run_same_wolf" "wolfSSL vs wolfSSL" "$OUT"
    done
}


echo 'Cleaning previous data'
cargo clean
rm -rf objective seeds corpus pipe_* "$LOGDIR" "$OUTFILE"
# experiments/ is a bind mount in the container: its content can be removed, it cannot
mkdir -p experiments
find experiments -mindepth 1 -maxdepth 1 -exec rm -rf {} +


echo 'Building fuzzer'
./tools/mk_vendor make "wolfssl:$PUT_B"
./tools/mk_vendor make "openssl:$PUT_A"
cargo build --release --bin tlspuffin --features cputs

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential


# Run the workers in parallel, one log and one results file per worker
mkdir -p "$LOGDIR"
PIDS=()
for i in $(seq 0 $(($NB_WORKERS - 1))); do
    WORKER=$(($i + 1))
    LOG="$LOGDIR/worker$WORKER.log"
    : > "$LOGDIR/worker$WORKER.csv"
    echo "Starting worker $WORKER (logs in $LOG)"
    run_perf_campaigns "$WORKER" "$(($FIRST_CORE + $i))" "$LOGDIR/worker$WORKER.csv" > "$LOG" 2>&1 &
    PIDS+=($!)
done

STATUS=0
for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}" || { echo "Worker $(($i + 1)) failed"; STATUS=1; }
done


# Merge the per-worker results into the single CSV read by perfs_stats.py
echo "Run,Executions,Timeout,Core count" > $OUTFILE
for i in $(seq 1 $NB_WORKERS); do
    cat "$LOGDIR/worker$i.csv" >> $OUTFILE
done

echo
echo "Results written to $OUTFILE ($(($(wc -l < $OUTFILE) - 1)) measurements, worker logs in $LOGDIR/)"

python -m evaluation-ddyf.perfs_stats $OUTFILE

echo ""

python -m evaluation-ddyf.perfs_stats results_perfs.csv

exit $STATUS
