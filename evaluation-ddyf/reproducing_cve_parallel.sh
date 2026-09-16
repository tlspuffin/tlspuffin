#!/usr/bin/env bash
set -euo pipefail

FIRST_CORE=${1:-0}
CORE_PER_EXP=${2:-8}
NB_WORKERS=${3:-5}
RUNS_PER_WORKER=${4:-10}

export LIBAFL_EDGES_MAP_SIZE=262144

TIMEOUT=${5:-5h}
PUT_A='openssl340'
PUT_B='wolfssl510'

# Logs live outside experiments/ so that listing_reproduced_cves.sh, which walks
# experiments/*, only ever sees actual campaign folders.
LOGDIR='cve_logs'
RESULTS='cve_list.csv'

TOTAL_RUNS=$(($NB_WORKERS * $RUNS_PER_WORKER))
LAST_CORE=$(($FIRST_CORE + $NB_WORKERS * $CORE_PER_EXP - 1))

echo "Running $TOTAL_RUNS campaigns of $TIMEOUT ($NB_WORKERS workers x $RUNS_PER_WORKER runs) on cores $FIRST_CORE-$LAST_CORE"

# Inlined from reproducing_cve.sh: runs the campaigns [START, END] one after the
# other on a single core range/port, triaging the objectives of each of them.
run_campaigns_with_triaging() {
    local START=$1
    local END=$2
    local START_CORE=$3

    local END_CORE=$(($START_CORE + CORE_PER_EXP - 1))
    local CORES="$START_CORE-$END_CORE"
    local PORT=$((10000 + $START_CORE))

    echo "Running campaigns $START to $END on cores $CORES using port $PORT"

    # Named pipe unique to this worker (its port is derived from its start core)
    local PIPENAME="pipe_$PORT"

    local i
    for i in $(seq $START $END); do
        echo "Run number $i"
        mkfifo $PIPENAME

        # Run the campaign and get the objective folder path
        timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment $PUT_A $PUT_B --title "test$i" 2>&1 | tee -i $PIPENAME &
        local OBJECTIVES="$(grep -oP "objective_dir: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

        # removing pipe
        rm $PIPENAME

        # -r: a campaign that produced no hidden metadata file must not abort the run
        find $OBJECTIVES -name ".*" | xargs -r -L 1000 rm

        # find_known_cves sorts the objectives into one bucket per known CVE,
        # which is what listing_reproduced_cves.sh reports at the end
        echo "Triaging objectives in $OBJECTIVES"
        python -m evaluation-ddyf.find_known_cves $OBJECTIVES

        rm -rf $OBJECTIVES/../corpus
        rm -rf $OBJECTIVES/../log
    done
}

echo 'Cleaning previous data'
cargo clean
# experiments/ and the pipe_* fifos are the leftovers of a previous (possibly
# interrupted) run, they would otherwise be mixed with the new results
rm -rf objective seeds corpus log pipe_* "$LOGDIR" "$RESULTS"
# experiments/ is a bind mount in the container: its content can be removed, it cannot
mkdir -p experiments
find experiments -mindepth 1 -maxdepth 1 -exec rm -rf {} +


echo 'Building fuzzer'
./tools/mk_vendor make "wolfssl:$PUT_B"
./tools/mk_vendor make "openssl:$PUT_A"
cargo build --release --bin tlspuffin --features cputs

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential


# Run the workers in parallel, one log file per worker. Worker i takes the
# campaign range [i * RUNS_PER_WORKER + 1, (i + 1) * RUNS_PER_WORKER] and its
# own range of CORE_PER_EXP cores.
mkdir -p "$LOGDIR"
PIDS=()
for i in $(seq 0 $(($NB_WORKERS - 1))); do
    WORKER=$(($i + 1))
    START=$(($i * $RUNS_PER_WORKER + 1))
    END=$((($i + 1) * $RUNS_PER_WORKER))
    LOG="$LOGDIR/worker$WORKER.log"
    echo "Starting worker $WORKER: campaigns $START-$END (logs in $LOG)"
    run_campaigns_with_triaging "$START" "$END" "$(($FIRST_CORE + $i * $CORE_PER_EXP))" > "$LOG" 2>&1 &
    PIDS+=($!)
done

STATUS=0
for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}" || { echo "Worker $(($i + 1)) failed"; STATUS=1; }
done


# Display the CVEs reproduced by all the campaigns. listing_reproduced_cves.sh
# starts by removing its output file, create it so that it has nothing to report
echo
echo 'Listing the reproduced CVEs'
: > "$RESULTS"
./evaluation-ddyf/listing_reproduced_cves.sh

# Tally of the CSV, `python -m evaluation-ddyf.cves_stats` gives the full analysis.
# The trash bucket is the catch-all of the triaging, it holds no reproduced CVE.
CVE_ROWS=$(awk -F, '
    NR == 1 { next }
    $2 == "trash" { next }
    { traces[$2]++; if (!seen[$2 SUBSEP $1]++) campaigns[$2]++ }
    END { for (cve in traces) printf "%-20s %12d %10d\n", cve, campaigns[cve], traces[cve] }' "$RESULTS" | sort)

echo
if [ -n "$CVE_ROWS" ]; then
    printf '%-20s %12s %10s\n' 'CVE' 'campaigns' 'traces'
    echo "$CVE_ROWS"
else
    echo 'No CVE reproduced'
fi

echo
echo "Reproduced CVEs written to $RESULTS (campaign logs in $LOGDIR/)"

exit $STATUS
