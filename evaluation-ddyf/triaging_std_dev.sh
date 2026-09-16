#!/usr/bin/env bash
set -euo pipefail

FIRST_CORE=${1:-0}
CORE_PER_EXP=${2:-8}
NB_WORKERS=${3:-5}
RUNS_PER_WORKER=${4:-1}

export LIBAFL_EDGES_MAP_SIZE=262144

TIMEOUT=${5:-24h}
PUT_A='openssl340'
PUT_B='wolfssl580'

# The duration used to be the 4th argument, which is now the number of campaigns
# each worker runs one after the other
if [[ "$RUNS_PER_WORKER" =~ [^0-9] ]]; then
    echo "The arguments are FIRST_CORE CORE_PER_EXP NB_WORKERS RUNS_PER_WORKER TIMEOUT:" >&2
    echo "'$RUNS_PER_WORKER' is not a number of campaigns, the duration comes last" >&2
    echo "(5 campaigns of 24h on 8 cores each: $0 0 8 5 1 24h)" >&2
    exit 1
fi

# A worker triages the campaign it has just run, and all the workers run at the
# same time, so each triaging is given the cores of its own worker
# (oversubscribed twice, a trace execution is short)
export DDYF_PARALLELISM=${DDYF_PARALLELISM:-$(($CORE_PER_EXP * 2))}

NB_CAMPAIGNS=$(($NB_WORKERS * $RUNS_PER_WORKER))
LAST_CORE=$(($FIRST_CORE + $NB_WORKERS * $CORE_PER_EXP - 1))

echo "Running $NB_CAMPAIGNS campaigns of $TIMEOUT ($NB_WORKERS workers x $RUNS_PER_WORKER campaigns) on cores $FIRST_CORE-$LAST_CORE"

# Inlined from run_campaign_with_triaging_ossl_wolf.sh: runs one campaign on its
# own core range/port, then triages the objectives it produced.
run_campaign_with_triaging() {
    local START_CORE=$1
    local TITLE=$2
    local OBJDIR_FILE=$3

    local END_CORE=$(($START_CORE + CORE_PER_EXP - 1))
    local CORES="$START_CORE-$END_CORE"
    local PORT=$((10000 + $START_CORE))

    echo "Running campaign on cores $CORES using port $PORT"

    # Creating a new named pipe with a random number
    local PIPENAME="pipe_$PORT"

    mkfifo $PIPENAME

    # Run the campaign and get the objective folder path
    timeout -s KILL $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment $PUT_A $PUT_B --title "$TITLE" 2>&1 | tee -i $PIPENAME &
    local OBJECTIVES="$(grep -oP "objective_dir: \"\K(.*?)\"" < $PIPENAME | sed "s/\"//")"

    # removing pipe
    rm $PIPENAME

    find $OBJECTIVES -name ".*" | xargs -r -L 1000 rm

    # Record the objective folder so that the statistics can be computed later on
    echo "$OBJECTIVES" > $OBJDIR_FILE

    echo "Triaging objectives in $OBJECTIVES"
    python -m evaluation-ddyf.sort_objectives_ossl_wolf $OBJECTIVES

    rm -rf $OBJECTIVES/../corpus
    # log/stats.json is the input of the deduplication plot (Claim 3), the rest
    # of log/ is the broker log, which is tens of GiB on a long campaign
    find "$OBJECTIVES/../log" -type f ! -name stats.json -delete 2>/dev/null || true
}

echo 'Cleaning previous data'
cargo clean
# experiments/ and the pipe_* fifos are the leftovers of a previous (possibly
# interrupted) experiment, they would otherwise be mixed with the new statistics
rm -rf objective seeds corpus log pipe_*
# experiments/ is a bind mount in the container: its content can be removed, it cannot
mkdir -p experiments
find experiments -mindepth 1 -maxdepth 1 -exec rm -rf {} +


echo 'Building fuzzer'
./tools/mk_vendor make wolfssl:wolfssl580
./tools/mk_vendor make openssl:openssl340
cargo build --release --bin tlspuffin --features cputs

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential


# Runs the campaigns [START, END] one after the other on the cores of one worker
run_worker() {
    local START=$1
    local END=$2
    local START_CORE=$3

    local i
    for i in $(seq $START $END); do
        echo "Starting campaign $i (logs in experiments/logs/campaign$i.log)"
        run_campaign_with_triaging "$START_CORE" "test$i" \
            "experiments/logs/campaign$i.objdir" \
            > "experiments/logs/campaign$i.log" 2>&1
    done
}

# Run the workers in parallel, one log file per campaign. Worker i takes the
# campaigns [i * RUNS_PER_WORKER + 1, (i + 1) * RUNS_PER_WORKER] and its own
# range of CORE_PER_EXP cores.
mkdir -p experiments/logs
PIDS=()
for i in $(seq 0 $(($NB_WORKERS - 1))); do
    WORKER=$(($i + 1))
    START=$(($i * $RUNS_PER_WORKER + 1))
    END=$((($i + 1) * $RUNS_PER_WORKER))
    LOG="experiments/logs/worker$WORKER.log"
    echo "Starting worker $WORKER: campaigns $START-$END (logs in $LOG)"
    run_worker "$START" "$END" "$(($FIRST_CORE + $i * $CORE_PER_EXP))" > "$LOG" 2>&1 &
    PIDS+=($!)
done

STATUS=0
for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}" || { echo "Worker $(($i + 1)) failed"; STATUS=1; }
done


# Count the buckets and the objectives of each campaign, then aggregate them
STATS="experiments/logs/triaging_stats.csv"
echo "campaign,empty_buckets,non_empty_buckets,total_objectives,non_triaged,non_triaged_pct" > $STATS

for CAMPAIGN in $(seq 1 $NB_CAMPAIGNS); do
    OBJDIR_FILE="experiments/logs/campaign$CAMPAIGN.objdir"

    if [ ! -f "$OBJDIR_FILE" ]; then
        echo "No objective folder recorded for campaign $CAMPAIGN, skipping it"
        continue
    fi

    # list_buckets.sh prints "non triaged : N", then "<bucket> : N" per bucket and "total: N"
    ./evaluation-ddyf/list_buckets.sh "$(cat $OBJDIR_FILE)" | awk -v campaign=$CAMPAIGN '
        /^non triaged :/ { non_triaged = $NF; next }
        /^total:/        { total = $NF; next }
        / : /            { if ($NF == 0) empty++; else non_empty++ }
        END {
            pct = (total > 0) ? 100 * non_triaged / total : 0
            printf "%d,%d,%d,%d,%d,%.2f\n", campaign, empty, non_empty, total, non_triaged, pct
        }' >> $STATS
done

# Summary of the campaign: the per-campaign table and its mean/standard deviation
SUMMARY="experiments/logs/summary.md"

cat > $SUMMARY <<EOF
# Differential fuzzing campaign summary

- Date: $(date --iso-8601=seconds)
- PUTs: $PUT_A vs $PUT_B
- Campaigns: $NB_CAMPAIGNS of $CORE_PER_EXP cores ($NB_WORKERS at a time), on cores $FIRST_CORE-$LAST_CORE
- Timeout per campaign: $TIMEOUT
- Logs: experiments/logs/campaign<N>.log, raw counts: $STATS

EOF

# Both tables are built from $STATS, non triaged objectives are counted in the total
awk -F, '
    NR == 1 { next }
    {
        campaign[++n] = $0
        for (f = 2; f <= NF; f++) {
            sum[f] += $f
            sum_sq[f] += $f * $f
            if (n == 1 || $f < min[f]) min[f] = $f
            if (n == 1 || $f > max[f]) max[f] = $f
        }
    }
    END {
        if (n == 0) { print "No campaign statistics to aggregate"; exit }

        print "## Per-campaign results\n"
        print "| Campaign | Empty buckets | Non-empty buckets | Total objectives | Non triaged | Non triaged (%) |"
        print "| --- | ---: | ---: | ---: | ---: | ---: |"
        for (i = 1; i <= n; i++) {
            split(campaign[i], c, ",")
            printf "| %s | %s | %s | %s | %s | %s |\n", c[1], c[2], c[3], c[4], c[5], c[6]
        }

        printf "\n## Aggregated over %d campaigns\n\n", n
        print "| Metric | Mean | Std dev | Min | Max |"
        print "| --- | ---: | ---: | ---: | ---: |"
        split("Empty buckets;Non-empty buckets;Total objectives;Non triaged;Non triaged (%)", metric, ";")
        for (f = 2; f <= 6; f++) {
            mean = sum[f] / n
            var = (n > 1) ? (sum_sq[f] - n * mean * mean) / (n - 1) : 0
            if (var < 0) var = 0
            printf "| %s | %.2f | %.2f | %.2f | %.2f |\n", metric[f - 1], mean, sqrt(var), min[f], max[f]
        }
    }' $STATS >> $SUMMARY

cat $SUMMARY
echo "Summary written to $SUMMARY"

exit $STATUS
