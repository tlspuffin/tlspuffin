#!/usr/bin/env bash
set -euo pipefail

# Analysis part of triaging_std_dev.sh (Claim 2): it runs no fuzzing campaign at
# all, it only compares the buckets of the campaigns already in experiments/ and
# reports how stable they are from one campaign to the next.
#
# A campaign already triaged by triaging_std_dev.sh is counted as it is, which
# costs seconds. A campaign coming from the Claim 1 experiment is only sorted
# into one folder per known CVE, so its traces are first gathered back into a
# flat objective_std_dev/ folder and triaged with the buckets of
# sort_objectives_ossl_wolf.py, leaving the CVE folders untouched. Set
# DDYF_RETRIAGE=1 to triage again a campaign that was already triaged.

EXP_ROOT=${1:-experiments}
PUT_A=${2:-}
PUT_B=${3:-}
PARALLELISM=${4:-8}
RETRIAGE=${DDYF_RETRIAGE:-0}

export LIBAFL_EDGES_MAP_SIZE=262144
# The statistics below are sorted and formatted with a dot as decimal separator
export LC_NUMERIC=C

FUZZER='./target/release/tlspuffin'
WORKDIR_NAME='objective_std_dev'

LOGDIR="$EXP_ROOT/logs"
STATS="$LOGDIR/triaging_stats_reduced.csv"
BUCKET_STATS="$LOGDIR/bucket_counts_reduced.csv"
SUMMARY="$LOGDIR/summary_reduced.md"

# Campaign folders are the children of $EXP_ROOT holding an objective/ folder,
# which leaves out logs/ and any other bookkeeping folder
CAMPAIGNS=()
for exp in "$EXP_ROOT"/*/; do
    exp="${exp%/}"
    [ -d "$exp/objective" ] && CAMPAIGNS+=("$exp")
done

if [ "${#CAMPAIGNS[@]}" -eq 0 ]; then
    echo "No campaign found in $EXP_ROOT/: run a set of campaigns first" >&2
    echo "(./evaluation-ddyf/triaging_std_dev.sh or ./evaluation-ddyf/reproducing_cve_parallel.sh)" >&2
    exit 1
fi

# no_errors/ is the first bucket every sort_objectives_*.py creates, so its presence tells
# that the campaign has been triaged (the ablation study creates it too: run this script on
# a campaign's own objective/ folder, not on an ablation copy)
TO_TRIAGE=()
for exp in "${CAMPAIGNS[@]}"; do
    if [ "$RETRIAGE" != 0 ] || [ ! -d "$exp/objective/no_errors" ]; then
        TO_TRIAGE+=("$exp")
    fi
done

echo "Analysing ${#CAMPAIGNS[@]} campaigns from $EXP_ROOT/, ${#TO_TRIAGE[@]} of them to triage"

# Only the campaigns that have to be triaged need the fuzzer: the traces are
# executed again on both PUTs to be sorted into buckets
if [ "${#TO_TRIAGE[@]}" -gt 0 ]; then
    if [ ! -x "$FUZZER" ]; then
        echo "$FUZZER not found: run this script from the root of the repository," >&2
        echo "with the fuzzer of the campaigns already built" >&2
        echo "(cargo build --release --bin tlspuffin --features cputs)" >&2
        exit 1
    fi

    # The PUTs of the campaigns are recorded in the README.md written by the
    # fuzzer, as the first two arguments of the differential-experiment command
    if [ -z "$PUT_A" ] || [ -z "$PUT_B" ]; then
        DETECTED=($(grep -oP 'raw_vals: \[\["\K[^"]+' "${TO_TRIAGE[0]}/README.md" 2>/dev/null | head -n 2 || true))
        PUT_A=${PUT_A:-${DETECTED[0]:-openssl340}}
        PUT_B=${PUT_B:-${DETECTED[1]:-wolfssl580}}
    fi

    echo "Triaging with $PUT_A vs $PUT_B, $PARALLELISM traces at a time"

    # An unknown PUT is only reported on a valid trace, hence the sample
    SAMPLE_TRACE=$(find "${TO_TRIAGE[0]}/objective" -mindepth 1 -maxdepth 2 -type f \
        -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?' | head -n 1)

    if [ -z "$SAMPLE_TRACE" ]; then
        echo "No trace found in ${TO_TRIAGE[0]}/objective" >&2
        exit 1
    fi

    PUT_CHECK=$("$FUZZER" differential-execute --json "$PUT_A" "$PUT_B" "$SAMPLE_TRACE" 2>&1 || true)
    if grep -q 'PUT not found' <<<"$PUT_CHECK"; then
        echo "$PUT_CHECK" | grep -E 'PUT not found|Available PUTs' >&2
        echo "Pass the PUTs of the campaigns as arguments, or rebuild the fuzzer with them" >&2
        exit 1
    fi

    export DDYF_FIRST_PUT="$PUT_A"
    export DDYF_SECOND_PUT="$PUT_B"
    export DDYF_PARALLELISM="$PARALLELISM"
fi

# Gather the traces and their metadata of every bucket of a campaign into one
# flat folder. Hard links keep the Claim 1 buckets intact and cost no disk
# space; a copy is the fallback when the work folder is on another filesystem.
gather_traces() {
    local src=$1
    local dst=$2

    if find "$src" -mindepth 1 -maxdepth 2 -type f -print0 |
        xargs -0 -r -n 500 ln -f -t "$dst" 2>/dev/null; then
        return 0
    fi

    find "$src" -mindepth 1 -maxdepth 2 -type f -print0 |
        xargs -0 -r -n 500 cp -f -t "$dst"
}

mkdir -p "$LOGDIR"

STATUS=0
for i in "${!CAMPAIGNS[@]}"; do
    CAMPAIGN=$(($i + 1))
    EXP="${CAMPAIGNS[$i]}"
    WORK="$EXP/objective"
    LOG="$LOGDIR/triaging_reduced_campaign$CAMPAIGN.log"

    if [[ " ${TO_TRIAGE[*]-} " == *" $EXP "* ]]; then
        WORK="$EXP/$WORKDIR_NAME"

        echo "Campaign $CAMPAIGN: $(basename "$EXP"), triaging (logs in $LOG)"

        # Derived folder of a previous run of this script, it would mix two triagings
        rm -rf "$WORK"
        mkdir -p "$WORK"

        {
            echo "Campaign: $EXP"
            gather_traces "$EXP/objective" "$WORK"
            echo "Triaging $(find "$WORK" -maxdepth 1 -type f -regextype posix-egrep \
                -regex '.*\.trace(-[0-9]+)?' | wc -l) traces in $WORK"
            python -m evaluation-ddyf.sort_objectives_ossl_wolf "$WORK"
        } > "$LOG" 2>&1 || { echo "Campaign $CAMPAIGN failed, see $LOG"; STATUS=1; }
    else
        echo "Campaign $CAMPAIGN: $(basename "$EXP"), already triaged"
    fi

    ./evaluation-ddyf/list_buckets.sh "$WORK" > "$LOGDIR/campaign$CAMPAIGN.buckets"
done

# Per-campaign counts, in the format of triaging_std_dev.sh, and the count of
# every bucket in every campaign, which is what the stability is computed on
echo "campaign,empty_buckets,non_empty_buckets,total_objectives,non_triaged,non_triaged_pct" > $STATS
echo "campaign,bucket,objectives" > $BUCKET_STATS

for i in "${!CAMPAIGNS[@]}"; do
    CAMPAIGN=$(($i + 1))
    BUCKETS="$LOGDIR/campaign$CAMPAIGN.buckets"

    [ -f "$BUCKETS" ] || continue

    # list_buckets.sh prints "non triaged : N", then "<bucket> : N" per bucket and "total: N"
    awk -v campaign=$CAMPAIGN '
        /^non triaged :/ { non_triaged = $NF; next }
        /^total:/        { total = $NF; next }
        / : /            { if ($NF == 0) empty++; else non_empty++ }
        END {
            pct = (total > 0) ? 100 * non_triaged / total : 0
            printf "%d,%d,%d,%d,%d,%.2f\n", campaign, empty, non_empty, total, non_triaged, pct
        }' "$BUCKETS" >> $STATS

    awk -v campaign=$CAMPAIGN '
        /^non triaged :/ { next }
        /^total:/        { next }
        / : / {
            name = $1
            sub(/.*\//, "", name)
            printf "%d,%s,%d\n", campaign, name, $NF
        }' "$BUCKETS" >> $BUCKET_STATS
done

NB_CAMPAIGNS=${#CAMPAIGNS[@]}

# For the summary header, when no campaign had to be triaged
if [ -z "$PUT_A" ] || [ -z "$PUT_B" ]; then
    DETECTED=($(grep -oP 'raw_vals: \[\["\K[^"]+' "${CAMPAIGNS[0]}/README.md" 2>/dev/null | head -n 2 || true))
    PUT_A=${PUT_A:-${DETECTED[0]:-unknown}}
    PUT_B=${PUT_B:-${DETECTED[1]:-unknown}}
fi

cat > $SUMMARY <<EOF
# Stability of the findings across campaigns (Claim 2, analysis only)

- Date: $(date --iso-8601=seconds)
- PUTs: $PUT_A vs $PUT_B
- Campaigns: $NB_CAMPAIGNS from $EXP_ROOT/, ${#TO_TRIAGE[@]} triaged by this script, no new campaign
- Logs: $LOGDIR/triaging_reduced_campaign<N>.log
- Raw counts: $STATS and $BUCKET_STATS

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

# Stability of each bucket: a bucket found in every campaign is a difference
# that DDYF rediscovers independently of the campaign
{
    printf '\n## Per-bucket stability over %d campaigns\n\n' "$NB_CAMPAIGNS"
    printf '| Bucket | Campaigns | Mean | Std dev | Min | Max |\n'
    printf '| --- | ---: | ---: | ---: | ---: | ---: |\n'
    awk -F, -v n="$NB_CAMPAIGNS" '
        NR == 1 { next }
        {
            bucket = $2
            if (!(bucket in seen)) { seen[bucket] = 1; order[++b] = bucket }
            sum[bucket] += $3
            sum_sq[bucket] += $3 * $3
            if (!(bucket in min) || $3 < min[bucket]) min[bucket] = $3
            if (!(bucket in max) || $3 > max[bucket]) max[bucket] = $3
            if ($3 > 0) present[bucket]++
        }
        END {
            for (i = 1; i <= b; i++) {
                bucket = order[i]
                mean = sum[bucket] / n
                var = (n > 1) ? (sum_sq[bucket] - n * mean * mean) / (n - 1) : 0
                if (var < 0) var = 0
                printf "%.4f\t| %s | %d/%d | %.2f | %.2f | %d | %d |\n", mean, bucket,
                    present[bucket] + 0, n, mean, sqrt(var), min[bucket], max[bucket]
            }
        }' $BUCKET_STATS | LC_ALL=C sort -t$'\t' -k1,1nr | cut -f2-
} >> $SUMMARY

# One line summing up the claim: how many buckets are found by every campaign
awk -F, -v n="$NB_CAMPAIGNS" '
    NR == 1 { next }
    { total[$2]; if ($3 > 0) present[$2]++ }
    END {
        for (bucket in total) {
            buckets++
            if (present[bucket] + 0 == n) all++
            else if (present[bucket] + 0 > 0) some++
        }
        printf "\n%d buckets: %d non empty in all the %d campaigns, ", buckets, all + 0, n
        printf "%d in some of them, %d in none.\n", some + 0, buckets - all - some
    }' $BUCKET_STATS >> $SUMMARY

cat $SUMMARY
echo "Summary written to $SUMMARY"

exit $STATUS
