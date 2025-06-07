#!/bin/bash

###############################################################################
# Script Name: check_experiments.sh
#
# Description:
#   This script checks all subfolders under ./experiments/ (e.g., exp1, exp2).
#   For each experiment folder, if the `stats.json` file has been modified
#   within the last 5 minutes, it displays:
#     - The path to the experiment folder
#     - The time elapsed since the last update of `stats.json`
#     - The number of files in the `corpus/` subfolder and the timestamp
#       of the most recently modified file
#     - The number of files in the `objective/` subfolder and the timestamp
#       of the most recently modified file
#
# Usage:
#   ./check_experiments.sh
#
# Notes:
#   - Requires `find`, `stat`, `sort`, `cut`, and `wc` (standard Unix tools).
#   - Assumes each experiment is located at ./experiments/expX/
#   - You can modify the 5-minute window by changing the TIME_WINDOW variable.
###############################################################################

# Show usage information
show_help() {
    echo "Usage: $0"
    echo
    echo "Check experiments under ./experiments/ for recent updates to stats.json."
    echo "Displays information if stats.json was modified within the last 5 minutes."
    echo
    echo "No arguments needed."
}

# Show help if requested
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Time window in seconds (5 minutes)
TIME_WINDOW=300

# Current time in epoch seconds
now=$(date +%s)

echo -e "# All running tlspuffin main jobs:"
ps x | grep "l+" | grep tlspuffin

# Loop through all experiment folders
for exp in ./experiments/*; do
    stats_file="$exp/log/stats.json"

    if [ -f "$stats_file" ]; then
        # Last modified time in epoch seconds
        mod_time=$(stat -c %Y "$stats_file")
        elapsed=$((now - mod_time))

        # Check if modified in the last 5 minutes (TIME_WINDOW seconds)
        if [ "$elapsed" -le ${TIME_WINDOW} ]; then
            echo "# Experiment: $exp"
            echo "  Time since last stats.json update: ${elapsed}s"

            # Default PUT info from log
            log_file="$exp/log/stats_puffin_main_broker.log"
            if [ -f "$log_file" ]; then
                default_put=$(head -n 100 "$log_file" | grep "Default PUT:" | head -n1 | sed 's/^[ \t]*//' | cut -d' ' -f2-)
                if [ -n "$default_put" ]; then
                    echo "  $default_put"
                else
                    echo "  Default PUT: Not found in log"
                fi
            else
                echo "  Log file not found: $log_file"
            fi

            # Corpus info
            corpus_dir="$exp/corpus"
            if [ -d "$corpus_dir" ]; then
                corpus_count=$(find "$corpus_dir" -type f -name "*.trace" | wc -l)
                last_corpus=$(find "$corpus_dir" -type f -name "*.trace" -printf "%T@ %Tc\n" | sort -nr | head -n1 | cut -d' ' -f2-)
                last_corpus_time=$(find "$corpus_dir" -type f -name "*.trace" -printf "%T@\n" | sort -nr | head -n1 | cut -d. -f1)
                now=$(date +%s)
                last_corpus_elapsed=$(( (now - last_corpus_time) / 60 ))
                echo "  Corpus: $corpus_count file(s), last modified: $last_corpus_elapsed minutes ago - $last_corpus"
            else
                echo "  Corpus: Directory not found"
            fi

            # Objective info
            objective_dir="$exp/objective"
            if [ -d "$objective_dir" ]; then
                objective_count=$(find "$objective_dir" -type f -name "*.trace" | wc -l)
                last_objective=$(find "$objective_dir" -type f -name "*.trace" -printf "%T@ %Tc %p\n" | sort -nr | head -n1 | cut -d' ' -f2-)
                last_objective_time=$(find "$objective_dir" -type f -name "*.trace" -printf "%T@\n" | sort -nr | head -n1 | cut -d. -f1)
                now=$(date +%s)
                last_objective_elapsed=$(( (now - last_objective_time) / 60 ))
                 # Display the following if obejctive_count is greater than 0
                if [ "$objective_count" -gt 0 ]; then
                  echo "  ==> Objective: $objective_count file(s), last modified: $last_objective_elapsed minutes ago - $last_objective"
                else
                  echo "  (no objective yet)"
                fi
            else
                echo "  Objective: Directory not found"
            fi

            echo ""
        fi
    fi
done
