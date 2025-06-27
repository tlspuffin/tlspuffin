#!/bin/bash

# look_for_obj.sh
#
# This script searches for objective directories with files and reports their statistics.
#
# Usage:
#   ./look_for_obj.sh <search_directory>
#
# Arguments:
#   search_directory:  The root directory to search within
#
# The script:
# 1. Recursively finds all directories named "objective" under the provided search directory
# 2. For each objective directory that contains files:
#    - Counts the number of files
#    - Identifies the most recently modified file
#    - Displays the directory path, file count, and last modification date
#
# Example:
#   ./look_for_obj.sh ./experiments/
#   Output: ./experiments/2023-05-10--OpenSSL-8c/objective: 3 file(s), last modified: 2023-05-10 14:32

find $1 -type d -name objective | while IFS= read -r dir; do
  file_count=$(find "$dir" -type f | wc -l)
  if [ "$file_count" -gt 0 ]; then
    latest_file=$(find "$dir" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    latest_date=$(ls -l --time-style=long-iso "$latest_file" | awk '{print $6, $7}')
    echo "$dir: $file_count file(s), last modified: $latest_date"
  fi
done