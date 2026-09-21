#!/usr/bin/env python3
import sys
import re
from pathlib import Path

def compute_gcov_coverage(file_path):
    """
    Parses a .gcov file to compute line coverage statistics.
    """
    path = Path(file_path)
    if not path.is_file():
        print(f"Error: File '{file_path}' does not exist.")
        sys.exit(1)

    executed_lines = 0
    unexecuted_lines = 0

    # Regular expressions to match the gcov prefix formats:
    # 1. Executed lines look like: "    12:   45:  if (x > 0) {"
    # 2. Unexecuted lines look like: "#####:   46:    printf("error");"
    executed_regex = re.compile(r'^\s*([0-9]+):')
    unexecuted_regex = re.compile(r'^\s*#####:')

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Skip gcov branch or call metrics if they exist in the file
            if line.strip().startswith(('branch', 'call')):
                continue

            if executed_regex.match(line):
                executed_lines += 1
            elif unexecuted_regex.match(line):
                unexecuted_lines += 1

    total_executable = executed_lines + unexecuted_lines

    # Calculate percentage safely
    if total_executable > 0:
        coverage_percent = (executed_lines / total_executable) * 100
    else:
        coverage_percent = 0.0

    # Print a structured report
    print(f"========================================")
    print(f" GCOV Coverage Report: {path.name}")
    print(f"========================================")
    print(f"Executed Lines     : {executed_lines}")
    print(f"Unexecuted Lines   : {unexecuted_lines}")
    print(f"Total Executable   : {total_executable}")
    print(f"----------------------------------------")
    print(f"Line Coverage      : {coverage_percent:.2f}%")
    print(f"========================================")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse_gcov.py <path_to_file.gcov>")
        sys.exit(1)

    compute_gcov_coverage(sys.argv[1])
