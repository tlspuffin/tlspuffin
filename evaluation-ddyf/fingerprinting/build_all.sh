#!/usr/bin/env bash

# build_all.sh
# Build all versions for a given vendor and record success in a table.

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: ./build_all.sh <vendor> <version1> [<version2> ...]"
    exit 1
fi

VENDOR="$1"
shift
VERSIONS=("$@")

cd "$(dirname "$0")/../.." || exit 1
RESULTS_FILE="evaluation-ddyf/fingerprinting/build_results_${VENDOR}.md"
echo "| Version | PUT build | Harness build | Included? |" > "$RESULTS_FILE"
echo "|---|---|---|---|" >> "$RESULTS_FILE"

# Clean before starting
cargo clean

for VERSION in "${VERSIONS[@]}"; do
    NAME_VER="${VERSION//./}"
    PRESET="${VENDOR}${NAME_VER}"

    PUT_OK="NO"
    if ./tools/mk_vendor make "${VENDOR}:${PRESET}"; then
        PUT_OK="YES"
    fi
    # We will log the harness/included later since we build it all at once
    echo "| $VERSION | $PUT_OK | PENDING | PENDING |" >> "$RESULTS_FILE"
done

echo "Building Harness for all compiled PUTs..."
if cargo build --release --bin tlspuffin --features cputs; then
    echo "Harness built successfully."
    # Update results file to YES for all that had PUT_OK=YES
    sed -i 's/YES | PENDING | PENDING/YES | YES | YES/g' "$RESULTS_FILE"
    sed -i 's/NO | PENDING | PENDING/NO | NO | NO/g' "$RESULTS_FILE"
else
    echo "HARNESS COMPILATION FAILED!"
    sed -i 's/YES | PENDING | PENDING/YES | NO | NO/g' "$RESULTS_FILE"
    cat "$RESULTS_FILE"
    exit 1
fi

cat "$RESULTS_FILE"
