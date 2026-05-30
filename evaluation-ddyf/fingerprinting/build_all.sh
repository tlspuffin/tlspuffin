#!/usr/bin/env bash

# build_all.sh
# Build all wolfssl versions and record success in a table.

set -euo pipefail

VERSIONS=(
    "5.0.0" "5.1.0" "5.1.1" "5.2.0" "5.2.1" "5.3.0" "5.4.0" "5.5.0"
    "5.5.1" "5.5.2" "5.5.3" "5.5.4" "5.6.0" "5.6.2" "5.6.3" "5.6.4"
    "5.6.6" "5.7.0" "5.7.2" "5.7.4" "5.7.6" "5.8.0" "5.8.2" "5.8.4"
    "5.9.0" "5.9.1"
)

cd "$(dirname "$0")/../.." || exit 1
RESULTS_FILE="evaluation-ddyf/fingerprinting/build_results.md"
echo "| Version | PUT build | Harness build | Included? |" > "$RESULTS_FILE"
echo "|---|---|---|---|" >> "$RESULTS_FILE"

# Clean before starting
cargo clean

for VERSION in "${VERSIONS[@]}"; do
    NAME_VER="${VERSION//./}"
    PRESET="wolfssl${NAME_VER}"

    PUT_OK="NO"
    if ./tools/mk_vendor make "wolfssl:${PRESET}"; then
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
    exit 1
fi

cat "$RESULTS_FILE"
