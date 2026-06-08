#!/usr/bin/env bash
# build_openssl3x.sh
# Build all 61 OpenSSL 3.x versions (3.0.0→3.6.2) for the adaptive fingerprinting campaign.
# Writes results to evaluation-ddyf/fingerprinting/build_results_openssl3x.md
# Pins the final binary to /tmp/tlspuffin_o3x
#
# USAGE: run from repo root inside nix-shell ./shell.nix with LIBAFL env vars set.
#
# Non-ASan, upstream no-claims, sancov instrumentation only.

set -euo pipefail

export LIBAFL_EDGES_MAP_DEFAULT_SIZE=67108864
export LIBAFL_EDGES_MAP_SIZE=67108864
export LIBAFL_EDGES_MAP_ALLOCATED_SIZE=67108864

VENDOR="openssl"
RESULTS_FILE="evaluation-ddyf/fingerprinting/build_results_openssl3x.md"

# All 61 OpenSSL 3.x versions
VERSIONS=(
    "3.0.0" "3.0.1" "3.0.2" "3.0.3" "3.0.4" "3.0.5" "3.0.6" "3.0.7" "3.0.8" "3.0.9"
    "3.0.10" "3.0.11" "3.0.12" "3.0.13" "3.0.14" "3.0.15" "3.0.16" "3.0.17" "3.0.18" "3.0.19" "3.0.20"
    "3.1.0" "3.1.1" "3.1.2" "3.1.3" "3.1.4" "3.1.5" "3.1.6" "3.1.7" "3.1.8"
    "3.2.0" "3.2.1" "3.2.2" "3.2.3" "3.2.4" "3.2.5" "3.2.6"
    "3.3.0" "3.3.1" "3.3.2" "3.3.3" "3.3.4" "3.3.5" "3.3.6" "3.3.7"
    "3.4.0" "3.4.1" "3.4.2" "3.4.3" "3.4.4" "3.4.5"
    "3.5.0" "3.5.1" "3.5.2" "3.5.3" "3.5.4" "3.5.5" "3.5.6"
    "3.6.0" "3.6.1" "3.6.2"
)

echo "Building ${#VERSIONS[@]} OpenSSL 3.x PUTs..."
echo ""

echo "| Version | Preset name | PUT build |" > "$RESULTS_FILE"
echo "|---|---|---|" >> "$RESULTS_FILE"

BUILT_VERSIONS=()
FAILED_VERSIONS=()

for VERSION in "${VERSIONS[@]}"; do
    NAME_VER="${VERSION//./}"
    PRESET="${VENDOR}${NAME_VER}"

    PUT_OK="NO"
    echo -n "Building ${PRESET}... "
    if ./tools/mk_vendor make "${VENDOR}:${PRESET}" 2>&1 | tail -3; then
        PUT_OK="YES"
        BUILT_VERSIONS+=("$VERSION")
        echo "  -> OK"
    else
        FAILED_VERSIONS+=("$VERSION")
        echo "  -> FAILED"
    fi
    echo "| $VERSION | $PRESET | $PUT_OK |" >> "$RESULTS_FILE"
done

echo ""
echo "PUT builds complete: ${#BUILT_VERSIONS[@]} OK, ${#FAILED_VERSIONS[@]} failed."
if [ ${#FAILED_VERSIONS[@]} -gt 0 ]; then
    echo "Failed: ${FAILED_VERSIONS[*]}"
fi

echo ""
echo "Building combined harness (cargo build --release --features cputs)..."
if cargo build --release --features cputs 2>&1 | tail -5; then
    echo "Harness built successfully."
    # Pin a copy
    cp target/release/tlspuffin /tmp/tlspuffin_o3x
    echo "Pinned binary to /tmp/tlspuffin_o3x"
    # Update results
    echo "" >> "$RESULTS_FILE"
    echo "**Harness build: SUCCESS** — binary pinned to \`/tmp/tlspuffin_o3x\`" >> "$RESULTS_FILE"
else
    echo "HARNESS COMPILATION FAILED!"
    echo "**Harness build: FAILED**" >> "$RESULTS_FILE"
    exit 1
fi

echo ""
echo "Results written to $RESULTS_FILE"
cat "$RESULTS_FILE"
