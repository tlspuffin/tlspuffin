#!/bin/bash

WORK_DIR="./target-nightly"
TARGET_DIR="$WORK_DIR"

# This only work with the Rust nightly address sanitizer.
# For some reason the asan runtime we link in openssl-src is not enough!

# We also need asan in linker: https://stackoverflow.com/questions/42482494/undefined-reference-to-asan-init-v4-when-compiling
# We enabled asan in openssl and also link libasan by default.
# Disable features such that __sanitizer_cov_trace_pc_guard* is not implemented. It gets implemented by the address
# sanitizer.
# Adapted from https://github.com/rust-fuzz/libfuzzer
cargo +nightly rustc --example seed_successful \
    --target-dir "$TARGET_DIR" \
    --no-default-features \
    -- \
    -Z sanitizer=address

# Or define this variable:
#export RUSTFLAGS="-Z sanitizer=address"

export ASAN_OPTIONS="coverage=1:coverage_dir=$WORK_DIR"

BIN="$TARGET_DIR/x86_64-unknown-linux-gnu/debug/examples/seed_successful"


rm "$WORK_DIR/"*.sancov

$BIN

# Print stats
sancov --print-coverage-stats "$WORK_DIR/"*.sancov "$BIN"

# Serve HTML
sancov -symbolize "$WORK_DIR/"*.sancov "$BIN" > "$WORK_DIR/symbolized.symcov"

SERVER="$(pwd)/tools/coverage-report-server.py"
python "$SERVER" --symcov "$WORK_DIR/symbolized.symcov" --srcpath dummy
