#!/bin/bash

WORK_DIR="./target-nightly"
TARGET_DIR="$WORK_DIR"

# We also need asan in linker: https://stackoverflow.com/questions/42482494/undefined-reference-to-asan-init-v4-when-compiling
# Disable features such that __sanitizer_cov_trace_pc_guard* is not implemented.
# Adapted from https://github.com/rust-fuzz/libfuzzer
cargo +nightly rustc --example seed_successful \
    --target-dir "$TARGET_DIR" \
    --no-default-features \
    --features "openssl-fuzzing" \
    -- \
    -Z sanitizer=address

# Or define this variable:
#export RUSTFLAGS="-Z sanitizer=address"

export ASAN_OPTIONS="coverage=1:coverage_dir=$WORK_DIR"
# Run seed_successful as an example
#cargo +nightly run --example seed_successful --no-default-features --target-dir "$TARGET_DIR"

BIN="$TARGET_DIR/debug/examples/seed_successful"
SERVER="$(pwd)/tools/coverage-report-server.py"

rm "$WORK_DIR/"*.sancov

$BIN

# Print stats
sancov --print-coverage-stats "$WORK_DIR/"*.sancov "$BIN"

# Serve HTML
sancov -symbolize "$WORK_DIR/"*.sancov "$BIN" > "$WORK_DIR/symbolized.symcov"
python "$SERVER" --symcov "$WORK_DIR/symbolized.symcov" --srcpath dummy
