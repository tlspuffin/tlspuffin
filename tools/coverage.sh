

# https://github.com/rust-fuzz/libfuzzer

# We also need asan in linker: https://stackoverflow.com/questions/42482494/undefined-reference-to-asan-init-v4-when-compiling
cargo +nightly rustc --bin tlspuffin -- \
    -Z sanitizer=address

WORK_DIR=$(mktemp -d)
# Run test successful_trace
ASAN_OPTIONS="coverage=1:coverage_dir=$WORK_DIR" cargo test --package tlspuffin --bin tlspuffin tests::tlspuffin::successful_trace -- --exact
sancov -symbolize "$WORK_DIR/"*.sancov target/debug/tlspuffin > "$WORK_DIR"/symbolized.symcov

sancov --print-coverage-stats "$WORK_DIR/"*.sancov target/debug/tlspuffin
python tools/coverage-report-server.py --symcov "$WORK_DIR"/symbolized.symcov --srcpath dummy

