

# https://github.com/rust-fuzz/libfuzzer

# We also need asan in linker: https://stackoverflow.com/questions/42482494/undefined-reference-to-asan-init-v4-when-compiling
cargo +nightly rustc --bin tlspuffin -- -C passes='sancov' -C llvm-args='-sanitizer-coverage-level=3' -C llvm-args='-sanitizer-coverage-inline-8bit-counters' -Z sanitizer=address

WORK_DIR=$(mktemp -d)
ASAN_OPTIONS="coverage=1:coverage_dir=$WORK_DIR" target/debug/tlspuffin
sancov -symbolize "$WORK_DIR"/*.sancov target/debug/tlspuffin > "$WORK_DIR"/symbolized.json
python tools/coverage-report-server.py --symcov "$WORK_DIR"/symbolized.json --srcpath dummy

