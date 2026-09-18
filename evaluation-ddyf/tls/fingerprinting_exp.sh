#!/bin/bash
export LIBAFL_EDGES_MAP_SIZE=262144

TIMEOUT='48h'
CORES="0-3"
PORT=2000

echo 'Cleaning previous data'
cargo clean
rm -rf objectives seeds corpus experiments


echo 'Building fuzzer'
./tools/mk_vendor make wolfssl:wolfssl500-asan
./tools/mk_vendor make wolfssl:wolfssl510-asan
./tools/mk_vendor make wolfssl:wolfssl520-asan
cargo build --release --bin tlspuffin --features cputs,asan

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential

# Run the campaigns
RUST_LOG=info timeout $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl500-asan wolfssl510-asan --title "500vs510"
RUST_LOG=info timeout $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl510-asan wolfssl520-asan --title "510vs520"
RUST_LOG=info timeout $TIMEOUT ./target/release/tlspuffin -p $PORT --cores $CORES differential-experiment wolfssl500-asan wolfssl520-asan --title "500vs520"

# tmux new-session "$C1; exec zsh" \; split-window -h -l 66% "$C2; exec zsh" \; split-window -h -l 50% "$C3; exec zsh"

# zellij --layout ./DDYF/fingerprint_layout.kdl
