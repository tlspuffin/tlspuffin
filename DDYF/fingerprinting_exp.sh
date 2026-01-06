#!/bin/bash
export LIBAFL_EDGES_MAP_SIZE=262144

echo 'Cleaning previous data'
cargo clean
rm -rf objectives seeds corpus


echo 'Building fuzzer'
./tools/mk_vendor make wolfssl:wolfssl500-asan
./tools/mk_vendor make wolfssl:wolfssl510-asan
./tools/mk_vendor make wolfssl:wolfssl511-asan
cargo build --release --bin tlspuffin --features cputs,asan

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential

C1='RUST_LOG=info timeout 48h ./target/release/tlspuffin -p 2000 --cores 0-3 differential-experiment wolfssl500-asan wolfssl510-asan --title "500vs510"'
C2='RUST_LOG=info timeout 48h ./target/release/tlspuffin -p 2001 --cores 4-7 differential-experiment wolfssl510-asan wolfssl511-asan --title "510vs511"'
C3='RUST_LOG=info timeout 48h ./target/release/tlspuffin -p 2002 --cores 8-11 differential-experiment wolfssl500-asan wolfssl511-asan --title "500vs511"'

# Run the campaigns
tmux new-session "$C1; exec zsh" \; split-window -h -l 66% "$C2; exec zsh" \; split-window -h -l 50% "$C3; exec zsh"

# zellij --layout ./DDYF/fingerprint_layout.kdl
