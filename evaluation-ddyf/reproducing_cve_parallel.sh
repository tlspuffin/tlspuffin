#/bin/bash


echo 'Cleaning previous data'
cargo clean
rm -rf objective seeds corpus experiments


echo 'Building fuzzer'
./tools/mk_vendor make wolfssl:wolfssl510
./tools/mk_vendor make openssl:openssl340
cargo build --release --bin tlspuffin --features cputs

echo 'Generate seeds for diff fuzzing'
./target/release/tlspuffin seed --differential


zellij --layout ./evaluation-ddyf/reproducing_cve_layout.kdl
