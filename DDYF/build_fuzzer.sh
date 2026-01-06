#!/bin/bash


export LIBAFL_EDGES_MAP_SIZE=262144

./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580
./tools/mk_vendor make wolfssl:wolfssl510
cargo build --release --bin tlspuffin --features cputs
