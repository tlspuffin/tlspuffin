#!/usr/bin/env bash

RUST_LOG=info ./target/release/tlspuffin --cores 0-8 differential wolfssl500 wolfssl510
