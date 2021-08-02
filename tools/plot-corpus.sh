#!/bin/bash


find "corpus" -name "*.trace" -exec bash -c 'target/x86_64-unknown-linux-gnu/debug/tlspuffin plot --tree $1 svg plots/$(basename $1)' _ {} \;
