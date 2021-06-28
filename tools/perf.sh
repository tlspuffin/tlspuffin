#!/bin/bash

tlspuffin="$(dirname "$0")/.."

perf record --call-graph dwarf -- cargo bench --bench benchmark -- --profile-time 1 mutations
perf script | tools/stackcollapse-perf.pl | tools/rust-unmangle | tools/flamegraph.pl > flame.svg