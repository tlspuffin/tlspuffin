#!/bin/bash

tlspuffin="$(dirname "$0")/../.."

# bench="mutations"
bench="seeds/seed_session_resumption_dhe"
#bench="seeds/seed_client_attacker"

perf record --call-graph dwarf -- cargo bench --bench benchmark -- --profile-time 1 $bench
perf script | "$tlspuffin/tools/profile/stackcollapse-perf.pl" \
            | "$tlspuffin/tools/profile/rust-unmangle" \
            | "$tlspuffin/tools/profile/flamegraph.pl" > flame.svg

xdg-open flame.svg
