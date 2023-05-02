#!/bin/bash

count=0
batch=100

#corpus="/local-unsafe/mammann/2022-tlspuffin-evaluation-paper/evaluation-paper/parallel/experiments/2022-11-16-155256-21-SDOS1-0/corpus"
corpus="/local-unsafe/mammann/2022-tlspuffin-evaluation-paper/evaluation-paper/parallel/experiments/2022-11-16-155256-21-SIG-0/corpus"

features="wolfssl520"
#features="openssl111j"

#excludes=(-e ".*wolf.*" -e ".*test.*" -e ".*apps.*" -e ".*include.*" -e ".*engine.*" -e ".*fuzz.*")
excludes=(-e ".*openssl.*" -e ".*test.*")

gcovr --gcov-executable "llvm-cov gcov" -s -d > /dev/null 2>&1

while true; do
    time=$(cargo run -p tlspuffin --target x86_64-unknown-linux-gnu --features "$features,gcov_analysis" --no-default-features  -- \
        execute --index "$count" -n $batch $corpus/*)
    
    exit_status=$?

    cov_data=$(gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" -j32 -s | grep "[lb][a-z]*:")
 
    l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
    l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
    b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
    b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)
    
    echo "$cov_data"
    echo "$time,$l_per,$l_abs,$b_per,$b_abs" >> coverage.csv

    count=$(expr $count + $batch)
    if [ $exit_status -eq 1 ]; then
        break
    fi
done
