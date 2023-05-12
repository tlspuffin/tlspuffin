#!/bin/bash

count=0
batch=15000

#corpus="/local-unsafe/mammann/2022-tlspuffin-evaluation-paper/evaluation-paper/parallel/experiments/2022-11-16-155256-21-SDOS1-0/corpus"
#corpus="/local-unsafe/mammann/2022-tlspuffin-evaluation-paper/evaluation-paper/parallel/experiments/2022-11-16-155256-21-SIG-0/corpus"
corpus=$2

#features="wolfssl530"
features=$1
#features="openssl111j"

# openssl
#excludes=(-e ".*wolf.*" -e ".*test.*" -e ".*apps.*" -e ".*include.*" -e ".*engine.*" -e ".*fuzz.*")
# wolfssl
excludes=(-e ".*openssl.*" -e ".*examples.*" -e ".*test.*")

source ~/venv/bin/activate
source "$HOME/.cargo/env"

#gcovr --gcov-executable "llvm-cov gcov" -s -d > /dev/null 2>&1
#cargo clean
cargo build -p tlspuffin --target x86_64-unknown-linux-gnu --features "$features,gcov_analysis" --no-default-features

echo "Time,l_per,l_abs,b_per,b_abs" >> "coverage-$features.csv"

while true; do
    echo "Executing testcases"
    time=$(target/x86_64-unknown-linux-gnu/debug/tlspuffin execute --index "$count" -n "$batch" "$corpus" 2>/dev/null)
    
    exit_status=$?

    if [ $exit_status -ne 0 ] && [ $exit_status -ne 1 ]; then
        echo "Unexpected exit code. Do you have crashing inputs in the corpus?"
        break
    fi

    echo "Getting coverage"
    cov_data=$(gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" -s | grep "[lb][a-z]*:")
 
    l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
    l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
    b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
    b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)
    
    echo "$cov_data"
    echo "$time,$l_per,$l_abs,$b_per,$b_abs" >> "coverage-$features.csv"

    count=$(expr $count + $batch)
    if [ $exit_status -eq 1 ]; then
        break
    fi
done
