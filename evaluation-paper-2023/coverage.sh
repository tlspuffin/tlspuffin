#!/bin/bash



source ~/venv/bin/activate
source "$HOME/.cargo/env"

base="/local-unsafe/mammann/tasks/taskbc-tlspuffin-redo"
mkdir "$base"

generate_coverage () {
    features=""
    excludes=()
    seeds=$5

    if [ "$2" = "wolfssl" ]; then
        features="wolfssl530"
        excludes=(-e ".*openssl.*" -e ".*examples.*" -e ".*test.*")
    elif [ "$2" = "openssl" ]; then
        features="openssl111j"
        excludes=(-e ".*wolf.*" -e ".*test.*" -e ".*apps.*" -e ".*include.*" -e ".*engine.*" -e ".*fuzz.*")
    else
        echo "Wrong argument"
        exit 1
    fi

    corpus=$1

    name=$3

    batch=$4

    cov_file="$base/coverage-$features-$name.csv"
    cob_file="$base/coverage-$features-$name.cobertura"
    json_file="$base/coverage-$features-$name.json"
    html_dir="$base/coverage-$features-$name"
    build_dir="$base/tmp/build-$features-$name"
    mkdir -p "$build_dir"
    mkdir -p $html_dir

    src_dir=$(pwd)
    
    echo "time,b_abs,b_per,b_total,fn_abs,fn_per,fn_total,l_abs,l_per,l_total" >> $cov_file

    rm -rf "$build_dir"
    cp -r . "$build_dir"

    cd "$build_dir"

    #cargo clean
    find -name "*.gcda" -delete
    cargo build -p tlspuffin --target x86_64-unknown-linux-gnu --features "$features,gcov_analysis" --no-default-features

    $build_dir/target/x86_64-unknown-linux-gnu/debug/tlspuffin execute --index 0 -n 100 "$seeds"
    cov_data=$(gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --json-summary-pretty)
    echo "$cov_data" | jq "[\"\",.branch_covered,.branch_percent,.branch_total,.function_covered,.function_percent,.function_total,.line_covered,.line_percent,.line_total] | @csv" -r >> $cov_file

    count=0
    while true; do
        echo "Executing testcases"
        time=$($build_dir/target/x86_64-unknown-linux-gnu/debug/tlspuffin execute --index "$count" -n "$batch" "$corpus")
        
        exit_status=$?

        if [ $exit_status -ne 0 ] && [ $exit_status -ne 1 ]; then
            echo "Unexpected exit code. Do you have crashing inputs in the corpus?"
        fi

        echo "Getting coverage"
        cov_data=$(gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --json-summary-pretty)
        echo "$cov_data" | jq "[$time,.branch_covered,.branch_percent,.branch_total,.function_covered,.function_percent,.function_total,.line_covered,.line_percent,.line_total] | @csv" -r >> $cov_file

        count=$(expr $count + $batch)
        if [ $exit_status -eq 1 ]; then
            break
        fi
    done


    gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --html-details --html-self-contained -o "$html_dir/index.html"
    sleep 1
    gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --cobertura "$cob_file"
    sleep 1
    gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --json "$json_file"

    cd "$src_dir"
}

cargo clean

# find "$(pwd -P)" -type d -name "corpus" -exec echo "generate_coverage \"{}\" \"\" \"\"" \;

#taskc
generate_coverage "/local-unsafe/mammann/tasks/taskc-tlspuffin/openssl/experiments/2023-05-11-162035-openssl-0/corpus" "openssl" "taskc" 100 "/local-unsafe/mammann/tasks/taskc-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskc-tlspuffin/wolfssl/experiments/2023-05-11-161921-wolfssl-0/corpus" "wolfssl" "taskc" 100 "/local-unsafe/mammann/tasks/taskc-tlspuffin/wolfssl/seeds" &


# taskb
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-8-coverage-wolfssl-0/corpus" "wolfssl" "taskb-8" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-4-coverage-wolfssl-0/corpus" "wolfssl" "taskb-4" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-2-coverage-wolfssl-0/corpus" "wolfssl" "taskb-2" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-1-coverage-wolfssl-0/corpus" "wolfssl" "taskb-1" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-6-coverage-wolfssl-0/corpus" "wolfssl" "taskb-6" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-3-coverage-wolfssl-0/corpus" "wolfssl" "taskb-3" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-5-coverage-wolfssl-0/corpus" "wolfssl" "taskb-5" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-9-coverage-wolfssl-0/corpus" "wolfssl" "taskb-9" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-7-coverage-wolfssl-0/corpus" "wolfssl" "taskb-7" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/experiments/2023-05-15-154835-10-coverage-wolfssl-0/corpus" "wolfssl" "taskb-10" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/wolfssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-10-coverage-openssl-0/corpus" "openssl" "taskb-10" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-8-coverage-openssl-0/corpus" "openssl" "taskb-8" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-3-coverage-openssl-0/corpus" "openssl" "taskb-3" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-6-coverage-openssl-0/corpus" "openssl" "taskb-6" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-4-coverage-openssl-0/corpus" "openssl" "taskb-4" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-5-coverage-openssl-0/corpus" "openssl" "taskb-5" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-9-coverage-openssl-0/corpus" "openssl" "taskb-9" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-7-coverage-openssl-0/corpus" "openssl" "taskb-7" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-1-coverage-openssl-0/corpus" "openssl" "taskb-1" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &
generate_coverage "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/experiments/2023-05-15-154830-2-coverage-openssl-0/corpus" "openssl" "taskb-2" 5 "/local-unsafe/mammann/tasks/taskb-tlspuffin/openssl/seeds" &

wait
