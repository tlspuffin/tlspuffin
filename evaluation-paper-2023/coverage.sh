#!/bin/bash

### BEGIN USER CONFIG
task_root="$(pwd)/evaluation-paper-2023/TASKS" # where the tasks with seeds and corpus can be found

function main() {
## Instructions:
# generate_coverage <taskFolder> <PUT> <name> <batch>
    # - taskFolder: folder task in $task_root
    # - PUT: wolfssl or openssl
    # - name: just a name of the test
    # - batch: number of runs in parallel

    generate_coverage "taskBUF" "wolfssl" "test" 100 &
    generate_coverage "taskBUF_min" "wolfssl" "test" 100 &
    generate_coverage "taskBUF_min2" "wolfssl" "test" 100 &
    generate_coverage "taskBase" "wolfssl" "test" 100 &
    generate_coverage "taskFuzz" "wolfssl" "test" 100 &
    generate_coverage "taskBase2" "openssl" "test" 100 &
    generate_coverage "taskBase2" "wolfssl" "test" 100 &
    generate_coverage "taskSDOS1" "openssl" "test" 100 &
    generate_coverage "taskSDOS1" "wolfssl" "test" 100 &
    generate_coverage "taskBase_O" "openssl" "test" 100
}
### END USER CONFIG


# Main LOG file
LOG="$task_root/LOG.html"

# checks if branch has something pending
function parse_git_dirty() {
  git diff --quiet --ignore-submodules HEAD 2>/dev/null; [ $? -eq 1 ] && echo "*"
}

# gets the current git branch
function parse_git_branch() {
  git branch --no-color 2> /dev/null | sed -e '/^[^*]/d' -e "s/* \(.*\)/\1$(parse_git_dirty)/"
}

# get last commit hash prepended with @ (i.e. @8a323d0)
function parse_git_hash() {
  git rev-parse --short HEAD 2> /dev/null | sed "s/\(.*\)/@\1/"
}

# LOG
echo -e "Current TLSPUFFIN STATUS: "
GIT_BRANCH=$(parse_git_branch)$(parse_git_hash)
echo ${GIT_BRANCH}

generate_coverage () {
    echo -e  "-----------> RUN TASK $1 WITH PUT $2, EXPERIMENT $3 WITH BATCH $4 -------------"
    echo -e  "==============================================================================="
    task=$1
    PUT=$2
    name="$task_$3"
    batch=$4

    features=""
    excludes=()

    if [ "$PUT" = "wolfssl" ]; then
        features="wolfssl530"
        excludes=(-e ".*openssl.*" -e ".*examples.*" -e ".*test.*")
    elif [ "$PUT" = "openssl" ]; then
        features="openssl111"
        # excludes=(-e ".*crypto.*" -e ".*wolf.*" -e ".*test.*" -e ".*apps.*" -e ".*include.*" -e ".*engine.*" -e ".*fuzz.*")
        excludes=(-e ".*wolf.*" -e ".*test.*" -e ".*apps.*" -e ".*include.*" -e ".*engine.*" -e ".*fuzz.*")
    else
        echo -e  "Wrong argument"
        exit 1
    fi

    data="$task_root/$task/data"
    corpus="$data/corpus"
    seeds="$data/seeds"


    cov_file="$task_root/$task/coverage-$features-$name.csv"
    cob_file="$task_root/$task/coverage-$features-$name.cobertura"
    json_file="$task_root/$task/coverage-$features-$name.json"
    html_dir="$task_root/$task/coverage-$features-$name"
    html_dir_browse="evaluation-paper-2023/TASKS/$task/coverage-$features-$name"
    build_dir_="$task_root/$task/tmp"
    build_dir="$task_root/$task/tmp/build-$features-$name"
    src_dir=$(pwd)

    mkdir -p $html_dir
    echo -e  "time,b_abs,b_per,b_total,fn_abs,fn_per,fn_total,l_abs,l_per,l_total" >> $cov_file
	


    echo -e  "We need to (re)-build the executable $build_dir/target/x86_64-unknown-linux-gnu/debug/tlspuffin"
    echo -e  "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    cargo clean
    yes | rm -r "$build_dir"
    mkdir -p "$build_dir"
    cp -r . "$build_dir"
    cd "$build_dir"
    cargo clean
    find -name "*.gcda" -delete
    # echo -e  'Running "cargo build -p tlspuffin --target x86_64-unknown-linux-gnu --features "${features},gcov_analysis" --no-default-features" in $build_dir'
    # echo -e  "cargo build -p tlspuffin --target x86_64-unknown-linux-gnu --features '${features},gcov_analysis' --no-default-features"
    echo -e  "Building tlspuffin with features: $features in build_dir: $build_dir"
    cargo build -p tlspuffin --target x86_64-unknown-linux-gnu --features "${features},gcov_analysis" --no-default-features 2> log_eval_error.txt 1> log_eval.txt
    echo "tlspuffin has been built with features $features from the following branch and commit hash:" > README.txt
    echo ${GIT_BRANCH} >> README.txt


    source ~/venv/bin/activate
    # source "$HOME/.cargo/env"


    echo -e  "\n--> Executing testcases in SEEDS $seeds with PUT $2 and TASK $1"
    $build_dir/target/x86_64-unknown-linux-gnu/debug/tlspuffin execute --index 0 -n 100 "$seeds"
    cov_data=$(gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --json-summary-pretty)
    echo -e  "$cov_data" | jq "[\"\",.branch_covered,.branch_percent,.branch_total,.function_covered,.function_percent,.function_total,.line_covered,.line_percent,.line_total] | @csv" -r >> $cov_file

    count=0
    while true; do
        echo -e  "\n --> Executing testcases in CORPUS $corpus with PUT $2 and TASK $1"
        time=$($build_dir/target/x86_64-unknown-linux-gnu/debug/tlspuffin execute --index "$count" -n "$batch" "$corpus")
        
        exit_status=$?

        if [ $exit_status -ne 0 ] && [ $exit_status -ne 1 ]; then
            echo -e  "Unexpected exit code. Do you have crashing inputs in the corpus?"
        fi

        echo -e  "Getting coverage"
        cov_data=$(gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --json-summary-pretty)
        echo -e  "$cov_data" | jq "[$time,.branch_covered,.branch_percent,.branch_total,.function_covered,.function_percent,.function_total,.line_covered,.line_percent,.line_total] | @csv" -r >> $cov_file

        count=$(expr $count + $batch)
        if [ $exit_status -eq 1 ]; then
            break
        fi
    done


    echo -e  "Now computing coverage for TASK $1 WITH PUT $2, EXPERIMENT $3 WITH BATCH $4"
    gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --html-details --html-self-contained -o "$html_dir/index.html"
    sleep 1
    gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --cobertura "$cob_file"
    sleep 1
    gcovr --gcov-executable "llvm-cov gcov" "${excludes[@]}" --json "$json_file"

    
    echo "-----------> RUN TASK $1 WITH PUT $2, EXPERIMENT $3 WITH BATCH $4 -------------" > README.html
    echo "===============================================================================" >> README.html   

    README="$task_root/$task/README.html"
    echo ${GIT_BRANCH} >> $README
    date >> $README
    echo "data contains:" >> $README
    tree ${data} >> $README

    echo "-----------> RUN TASK $1 WITH PUT $2, EXPERIMENT $3 WITH BATCH $4 -------------" >> $LOG
    tree ${data} >> $LOG

    echo "END of RUN TASK $1 WITH PUT $2, EXPERIMENT $3 WITH BATCH $4\n-->  browse http://localhost:8000/$html_dir_browse\n\n"
    cd "$src_dir"
}

echo -e "\n\n============================================================================" >> $LOG
echo ${GIT_BRANCH} >> $LOG
date >> $LOG

# find "$(pwd -P)" -type d -name "corpus" -exec echo -e  "generate_coverage \"{}\" \"\" \"\"" \;

main

echo -e "\n\n Finished all coverage computations, now renaming file names..."


cd "$task_root"
find -name "*.cobertura" -exec sed --regexp-extended -i 's/target\/x86_64-unknown-linux-gnu\/debug\/build\/openssl-sys-([a-z0-9]*)\/out\/openssl-build\/build\/src\///g' {} \;
find -name "*.cobertura" -exec sed --regexp-extended -i 's/target\/x86_64-unknown-linux-gnu\/debug\/build\/wolfssl-sys-([a-z0-9]*)\/out\///g' {} \;
cd "$src_dir"
echo "DONE"

wait
