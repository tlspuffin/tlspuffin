# Results discussed in the paper

We provide raw results in [`./TASKS`](./TASKS) obtained using the methodology and the scripts explained next.
Look for all the files: `index.html` (GCOV results per task), `diff.html` (GCOV diff reports obtained with pycobertura), and `diff-increase.html` (similar GCOV diff reports but obly showing coverage incrases).


# Scripts
 - `coverage.sh`: create coverage reports in folder $task_root, to be executed from the tlspuffin root folder
 - `generate_diff-report.sh`: generate coverage diff reports, which relies on a [fork](https://github.com/LCBH/pycobertura/tree/only_count_increase) of pycobertura, to be executed from the $task_root folder
 - `textual-diff.sh`: generate textual diff summaries


# Methodology
 - create a $task_root folder, for example `./TASKS`
 - in $task_root, create task folders, each task folder must contain a `data` folder, itself containg a `seeds` and `corpus` folders respectively containing seeds and corpus test-cases; e.g., obtained at the end of a fuzzing campaign.
 - add a line in the main function of coverage.sh for each task to compute the coverage for this task
 - execute `./evaluation-paper-2023/coverage.sh`, each task folder will now have HTML gcov reports
 - add a line in the main function of generate_diff-report.sh for each diff-report to be produced
 - clone wolfssl530 and openssl111j projects in $task_root (just type `git clone https://github.com/openssl/openssl --branch OpenSSL_1_1_1j  --single-branch openssl111j` and `git clone https://github.com/wolfSSL/wolfssl --branch v5.3.0-stable  --single-branch`)
 - execute `generate_diff-report.sh` from $task_root, diff-* folders will be created with HTML gcov diff reports