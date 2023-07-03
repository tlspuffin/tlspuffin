# This script assumes gcov reports have been computed in task folders using the ./evaluation-paper-2023/coverage.sh script.
# This scripts relies on the pycobertura-increase program that can be installed from https://github.com/LCBH/pycobertura/tree/only_count_increase
generate_diff () {
    FOLDER=$1
    BASE=$2
    NEW=$3
    SOURCE=$4
    mkdir -p ${FOLDER}
    
    echo "Processing $FOLDER"
    pycobertura-increase diff $BASE $NEW --source1 $SOURCE --source2 $SOURCE --format html --output ${FOLDER}/diff.html
    pycobertura-increase diff --only-increase $BASE $NEW --source1 $SOURCE --source2 $SOURCE --format html --output ${FOLDER}/diff-increase.html
    echo -e "Done with $FOLDER, comparing $BASE with $NEW with respect to `dirname $SOURCE`\n --> browse http://localhost:8000/${FOLDER}/diff.html ou http://localhost:8000/${FOLDER}/diff-increase.html\n"
    echo "Done with $FOLDER, comparing <a href="`dirname ../$BASE`">`dirname ../$BASE`</a> with <a href="`dirname ../$NEW`">`dirname ../$NEW`</a> with respect to $SOURCE\n --> browse http://localhost:8000/${FOLDER}/diff.html ou http://localhost:8000/${FOLDER}/diff-increase.html\n" > ${FOLDER}/README.html
}

generate_diff diff taskBase/coverage-wolfssl530-test.cobertura taskBUF/coverage-wolfssl530-test.cobertura wolfssl &&
generate_diff diff_AFLNWE diff_AFLNWE/results-wolfssl-aflnwe-10/cov.cobertura taskFuzz/coverage-wolfssl530-test.cobertura  wolfssl &&
generate_diff diff_AFLNWE-Anvil diff_AFLNWE-Anvil/results-wolfssl-aflnwe-10/cov.cobertura  /local-unsafe/mammann/tasks/tlsanvil-builds/wolfssl/wolfssl-tlsanvil.cobertura wolfssl &&
generate_diff diff_Anvil /local-unsafe/mammann/tasks/tlsanvil-builds/wolfssl/wolfssl-tlsanvil.cobertura  taskFuzz/coverage-wolfssl530-test.cobertura wolfssl &&
generate_diff diff_BUF taskBase/coverage-wolfssl530-test.cobertura taskBUF/coverage-wolfssl530-test.cobertura wolfssl &&
generate_diff diff-BUF-AFLNWE diff-BUF-AFLNWE/results-wolfssl-aflnwe-10/cov.cobertura taskBUF/coverage-wolfssl530-test.cobertura  wolfssl &&
generate_diff diff-BUF-Anvil /local-unsafe/mammann/tasks/tlsanvil-builds/wolfssl/wolfssl-tlsanvil.cobertura taskBUF/coverage-wolfssl530-test.cobertura  wolfssl &&
generate_diff diff-PUFFIN_AFLNWE diff_AFLNWE/results-wolfssl-aflnwe-10/cov.cobertura diff_AFLNWE/taskbc-tlspuffin-redo/coverage-wolfssl530-taskb-6.cobertura  wolfssl &&
generate_diff diff-SDOS1-AFLNWE diff-SDOS1-AFLNWE/out-openssl-aflnwe/cov.cobertura taskSDOS1/coverage-openssl111-test.cobertura openssl111j &&
generate_diff diff-SDOS1 taskBase_O/coverage-openssl111-test.cobertura taskSDOS1/coverage-openssl111-test.cobertura openssl111j &&
generate_diff diff_BUF-BUF taskBUF_min/coverage-wolfssl530-test.cobertura taskBUF/coverage-wolfssl530-test.cobertura wolfssl &&
generate_diff diff_BUF-BUF2 taskBUF_min2/coverage-wolfssl530-test.cobertura taskBUF/coverage-wolfssl530-test.cobertura wolfssl
