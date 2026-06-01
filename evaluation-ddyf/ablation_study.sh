#!/bin/bash

folder="objective"

OUTPUT_FILE=ablation.csv

if [ "$#" -eq 1 ]; then
    folder="$1"
fi

PUT1=openssl:openssl340
PUT2=wolfssl:wolfssl580

export LIBAFL_EDGES_MAP_SIZE=262144

./tools/mk_vendor make "$PUT1"
./tools/mk_vendor make "$PUT2"

put1_version=$(echo "$PUT1" | awk -F: '{ print $2}')
put2_version=$(echo "$PUT2" | awk -F: '{ print $2}')

function clear_and_sort() {
    local obj_folder=$1
    echo "Cleaning buckets from $obj_folder"
    ./evaluation-ddyf/empty_buckets.sh $obj_folder
    echo "Sorting"
    python -m evaluation-ddyf.ablation_study_sort "$put1_version" "$put2_version" $obj_folder
    echo "Listing bucket contents"
    local found=$(find "$obj_folder" -maxdepth 1 -type f -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?' | wc -l)
    local lost=$(find "$obj_folder/no_errors" -maxdepth 1 -type f -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?' | wc -l)
    echo "$2,$found,$lost" >> $OUTPUT_FILE
}

echo "Experiment,Found,Lost" > $OUTPUT_FILE

cargo build --release --bin tlspuffin --features cputs
clear_and_sort $folder "ablation-all"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-status,ddyf-disable-decryption,ddyf-disable-knowledges
clear_and_sort $folder "ablation-only-claims"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-knowledges,ddyf-disable-decryption,ddyf-disable-claims
clear_and_sort $folder "ablation-only-status"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-status,ddyf-disable-decryption,ddyf-disable-claims
clear_and_sort $folder "ablation-only-knowledges"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-status
clear_and_sort $folder "ablation-no-status"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-knowledges
clear_and_sort $folder "ablation-no-knowledges"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-decryption
clear_and_sort $folder "ablation-no-decryption"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-claims
clear_and_sort $folder "ablation-no-claims"
