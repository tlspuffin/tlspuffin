#!/bin/bash

folder="objective"

if [ "$#" -eq 1 ]; then
    folder="$1"
fi

export LIBAFL_EDGES_MAP_SIZE=262144

./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580

function clear_and_sort() {
    local obj_folder=$1
    echo "Cleaning buckets from $obj_folder"
    ./DDYF/empty_buckets.sh $obj_folder
    echo "Sorting"
    python -m DDYF.ablation_study_sort $obj_folder
    echo "Listing bucket contents"
    ./DDYF/list_buckets.sh $obj_folder > $2
}


cargo build --release --bin tlspuffin --features cputs
clear_and_sort $folder "ablation-all.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-status
clear_and_sort $folder "ablation-no-status.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-knowledges
clear_and_sort $folder "ablation-no-knowledges.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-decryption
clear_and_sort $folder "ablation-no-decryption.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-claims
clear_and_sort $folder "ablation-no-claims.txt"

