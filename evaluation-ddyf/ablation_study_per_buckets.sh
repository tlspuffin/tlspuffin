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
    # go through all the sub-objectives folder
    for d in $obj_folder/*; do
      if [ -d "$d" ];
        then
            echo "Cleaning buckets from $d"
            ./evaluation-ddyf/empty_buckets.sh $d
            echo "Sorting"
            python -m evaluation-ddyf.ablation_study_sort $d
            echo "Listing bucket contents"
            echo "$d: $(./evaluation-ddyf/list_buckets.sh $d)" >> $2
        fi;
    done
}





cargo build --release --bin tlspuffin --features cputs
clear_and_sort $folder "ablation-all.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-status,ddyf-disable-decryption,ddyf-disable-knowledges
clear_and_sort $folder "ablation-only-claims.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-knowledges,ddyf-disable-decryption,ddyf-disable-claims
clear_and_sort $folder "ablation-only-status.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-status,ddyf-disable-decryption,ddyf-disable-claims
clear_and_sort $folder "ablation-only-knowledges.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-status
clear_and_sort $folder "ablation-no-status.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-knowledges
clear_and_sort $folder "ablation-no-knowledges.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-decryption
clear_and_sort $folder "ablation-no-decryption.txt"

cargo build --release --bin tlspuffin --features cputs,ddyf-disable-claims
clear_and_sort $folder "ablation-no-claims.txt"

