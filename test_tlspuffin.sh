#!/usr/bin/env bash

declare -a puts=( openssl111 openssl111j openssl111u openssl101f openssl102u libressl wolfssl430 wolfssl510 wolfssl520 wolfssl530 wolfssl540 )

for put in "${puts[@]}"
do
    printf 'starting test for put %s. see full log at: %s\n' "${put}" "tlspuffin_${put}.log"
    cargo clean
    LIBAFL_EDGES_MAP_SIZE=$(( 65536 * 2 )) cargo test -p tlspuffin --features="${put}" &> "tlspuffin_${put}.log"
done

cargo clean
cargo test -p sshpuffin &> sshpuffin.log

