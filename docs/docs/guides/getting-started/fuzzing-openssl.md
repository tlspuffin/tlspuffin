---
title: 'Fuzzing OpenSSL'
---

## Building the Fuzzer

Now that we have the OpenSSL library to serve as fuzz target, we can create the corresponding fuzzer:
```sh
cargo build --release --bin=tlspuffin --features=openssl312
```

By setting `--features=openssl312`, the build process will automatically select the fuzz target located in `./vendor/openssl312-sancov`.
The build process creates the fuzzer at `./target/release/tlspuffin`.

## Generating Seeds

*tlspuffin* comes with a set of standard seeds for TLS (handshake, session resumption, ...) that can serve as the initial corpus for the fuzzing process, rather than letting the fuzzer rediscover the details of the TLS protocol.

You can generate the seeds compatible with the selected fuzz target in the `./seeds` folder by running:
```sh
./target/release/tlspuffin seed
```

## Running the Fuzzer

Now we are finally ready to launch the fuzzer:
```sh
./target/release/tlspuffin --cores=0-3 --tui quick-experiment
```

This creates a folder `experiments/<id>` containing the results of the fuzzing run.
In particular, the folder `experiments/<id>/corpus` will store the corpus found during the fuzzing session.

:::tip[What are these .trace files in my corpus folder?]

Because *tlspuffin* works at a higher-level of abstraction compared to generic fuzzers, the corpus files are not raw inputs for a binary but rather traces of the protocol session between different agents. More details in the next section!

:::