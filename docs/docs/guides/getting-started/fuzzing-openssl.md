---
title: 'Fuzzing OpenSSL'
---

## Building the Fuzzer

Now that we have the OpenSSL library to serve as a fuzz target, we can create the corresponding fuzzer:
```sh
cargo build --release --bin=tlspuffin --features=cputs
```

By setting `--cputs`, the build process will automatically select all the fuzz targets located in `./vendor/`; a specific fuzz target can then be selected at runtime (see below).
The build process creates the fuzzer at `./target/release/tlspuffin`.

Use different features with ``--features`` for other targets (see  [support matrix](../../references/support-matrix).)

## Generating Seeds

*tlspuffin* comes with a set of standard seeds for TLS (handshake, session resumption, ...) that can serve as the initial corpus for the fuzzing process, rather than letting the fuzzer rediscover the details of the TLS protocol.

You can generate the seeds compatible with the selected fuzz target in the `./seeds` folder by running:
```sh
./target/release/tlspuffin seed
```

## Running the Fuzzer

We are finally ready to launch the fuzzer against a specific fuzz target (in this case `openssl312-asan`):
```sh
./target/release/tlspuffin --put openssl312-asan --cores=0-3 --tui quick-experiment
```

This creates a folder `experiments/<id>` containing the results of the fuzzing run.
In particular, the folder `experiments/<id>/corpus` will store the corpus found during the fuzzing session and the folder `experiments/<id>/objectives` will store the objectives (i.e., attack traces) found during the fuzzing session.

In case the port is already in use, you can specify a different port using the `--port` option.
The option `--cores` allows to specify the cores to use for the fuzzing process, by setting high affinity values to those cores.
Use `./target/release/tlspuffin --help` to get a list of all available options. 

:::tip[What are these .trace files in my corpus folder?]

Because *tlspuffin* works at a higher level of abstraction compared to generic fuzzers, the corpus files are not raw inputs for a binary but rather traces of the protocol session between different agents. More details in the next section!

:::
