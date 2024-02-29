<h1 align="center">tlspuffin</h1>
<p align="center">
  <img width=200px alt="Logo with Penguin" src="https://raw.githubusercontent.com/tlspuffin/tlspuffin/main/docs/logo.jpg">
</p>
<div align="center">
  <strong>TLS Protocol Under FuzzINg</strong>
</div>
<div align="center">
  A Dolev-Yao guided fuzzer for TLS
</div>

<div align="center">
  <img src="https://img.shields.io/badge/stability-experimental-orange.svg?style=flat-square" 
      alt="Stability" />
  <a href="https://github.com/tlspuffin/tlspuffin/actions/workflows/rust.yml">    
    <img src="https://github.com/tlspuffin/tlspuffin/actions/workflows/on_main_push.yml/badge.svg"
        alt="Build status" />
  </a>
</div>

<div align="center">
  Developed at LORIA, Inria, France and Trail of Bits, USA
</div>


<div align="center">
  <h3>
    <a href="https://raw.githubusercontent.com/tlspuffin/tlspuffin/main/docs/masterarbeit.pdf">
      Master Thesis
    </a>
    <span> | </span>
    <a href="https://docs.google.com/presentation/d/e/2PACX-1vS-AogsZAAWBAL19kf2b8f5gbOexg9DWmXAQp4Y8zL8K6RDQbTxgKa4b6vNRMq59IezIBVgwMw7KQq6/pub?start=false&loop=false&delayms=3000">
      Thesis Presentation
    </a>
    <span> | </span>
    <a href="https://tlspuffin.github.io/tlspuffin/tlspuffin">
      Documentation
    </a>
  </h3>
</div>

_Disclaimer: The term "symbolic-model-guided" should not be confused with symbolic execution or concolic fuzzing._

## Description

Fuzzing implementations of cryptographic protocols is challenging.
In contrast to traditional fuzzing of file formats, cryptographic protocols require a 
specific flow of cryptographic and mutually dependent messages to reach deep protocol states.
The specification of the TLS protocol describes sound flows of messages and cryptographic 
operations.

Although the specification has been formally verified multiple times with significant 
results, a gap has emerged from the fact that implementations of the same protocol have 
not undergone the same logical analysis.
Because the development of cryptographic protocols is error-prone, multiple security 
vulnerabilities have already been discovered in implementations in TLS which are not 
present in its specification.

Inspired by symbolic protocol verification, we present a reference implementation of a 
fuzzer named tlspuffin which employs a concrete semantic to execute TLS 1.2 and 1.3 symbolic traces. 
In fact attacks which mix \TLS versions are in scope of this implementation.
This method allows us to utilize a genetic fuzzing algorithm to fuzz protocol flows,
which is described by the following three stages.

* By mutating traces we can deviate from the specification to test logical flaws.
* Selection of interesting protocol flows advance the fuzzing procedure.
* A security violation oracle supervises executions for the absence of vulnerabilities.


The novel approach allows rediscovering known vulnerabilities, which are out-of-scope for 
classical bit-level fuzzers. This proves that it is capable of reaching critical protocol 
states.
In contrast to the promising methodology no new vulnerabilities were found by tlspuffin. 
This can can be explained by the fact that the implementation effort of TLS protocol 
primitives and extensions is high and not all features of the specification have been 
implemented.
Nonetheless, the innovating approach is promising in terms of quickly reaching high edge 
coverage, expressiveness of executable protocol traces and stable and extensible implementation.


## Features

* Uses the [LibAFL fuzzing framework](https://github.com/AFLplusplus/LibAFL)
* Fuzzer which is inspired by the [Dolev-Yao symbolic model](https://en.wikipedia.org/wiki/Dolev%E2%80%93Yao_model) used in protocol verification
* Domain specific mutators for Protocol Fuzzing!
* Supported Libraries Under Test: 
  * OpenSSL 1.0.1f, 1.0.2u, 1.1.1k
  * LibreSSL 3.3.3
  * wolfSSL 5.1.0 - 5.4.0
* Reproducible for each LUT. We use Git submodules to link to forks this are in the  [tlspuffin organisation](https://github.com/tlspuffin)
* 70% Test Coverage
* Writtin in Rust!


## Dependencies

* build-essential (make, gcc)
* clang
* graphviz

OpenSSL 1.0:
* makedepend from `xutils-dev package

WolfSSL:
* autoconf
* libtool

For the python `tlspuffin-analyzer`:
* libyajl-dev
* `wheel` from Python pip

## Building

Build the project:

```bash
git clone https://github.com/tlspuffin/tlspuffin.git
git submodule update --init --recursive
cargo build
```

## Running

Fuzz using three clients:

```bash
cargo run --bin tlspuffin -- --cores 0-3
```

Note: After switching the Library Under Test or its version do a clean rebuild (`cargo clean`).
For example when switching from OpenSSL 1.0.1 to 1.1.1.

## Testing

```bash
cargo test
```

## Command-line Interface

The syntax for the command-line of is:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;tlspuffin [⟨options] [⟨sub-commands⟩]

#### Global Options

Before we explain each sub-command, we first go over the options in the following.

* **-c, --cores ⟨spec⟩**
  > This option specifies on which cores the fuzzer should assign its worker processes. It can either be specified as a list by using commas "0,1,2,7" or as a range "0-7". By default, it runs just on core 0.

* **-i, --max-iters ⟨i⟩**
  > This option allows to bound the amount of iterations the fuzzer does. If omitted, then infinite iterations are done.

* **-p, --port ⟨n⟩**
  > As specified in [sec:design-multiprocessing] the initial communication between the fuzzer broker and workers happens over TCP/IP. Therefore, the broker requires a port allocation. The default port is 1337.

* **-s, --seed ⟨n⟩**
  > Defines an initial seed for the prng used for mutations. Note that this does not make the fuzzing deterministic, because of randomness introduced by the multiprocessing (see [sec:design-multiprocessing]).

#### Sub-commands

Now we will go over the sub-commands execute, plot, experiment, and seed.

* **execute ⟨input⟩**
  > This sub-command executes a single trace persisted in a file. The path to the file is provided by the ⟨input⟩ argument.
* **plot ⟨input⟩ ⟨format⟩ ⟨output_prefix⟩**
  > This sub-command plots the trace stored at ⟨input⟩ in the format specified by ⟨format⟩. The created graphics are stored at a path provided by ⟨output_prefix⟩. The option --multiple can be provided to create for each step in the trace a separate file. If the option --tree is given, then only a single graphic which contains all steps is produced.
* **experiment**
  > This sub-command initiates an experiment. Experiments are stored in a directory named experiments/ in the current working directory. An experiment consists of a directory which contains . The title and description of the experiment can be specified with --title ⟨t⟩ and --description ⟨d⟩ respectively. Both strings are persisted in the metadata of the experiment, together with the current commit hash of , the version and the current date and time.
* **seed**
  > This sub-command serializes the default seed corpus in a directory named corpus/ in the current working directory. The default corpus is defined in the source code of using the trace dsl.


## Rust Setup

Install [rustup](https://rustup.rs/).

The toolchain will be automatically downloaded when building this project. See [./rust-toolchain.toml](./rust-toolchain.toml) for more details about the toolchain.

Make sure that you have the [clang](https://clang.llvm.org/) compiler installed. Optionally, also install `llvm` to have additional tools like `sancov` available.
Also make sure that you have the usual tools for building it like `make`, `gcc` etc. installed. They may be needed to build OpenSSL.

## Advanced Features

### Running with ASAN

```bash
ASAN_OPTIONS=abort_on_error=1 \
    cargo run --bin tlspuffin --features asan -- --cores 0-3
```

It is important to enable `abort_on_error`, 
else the fuzzer workers fail to restart on crashes.

#### Compiling with ASAN using rustc

```
RUSTFLAGS=-Zsanitizer=address cargo +nightly build --target x86_64-unknown-linux-gnu --bin tlspuffin -p tlspuffin --release --features wolfssl530
```

### Generate Corpus Seeds

```bash
cargo run --bin tlspuffin -- seed
```

### Plot Symbolic Traces

To plot SVGs do the following:

```bash
cargo run --bin tlspuffin -- plot corpus/seed_client_attacker12.trace svg ./plots/seed_client_attacker12
```

Note: This requires that the `dot` binary is in on your path.
Note: The utility [tools/plot-corpus.sh](tools/plot-crashes.sh) plots a whole directory

### Execute a Symbolic Trace (with ASAN)

To analyze crashes you can also execute a trace which crashes the testing harness using ASAN:

```bash
cargo run --bin tlspuffin -- execute test.trace
```

To do the same with ASAN enabled:
```bash
ASAN_OPTIONS=detect_leaks=0 \
      cargo run --bin tlspuffin --features asan -- execute test.trace
```

### Crash Deduplication

Creates log files for each crash and parses ASAN crashes to group crashes together.

```bash
tools/analyze-crashes.sh
```


### Benchmarking

There is a benchmark which compares the execution of the dynamic functions to directly executing them
in [benchmark.rs](benches/benchmark.rs). You can run them using:

```bash
cargo bench
xdg-open target/criterion/report/index.html
```

## Documentation

This generates the documentation for this crate and opens the browser. This also includes the documentation of every
dependency like LibAFL or rustls.

```bash
cargo doc --open
```

You can also view the up-to-date documentation [here](https://mammann.gitlabpages.inria.fr/tlspuffin/tlspuffin/).

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/blog/license/mit)

at your option.

Note that tlspuffin also contains code/modification from external projects. See [THIRD_PARTY](THIRD_PARTY) for more details.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

