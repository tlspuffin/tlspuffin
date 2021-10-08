<h1 align="center">tlspuffin</h1>
<p align="center">
  <img alt="Logo with Penguin" src="https://raw.githubusercontent.com/tlspuffin/tlspuffin/main/docs/logo.jpg">
</p>
<div align="center">
  <strong>TLS Protocol Under FuzzINg</strong>
</div>
<div align="center">
  A symbolic-model-guided fuzzer
</div>

<div align="center">
  <img src="https://img.shields.io/badge/stability-experimental-orange.svg?style=flat-square" 
      alt="Stability" />    
  <img src="https://img.shields.io/github/workflow/status/tlspuffin/tlspuffin/Rust?style=flat-square"
      alt="Build status" />

</div>

<div align="center">
  <h3>
    <a href="https://tlspuffin.github.io/tlspuffin/">
      Master Thesis
    </a>
    <span> | </span>
    <a href="https://tlspuffin.github.io/tlspuffin/">
      Thesis Presentation
    </a>
    <span> | </span>
    <a href="https://tlspuffin.github.io/tlspuffin">
      Documentation
    </a>
  </h3>
</div>

## Features
* Supported Libraries Under Test: OpenSSL 1.0.1f, 1.0.2u, 1.1.1k and LibreSSL 3.3.3

## Building

Now, build the project:

```bash
git clone git@gitlab.inria.fr:mammann/tlspuffin.git
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

### Testing

```bash
cargo test
```


## Rust Setup

Install [rustup](https://rustup.rs/).

The toolchain will be automatically downloaded when building this project. See [./rust-toolchain.toml](./rust-toolchain.toml) for more details about the toolchain.

Make sure that you have the [clang](https://clang.llvm.org/) compiler installed. Optionally, also install `llvm` to have additional tools like `sancov` available.
Also make sure that you have the usual tools for building it like `make`, `gcc` etc. installed. They may be needed to build OpenSSL.


## Advanced Usage

### Running with ASAN

```bash
ASAN_OPTIONS=abort_on_error=1 \
    cargo run --bin tlspuffin --features asan -- --cores 0-3
```

It is important to enable `abort_on_error`, 
else the fuzzer workers fail to restart on crashes.

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

