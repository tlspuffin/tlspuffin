# Quick start [Outdated, please refer to the [official documentation](https://tlspuffin.github.io/docs/overview)]
We recommend you follow the up-to-date [Quickstart Guide](https://tlspuffin.github.io/docs/guides/quickstart) to get started quickly.

## Dependencies

We manage dependencies through [Nix](https://nixos.org/), see [shell.nix](./shell.nix). If you are new to Nix, we recommend using the [Zero to Nix install guide](https://zero-to-nix.com/start/install).

If you want to install the dependencies manually, you need the following:
* build-essential (make, gcc)
* clang
* graphviz

WolfSSL:
* autoconf
* libtool

BoringSSL:
* go
* cmake

For the python `tlspuffin-analyzer`:
* libyajl-dev
* `wheel` from Python pip

## Building
All the commands below must be entered in a nix-shell, obtained by first running `nix-shell` at top-level.

Build the project:

```bash
git clone https://github.com/tlspuffin/tlspuffin.git
cargo build
```

## Running

Fuzz OpenSSL v1.1.1j using three clients:

```bash
cargo run --bin tlspuffin --features=openssl111j -- --cores 0-3
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
  > This sub-command serializes the default seed corpus in a directory named seeds/ in the current working directory. The default corpus is defined in the source code using the trace dsl.


## Rust Setup

Install [rustup](https://rustup.rs/).

The toolchain will be automatically downloaded when building this project. See [./rust-toolchain.toml](./rust-toolchain.toml) for more details about the toolchain.

Make sure that you have the [clang](https://clang.llvm.org/) compiler installed. Optionally, also install `llvm` to have additional tools like `sancov` available.
Also make sure that you have the usual tools for building it like `make`, `gcc` etc. installed. They may be needed to build OpenSSL.

## Advanced Features

### Running with ASAN

```bash
    cargo run --bin tlspuffin --features --features=openssl111j,asan -- --cores 0-3
```

It is important to enable `abort_on_error`,
else the fuzzer workers fail to restart on crashes.

#### Compiling with ASAN using rustc

```
cargo build -p tlspuffin --release --features --features=openssl111j,asan
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
cargo run --bin tlspuffin --features=openssl111j -- execute test.trace
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
~~~~