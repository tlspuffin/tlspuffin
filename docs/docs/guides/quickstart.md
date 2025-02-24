---
title: Quickstart
---

This guide will help you quickly create your first fuzzer with *tlspuffin*, including:

- installing the necessary tools
- build a fuzzer for one of the pre-configured fuzz target (OpenSSL)
- run the fuzzer

:::tip[Want More Details?]

This guide is designed to get you started *fast*! The [Getting Started](./getting-started/introduction) guide keeps the same overall structure but provides you with in-depth explanations about each step.

:::


## Before you start

*tlspuffin* relies on [Nix](https://nixos.org/) to setup an environment with all the necessary dependencies and to provide a consistent development experience. This guide will leverage Nix to simplify the install process and **we strongly encourage you to setup Nix** on your machine as a pre-requisite. If you are new to Nix, we recommend using the [Zero to Nix install guide](https://zero-to-nix.com/start/install).

Otherwise, you can manually install the dependencies listed in the repository's [README](https://github.com/tlspuffin/tlspuffin?tab=readme-ov-file#dependencies) file, as well as the dependencies for building the OpenSSL fuzz target used in this guide.

## Install

Download the latest sources of tlspuffin:
```sh
git clone https://github.com/tlspuffin/tlspuffin
cd tlspuffin
```

Setup all the dependencies and tools using the provided nix shell environment:
```sh
nix-shell
```

## Building the Fuzzing Target

*tlspuffin* comes with several preconfigured fuzz targets and a wrapper script `mk_vendor` to simplify the build process:
```sh
./tools/mk_vendor make openssl:openssl312-asan
```

## Building the Fuzzer

Build a fuzzer for the target previously built with `mk_vendor`:
```sh
cargo build --release --bin=tlspuffin --features=cputs
```

## Running the Fuzzer

Create a set of initial seeds for the fuzzer:
```sh
./target/release/tlspuffin seed
```

Launch the fuzzing process:
```sh
./target/release/tlspuffin --cores=0-3 --tui quick-experiment
```
The fuzzer will create a folder `experiments/<id>/` containing the results of the fuzzing run.
Stop the fuzzer by pressing `q` and then `Ctrl+C`.
