#!/usr/bin/env just --justfile
# ^ A shebang isn't required, but allows a justfile to be executed
#   like a script, with `./justfile test`, for example.

set shell := ["bash", "-c"]

export NIGHTLY_TOOLCHAIN := "nightly-2022-04-04-x86_64-unknown-linux-gnu"
export CARGO_TERM_COLOR := "always"
export RUST_BACKTRACE := "1"

nightly-toolchain:
  rustup install $NIGHTLY_TOOLCHAIN
  rustup component add rust-src --toolchain $NIGHTLY_TOOLCHAIN

install-clippy:
  rustup component add clippy

install-nightly-clippy:
  rustup component add clippy --toolchain $NIGHTLY_TOOLCHAIN

check PROJECT ARCH: install-clippy
  cargo clippy --no-deps -p {{PROJECT}} --target {{ARCH}}

test PROJECT ARCH:
  cargo test -p {{PROJECT}} --target {{ARCH}}

benchmark:
  cargo bench -p benchmarks

install-rustfmt:
  rustup component add rustfmt --toolchain $NIGHTLY_TOOLCHAIN

fmt: install-rustfmt
  export RUSTUP_TOOLCHAIN=$NIGHTLY_TOOLCHAIN && cargo fmt

fmt-check: install-rustfmt
  export RUSTUP_TOOLCHAIN=$NIGHTLY_TOOLCHAIN && cargo fmt -- --check

default-toolchain:
  # Setups the toolchain from rust-toolchain.toml
  cargo --version > /dev/null

book-serve:
  mdbook serve docs
