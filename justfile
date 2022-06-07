#!/usr/bin/env just --justfile
# ^ A shebang isn't required, but allows a justfile to be executed
#   like a script, with `./justfile test`, for example.

set shell := ["bash", "-c"]

export CARGO_TERM_COLOR := "always"
export RUST_BACKTRACE := "1"

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
  rustup component add rustfmt

fmt: install-rustfmt
  cargo fmt --all --

fmt-check: install-rustfmt
  cargo fmt --all -- --check

default-toolchain:
  # Setups the toolchain from rust-toolchain.toml
  cargo --version > /dev/null

book-serve:
  mdbook serve docs
