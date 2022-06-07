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

check PROJECT ARCH FEATURES: install-clippy
  cargo clippy --no-deps -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}"

fix PROJECT ARCH FEATURES: install-clippy
  cargo clippy --no-deps -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}" --fix

test PROJECT ARCH FEATURES:
  cargo test -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}"

build PROJECT ARCH FEATURES:
  cargo build -p {{PROJECT}} --target {{ARCH}} --release --features "{{FEATURES}}"

benchmark:
  cargo bench -p tlspuffin --features "openssl111"

install-rustfmt: nightly-toolchain
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
