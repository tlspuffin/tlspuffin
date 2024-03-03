#!/usr/bin/env just --justfile
# ^ A shebang isn't required, but allows a justfile to be executed
#   like a script, with `./justfile test`, for example.

set shell := ["bash", "-c"]

export NIGHTLY_TOOLCHAIN := "nightly-2023-04-18"
export CARGO_TERM_COLOR := "always"
export RUST_BACKTRACE := "1"

nightly-toolchain:
  rustup install $NIGHTLY_TOOLCHAIN
  rustup component add rust-src --toolchain $NIGHTLY_TOOLCHAIN

install-clippy:
  rustup component add clippy

check PROJECT ARCH FEATURES CARGO_FLAGS="": install-clippy
  cargo clippy --no-deps -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}" {{CARGO_FLAGS}}

fix PROJECT ARCH FEATURES CARGO_FLAGS="": install-clippy
  cargo clippy --no-deps -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}" {{CARGO_FLAGS}} --fix

test PROJECT ARCH FEATURES CARGO_FLAGS="":
  cargo test -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}" {{CARGO_FLAGS}}

build PROJECT ARCH FEATURES CARGO_FLAGS="":
  cargo build -p {{PROJECT}} --target {{ARCH}} --release --features "{{FEATURES}}" {{CARGO_FLAGS}}

benchmark:
  cargo bench -p tlspuffin --target x86_64-unknown-linux-gnu --features "openssl111"

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

clear-gh-caches:
    gh api --paginate -H "Accept: application/vnd.github+json" \
            /repos/tlspuffin/tlspuffin/actions/caches \
            | for ID in `jq '.actions_caches[].id'`; \
              do echo "Deleting $ID"; \
                 gh api --method DELETE /repos/tlspuffin/tlspuffin/actions/caches/$ID | echo; done


ACT_CONFIG_DIR := justfile_directory() / ".github" / "act"
ACT_EVENTS_DIR := ACT_CONFIG_DIR / "events"

EVENT_NAME := "push"
EVENT_FILE := (ACT_EVENTS_DIR / "push-main.json")

set positional-arguments
act *ARGS="--":
  act "{{ EVENT_NAME }}"  \
    -e "{{ EVENT_FILE }}" \
    --log-prefix-job-id   \
    -P 'ubuntu-20.04=ghcr.io/catthehacker/ubuntu:rust-20.04'   \
    -P 'ubuntu-22.04=ghcr.io/catthehacker/ubuntu:rust-22.04'   \
    -P 'ubuntu-latest=ghcr.io/catthehacker/ubuntu:rust-latest' \
    "$@"
