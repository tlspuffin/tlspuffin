#!/usr/bin/env just --justfile
# ^ A shebang isn't required, but allows a justfile to be executed
#   like a script, with `./justfile test`, for example.

set shell := ["bash", "-c"]
set positional-arguments := true

export NIGHTLY_TOOLCHAIN := "nightly-2023-04-18"
export CARGO_TERM_COLOR := "always"
export RUST_BACKTRACE := "1"

default:
  @just --justfile {{ justfile() }} --list

nightly-toolchain:
  rustup install $NIGHTLY_TOOLCHAIN
  rustup component add rust-src --toolchain $NIGHTLY_TOOLCHAIN

install-clippy:
  rustup component add clippy

# run clippy on all workspace members
check-workspace: install-clippy
  cargo clippy

# run clippy on a vendored crate (e.g. libressl-src)
check-crate NAME FEATURES: install-clippy
  #!/usr/bin/env bash
  cleanup() {
    find {{ justfile_directory() / "crates" }} -name Cargo.lock -exec rm -f '{}' +
  }
  trap cleanup EXIT

  export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"{{ justfile_directory() / "target" }}"}
  cp Cargo.lock crates/{{ NAME }} && cd crates/{{ NAME }} && cargo clippy --features={{ FEATURES }}

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

fmt-rust: install-rustfmt
  export RUSTUP_TOOLCHAIN=$NIGHTLY_TOOLCHAIN && cargo fmt

fmt-rust-check: install-rustfmt
  export RUSTUP_TOOLCHAIN=$NIGHTLY_TOOLCHAIN && cargo fmt -- --check

fmt-clang:
  #!/usr/bin/env bash
  FILES=$(
    find {{ justfile_directory() }} -type f \
    | grep -v "^{{ justfile_directory() / "vendor" }}" \
    | grep -v "^{{ justfile_directory() / "target" }}" \
    | grep -E ".*\.(c|h|C|H|cpp|hpp|cc|hh|c\+\+|h\+\+|cxx|hxx)$"
  )

  printf '%s\n' "${FILES}" | xargs -L1 clang-format --verbose -style=file -i

fmt-clang-check:
  #!/usr/bin/env bash
  FILES=$(
    find {{ justfile_directory() }} -type f \
    | grep -v "^{{ justfile_directory() / "vendor" }}" \
    | grep -v "^{{ justfile_directory() / "target" }}" \
    | grep -E ".*\.(c|h|C|H|cpp|hpp|cc|hh|c\+\+|h\+\+|cxx|hxx)$"
  )

  check() {
    diff -u \
      --label "${1} (original)" \
      --label "${1} (reformatted)" \
      "${1}" <(clang-format -style=file "${1}")
  }

  declare -i result=0
  while IFS='\n' read -r c_file
  do
    check "${c_file}"
    (( result = ($? || result) ))
  done < <(printf '%s\n' "${FILES}")

  exit ${result}

fmt: fmt-rust fmt-clang
fmt-check: fmt-rust-check fmt-clang

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

# RECIPE: `act`
#
# NOTE: additional arguments are passed to the native `act` command
# NOTE: set ACT_EVENT_NAME/ACT_EVENT_FILE to emulate custom trigger events
#
# Examples:
# - list workflow triggered by the command and stops:
#   $ just act --list
#
# - do a dry-run:
#   $ just act -n
#
# - run only the configure job:
#   $ just act -j configure
#
# - emulate a pull_request against the main branch:
#   $ just ACT_EVENT_NAME=pull_request ACT_EVENT_FILE=${PWD}/.github/act/events/pr_to_main.json act

ACT_EVENT_NAME := "push"
ACT_EVENT_FILE := (justfile_directory() / ".github" / "act" / "events" / "push-main.json")

# !!! You need docker to run this recipe. !!! run github actions locally
act *ARGS="--":
  act "{{ ACT_EVENT_NAME }}" -e "{{ ACT_EVENT_FILE }}" \
    --log-prefix-job-id \
    -P 'ubuntu-20.04=ghcr.io/catthehacker/ubuntu:rust-20.04'   \
    -P 'ubuntu-22.04=ghcr.io/catthehacker/ubuntu:rust-22.04'   \
    -P 'ubuntu-latest=ghcr.io/catthehacker/ubuntu:rust-latest' \
    "$@"

# RECIPE: `lint`

LINT_ENVFILE := justfile_directory() / ".github" / "linters" / "super-linter.env"

# !!! You need docker to run this recipe. !!! run super-linter locally
lint:
  @-docker run --rm \
    -e RUN_LOCAL=true \
    -e CREATE_LOG_FILE=true \
    --env-file "{{ LINT_ENVFILE }}" \
    -v "{{ justfile_directory() }}:/tmp/lint" \
    ghcr.io/super-linter/super-linter:latest

  @RESULT=$?
  @printf '\nFull log file at %s\n' "{{ justfile_directory() }}/super-linter.log"
  @exit ${RESULT}
