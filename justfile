#!/usr/bin/env just --justfile
# ^ A shebang isn't required, but allows a justfile to be executed
#   like a script, with `./justfile test`, for example.

set shell := ["bash", "-c"]
set positional-arguments := true

export DEFAULT_TOOLCHAIN := env("RUSTUP_TOOLCHAIN", "1.68.2")
export NIGHTLY_TOOLCHAIN := "nightly-2023-04-18"
export RUSTUP_TOOLCHAIN := DEFAULT_TOOLCHAIN
export CARGO_TERM_COLOR := "always"
export RUST_BACKTRACE := "1"
export CC := "clang"
export CXX := "clang++"

default:
  @just --justfile {{ justfile() }} --list

install-rust-toolchain TOOLCHAIN=DEFAULT_TOOLCHAIN:
  #!/usr/bin/env bash
  exec 1>&2

  # install toolchain
  rustup install --no-self-update '{{ TOOLCHAIN }}'

  # install toolchain components
  rustup component add --toolchain '{{ TOOLCHAIN }}' \
    cargo        \
    clippy       \
    rust-docs    \
    rust-std     \
    rustc        \
    rustfmt      \
    rust-src

# install additional rust dependencies
install-rust-dependencies TOOLCHAIN=DEFAULT_TOOLCHAIN:
  #!/usr/bin/env bash
  exec 1>&2
  RUSTUP_TOOLCHAIN='{{ TOOLCHAIN }}' cargo install toml-cli --locked --version "0.2.3" # mk_vendor
  RUSTUP_TOOLCHAIN='{{ TOOLCHAIN }}' cargo install mdbook --locked --version "0.4.35"  # docs

install-rust-toolchain-default: (install-rust-toolchain DEFAULT_TOOLCHAIN)
install-rust-toolchain-nightly: (install-rust-toolchain NIGHTLY_TOOLCHAIN)

# run clippy on all workspace members
check-workspace: install-rust-toolchain
  cargo clippy

# run clippy on a vendored crate (e.g. libressl-src)
check-crate NAME FEATURES: install-rust-toolchain
  #!/usr/bin/env bash
  cleanup() {
    find {{ justfile_directory() / "crates" }} -name Cargo.lock -exec rm -f '{}' +
  }
  trap cleanup EXIT

  export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"{{ justfile_directory() / "target" }}"}
  cp Cargo.lock crates/{{ NAME }} && cd crates/{{ NAME }} && cargo clippy --features={{ FEATURES }}

check PROJECT ARCH FEATURES CARGO_FLAGS="": install-rust-toolchain
  cargo clippy --no-deps -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}" {{CARGO_FLAGS}}

fix PROJECT ARCH FEATURES CARGO_FLAGS="": install-rust-toolchain
  cargo clippy --no-deps -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}" {{CARGO_FLAGS}} --fix

test PROJECT ARCH FEATURES CARGO_FLAGS="": install-rust-toolchain
  cargo test -p {{PROJECT}} --target {{ARCH}} --features "{{FEATURES}}" {{CARGO_FLAGS}}

build PROJECT ARCH FEATURES="" FLAGS="": install-rust-toolchain
  cargo build -p {{PROJECT}} --target {{ARCH}} --profile=release --features "{{FEATURES}}" {{FLAGS}}

# run an arbitrary command in the justfile environment
[no-exit-message]
run COMMAND *ARGS:
  "{{COMMAND}}" {{ARGS}}

# build a vendor library (examples: `just mk_vendor openssl openssl111k`)
[no-exit-message]
mk_vendor VENDOR PRESET NAME="" OPTIONS="" EXTRA_FLAGS="": install-rust-toolchain
  #!/usr/bin/env bash
  args=( make "{{VENDOR}}:{{PRESET}}" )

  [[ -n "{{OPTIONS}}" ]] && args+=( --options="{{OPTIONS}}" )
  [[ -n "{{NAME}}" ]] && args+=( --name="{{NAME}}" )

  {{ justfile_directory() / "tools" / "mk_vendor" }} "${args[@]}" {{EXTRA_FLAGS}}

benchmark: install-rust-toolchain
  cargo bench -p tlspuffin --target x86_64-unknown-linux-gnu --features "openssl111k"

fmt-rust: (install-rust-toolchain NIGHTLY_TOOLCHAIN)
  RUSTUP_TOOLCHAIN='{{ NIGHTLY_TOOLCHAIN }}' cargo fmt

fmt-rust-check: (install-rust-toolchain NIGHTLY_TOOLCHAIN)
  RUSTUP_TOOLCHAIN='{{ NIGHTLY_TOOLCHAIN }}' cargo fmt -- --check

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

book-serve: install-rust-toolchain
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
