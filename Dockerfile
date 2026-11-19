# syntax=docker/dockerfile:1

# DDYF / Dpuffin container image.
#
#   docker build -t ddyf .
#   docker run --rm -it -v "${PWD}/experiments:/ddyf/experiments" ddyf
#
# The image ships the repository at /ddyf, a fully realised nix-shell (the
# repository's ./shell.nix, see docker/container-shell.nix) and the pinned Rust
# toolchain, with the PUTs and the fuzzer already built. Every command run in
# the container goes through the nix-shell, so `cargo build --release --bin
# tlspuffin --features cputs` works as-is.

ARG NIX_IMAGE=nixos/nix:2.24.15
FROM ${NIX_IMAGE}

ENV DDYF_ENV_DIR=/opt/ddyf-env \
    RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    PATH=/usr/local/bin:/opt/rust/cargo/bin:${PATH} \
    LIBAFL_EDGES_MAP_SIZE=262144

# Single-user nix in a container: no sandbox. The very long tarball TTL keeps
# the fetchTarball'd nixpkgs valid, so the image never needs the network to
# re-enter the shell.
RUN printf '%s\n' \
        '' \
        'sandbox = false' \
        'filter-syscalls = false' \
        'tarball-ttl = 31536000' \
        'max-jobs = auto' \
    >> /etc/nix/nix.conf

# Instantiate the shell once and realise all of its inputs. Later stages (and
# the container at runtime) enter it through the resulting derivation, which
# skips nixpkgs evaluation entirely.
WORKDIR ${DDYF_ENV_DIR}
COPY shell.nix docker/container-shell.nix ./
RUN nix-instantiate ./container-shell.nix \
        --add-root /nix/var/nix/gcroots/ddyf-shell.drv --indirect \
        > ./shell.drv \
    && nix-shell "$(cat ./shell.drv)" --run true

COPY docker/entrypoint.sh /usr/local/bin/ddyf-shell
RUN chmod +x /usr/local/bin/ddyf-shell

# Install the toolchain pinned by rust-toolchain.toml.
COPY rust-toolchain.toml ./
RUN ddyf-shell rustup show \
    && ddyf-shell sh -c 'rustc --version && cargo --version'

WORKDIR /ddyf
COPY . .
RUN chmod +x ./tools/mk_vendor ./tools/*.sh ./evaluation-ddyf/*.sh

RUN ddyf-shell cargo fetch

ENTRYPOINT ["/usr/local/bin/ddyf-shell"]
