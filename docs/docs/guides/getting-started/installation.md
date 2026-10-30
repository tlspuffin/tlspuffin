---
title: 'Installation'
---

## Before you start

*tlspuffin* relies on [Nix](https://nixos.org/) to set up an environment with all the necessary dependencies and to provide a consistent development experience. This guide will leverage Nix to simplify the installation process and **we strongly encourage you to set up Nix** on your machine as a pre-requisite. If you are new to Nix, we recommend using the [Zero to Nix install guide](https://zero-to-nix.com/start/install).

Otherwise, you can install the dependencies manually. The reference list is the repository's
[`shell.nix`](https://github.com/tlspuffin/tlspuffin/blob/main/shell.nix):

| Dependency | Used for |
|---|---|
| `rustup` | Rust toolchains (the required versions are installed automatically by `just`) |
| `just` | task runner used by the documentation and the CI |
| `clang` / `llvm` 14 (with `libclang`) | compiling the C harnesses and the vendor libraries, `bindgen` |
| `cmake` | building the vendor libraries and the harnesses |
| `autoconf`, `automake`, `libtool` | building wolfSSL |
| `go` | building BoringSSL |
| `openssl` (development files) | `sshpuffin` |
| `graphviz` | plotting traces (`tlspuffin plot`) |
| `yajl` | |
| `python` with `pip` and `virtualenv` | evaluation and analysis scripts |
| `nodejs` 20 | building this documentation website |

Usual base tools (`git`, `make`, a C/C++ toolchain) are also needed. When `libclang` is not found automatically,
set `LIBCLANG_PATH` to the directory that contains it.

## Install

Download the latest sources of tlspuffin:
```sh
git clone https://github.com/tlspuffin/tlspuffin
```

Note that all the subsequent commands in this guide should be run from the root `tlspuffin` folder that was just downloaded through git:
```sh
cd tlspuffin
```

The provided nix shell environment will provide all the dependencies and tools necessary for this guide:
```sh
nix-shell
```
