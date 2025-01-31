---
title: 'Overview'
---

:::warning[Ongoing Work]

This page is currently under development. Information presented here might be incomplete or outdated.

:::

## Setup

Configure your environment for developement on the puffin project:

- nix
- editor setup
    - vscode (recommended extensions, change default features, ...)

## The puffin Project

Understand the various components of puffin and how they work together. Here is a description of the main folders found in project's repository:

- `puffin` contains the generic fuzzing code. It deals at a high level with the *terms algebra*, the input *traces* and the fuzzing process (scheduling, logging, mutations, ...)
- `tlspuffin` contains the TLS-specific part of the fuzzer. That is, the specific terms and functions for the TLS terms algebra, based on the `rustls` crate.
- `puffin-build` contains a crate implements the [build process](./build), from creating *vendor libraries* to linking PUTs into a fuzzer.

## Testing my changes

- justfile (fmt, check, check-workspace)
    - rustfmt
    - clang-format
    - cargo clippy
    - cargo bench
- github PRs/github CI
- puffin-bench
