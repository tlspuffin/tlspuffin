---
title: 'Overview'
---

## Implementation

From an implementation perspective, several modules exist to make the fuzzer reusable.

### Fuzzing loop
The main fuzzing loop is made of the following modules, each at a different layer (from high-level to low-level):
  1. [`puffin`](https://github.com/tlspuffin/tlspuffin/tree/main/puffin): Core fuzzing engine which is protocol- and target-agnostic. It deals at a high level with the *terms algebra*, the input *traces* and the fuzzing process (scheduling, logging, mutations, ...). This module is built on top of the [`libAFL`](https://github.com/AFLplusplus/LibAFL) crate.
  2. [`tlspuffin`](https://github.com/tlspuffin/tlspuffin/tree/main/tlspuffin): TLS fuzzer which instantiates `puffin` to the TLS protocol and is PUTs-agnostic. It notably instantiates the traces to TLS traces with the TLS-specific terms and functions for the TLS terms algebra, based on the `rustls` crate (e.g., ECDSA signatures, ECDHE encryption, ClientHello, etc.).
  3. [`harness`](https://github.com/tlspuffin/tlspuffin/tree/main/tlspuffin/harness): the layer between the fuzzer and the *PUTs* (the tested libraries, e.g. OpenSSL 3.4.0). A harness is written in C, once per library family (`openssl`, `libressl`, `wolfssl`, `boringssl`), and implements the C interface [`TLS_PUT_INTERFACE`](https://github.com/tlspuffin/tlspuffin/blob/main/tlspuffin/include/puffin/tls.h), see for example the OpenSSL harness [`harness/openssl`](https://github.com/tlspuffin/tlspuffin/tree/main/tlspuffin/harness/openssl). Compiling a harness with a given PUT gives a *target* (e.g. `openssl340` = `harness/openssl` + OpenSSL 3.4.0), which is what the fuzzer actually executes. See the [terminology](../overview.md) for these terms.

Finally, other protocols and PUTs can be fuzzed as well, by extending the fuzzer at layer 2. (new protocols) and 3. (new harnesses). We did a preliminary version of those for SSH and libssh in the module [`sshpuffin` (WIP)](https://github.com/tlspuffin/tlspuffin/tree/main/sshpuffin).

The following diagram shows the dependencies between the modules:
```mermaid
graph TD;
    tlspuffin-- trait ProtocolBehavior -->puffin;
    sshpuffin-- trait ProtocolBehavior -->puffin;

    puffin-->LibAFL;

    tlspuffin-- "C interface TLS_PUT_INTERFACE" -->bundle;
    sshpuffin-- "Rust bindings (libssh-sys)" -->libssh;

    subgraph bundle ["libputs-bundle.a: one target per vendor library in VENDOR_DIR (built by puffin-build)"]
        P1["e.g. openssl340 = harness/openssl + OpenSSL 3.4.0"];
        P2["e.g. wolfssl580 = harness/wolfssl + wolfSSL 5.8.0"];
        P3["..."];
    end
```
The content of the bundle depends on the vendor libraries built with `mk_vendor`; see [build process](./build.md) for how targets are produced and linked into the fuzzer.

The interfaces between the modules are the following:
- **Protocol \<-> `puffin`**: a protocol is defined by implementing the Rust trait
  [`ProtocolBehavior`](https://tlspuffin.github.io/api/puffin/protocol/trait.ProtocolBehavior.html)
  (message types, terms algebra, claims, ...).
- **PUTs \<-> `puffin`**: PUTs are exposed to `puffin` through the Rust traits
  [`Factory<PB: ProtocolBehavior>`](https://tlspuffin.github.io/api/puffin/put_registry/trait.Factory.html),
  which creates agents for a given PUT, and
  [`Put<PB: ProtocolBehavior>`](https://tlspuffin.github.io/api/puffin/put/trait.Put.html),
  which represents a running agent.
- **`tlspuffin` \<-> C harnesses**: `tlspuffin` implements `Factory` and `Put` once,
  with [`CPut`](https://tlspuffin.github.io/api/tlspuffin/put/struct.CPut.html) and
  [`CAgent`](https://tlspuffin.github.io/api/tlspuffin/put/struct.CAgent.html), on top of
  the C interface [`TLS_PUT_INTERFACE`](https://github.com/tlspuffin/tlspuffin/blob/main/tlspuffin/include/puffin/tls.h). Each C harness
  implements this interface for one library family, so adding a new TLS library does not
  require any Rust code.

### Program Under Tests (PUTs)
The fuzzer then requires a *target* (that is a harness linked to some PUT) to fuzz. To build the PUTs (vendor libraries) and link them to the fuzzer, the following tooling is used:
  - [`puffin-build`](https://github.com/tlspuffin/tlspuffin/tree/main/puffin-build) (generates the `mk_vendor` tool): a crate implementing the [build process](./build.md), from creating *PUTs* (*vendor libraries*) to linking PUTs into the fuzzer (through some fuzzing *harness*).

### Benchmarks
To benchmark the fuzzer and perform regression tests, the following tooling is used:
  - [puffin-bench](https://github.com/tlspuffin/puffin-bench): performance testbench for the `puffin` fuzzer (external tooling; not part of the `puffin` crate), see [benchmarks](./benchmarks.md).

## Setup

:::warning[Ongoing Work]

The rest of this page is currently under development. Information presented here might be incomplete or outdated.

:::

Configure your environment for development on the puffin project:

- nix
- editor setup
    - vscode (recommended extensions, change default features, ...)

## Testing my changes

- justfile: use `just fmt` for code formatting, `just check` for basic checks, and `just check-workspace` for more advanced checks. Under-the-hood, it uses:
    - rustfmt
    - clang-format
    - cargo clippy
    - cargo bench
- github PRs/github CI: use the PR's labels `ci:none`, `ci:fast`, `ci:full` to fine-tune the CI checks. The full checks (`ci:full`) must be checked prior to merging PRs.
- [puffin-bench](https://github.com/tlspuffin/puffin-bench): run `uv run benchmark` for end-to-end, long, and comprehensive regressions and performance checks, see [benchmarks](./benchmarks.md).
