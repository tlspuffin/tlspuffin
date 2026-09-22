---
title: 'Integrating a new protocol'
---

`puffin` is protocol- and target-agnostic; a concrete fuzzer is built by extending
it at two layers (see [Overview](./overview)):

- **Layer 2 — the protocol crate ("the mapper").** A new crate `<proto>puffin`
  that instantiates `puffin` to one protocol: its message types and wire codec, the
  term algebra (function symbols), a seed corpus, claims, and the security policy.
- **Layer 3 — the PUT (harness + vendor).** A C harness exposing a small ABI, one
  or more vendor libraries built by `mk_vendor`, and the glue that links them into
  the fuzzer as Programs Under Test.

This page is the end-to-end checklist of every integration touch-point, using
[`sshpuffin`](https://github.com/tlspuffin/tlspuffin/tree/main/sshpuffin) (SSH, with
the libssh and wolfSSH PUTs) as the worked example. It complements two focused
guides: [Adding differential fuzzing to a protocol](./differential-fuzzing) (the
knowledge/claim comparison and decryption recipes) and
[How To](./howto) (adding a vendor preset). Do the differential-specific work only
if you want differential fuzzing.

The reference traits are
[`ProtocolBehavior`](https://tlspuffin.github.io/api/puffin/protocol/trait.ProtocolBehavior.html),
[`ProtocolTypes`](https://tlspuffin.github.io/api/puffin/protocol/trait.ProtocolTypes.html)
and [`Put`](https://tlspuffin.github.io/api/puffin/put/trait.Put.html).

## Layer 2 — the protocol crate

Create a new workspace crate `<proto>puffin` (mirror `sshpuffin/`). Its binary
entry point is a one-liner handing your registry to the shared CLI
(`sshpuffin/src/main.rs`):

```rust
pub fn main() -> ExitCode {
    puffin::cli::main("Fuzzes the SSH protocol at the symbolic level", ssh_registry())
}
```

### 1. `ProtocolTypes` and `ProtocolBehavior`

These two trait impls (in `sshpuffin/src/protocol.rs`) are the contract with
`puffin`. `ProtocolBehavior` wires up the associated types:

| Associated type | sshpuffin | What it is |
|---|---|---|
| `ProtocolTypes` | `SshProtocolTypes` | matcher, signature, PUT config (below) |
| `Claim` | `SshClaim` | security-relevant state captured at a claim point |
| `SecurityViolationPolicy` | `SshSecurityViolationPolicy` | the objective oracle (see §5) |
| `ProtocolMessage` / `OpaqueProtocolMessage` | `SshMessage` / `RawSshMessage` | parsed vs. opaque wire message |
| `ProtocolMessageFlight` / `OpaqueProtocolMessageFlight` | `SshMessageFlight` / `RawSshMessageFlight` | a flight = one output drain |

`ProtocolBehavior` also requires `create_corpus` (§4) and `try_read_bytes` (decode a
bitstring as a given `TypeId`), and lets you revisit the term-zoo generation budgets
(`ZOO_MAX_DEPTH` / `ZOO_MAX_SIZE` / `ZOO_MAX_TRIES`) — the defaults are tuned for
TLS, and are a property of the protocol, so review them.

`ProtocolTypes` declares the `Matcher` (§6) and `PUTConfig` types, exposes the term
`signature()` (§3), and — only if you do differential fuzzing — the
`differential_fuzzing_*` hooks documented in [that guide](./differential-fuzzing).

### 2. Messages and the wire codec

Define the protocol's message enum and payload structs (`sshpuffin/src/ssh/message.rs`)
and give each a `puffin::codec::Codec` (`encode`/`read`) implementation. Derive
`Extractable` (so sub-values become queryable knowledge) and, for differential
fuzzing, `Comparable`. A **deframer** (`sshpuffin/src/ssh/deframe.rs`) turns a raw
byte stream from the PUT back into a flight of messages; the opaque-flight `read`
runs the deframer so a concatenation of drains re-frames into one flight.

### 3. The term algebra (function symbols)

The mutator only ever builds terms from the **signature**: the set of typed function
symbols registered with `define_signature!` (`sshpuffin/src/ssh/mod.rs`). Each `fn_*`
is an ordinary Rust function (`sshpuffin/src/ssh/fn_{constants,message,crypto}.rs`)
whose arguments and return type define its slot in the algebra. Symbol flags shape
generation and mutation:

- `[no_gen]` — never synthesised during blind generation (probe/reproducer atoms, or
  helpers that need a specific key or a live claim, e.g. `fn_sign_userauth`,
  `fn_u32_auto`);
- `[opaque]` / `[list]` / `[get]` — see the `FunctionAttributes` (byte-blob leaves,
  name-list families, getters). Choosing the right flags and *newtyping* opaque byte
  fields (rather than a bare `SshBytes`) is what makes mutation target the field that
  matters — a substantial fuzzing-efficacy lever.

### 4. Seeds

`create_corpus` (delegating to `sshpuffin/src/ssh/seeds.rs`) returns the initial
traces. Hand-write at least one complete, honest handshake per role; keep seeds that
diverge across PUTs out of the differential corpus (register them behind a feature
such as `rich-corpus` instead).

### 5. Claims and the security policy

- **Claim** (`sshpuffin/src/claim.rs`) — a `#[repr(C)]` Rust mirror of the C
  `struct Claim` (§7), holding the transport state the harness reports at a claim
  point.
- **`SecurityViolationPolicy`** (`sshpuffin/src/violation.rs`) — `check_violation`
  turns claims into objectives. It may start as a `None` stub and be filled in as you
  discover what a violation looks like for your protocol.

### 6. Query matcher

`Matcher` (`sshpuffin/src/query.rs`, e.g. `SshQueryMatcher`) is how a trace addresses
a specific piece of knowledge (`(agent, counter)[matcher]/Type`). Model it on the
message kinds a recipe needs to pick out.

## Layer 3 — the PUT (harness + vendor)

### 7. The C harness ABI header

Declare the ABI the Rust side binds to in `sshpuffin/include/puffin/<proto>.h`
(which `#include`s the shared `puffin/puffin.h` from the `puffin` crate): the
agent-role enum, the plain-old-data
`struct Claim` (fixed-size buffers so it mirrors a `#[repr(C)]` type with no heap
ownership crossing FFI), and the PUT interface vtable. This header is the single
source of truth shared by the C harness and the Rust bindings.

### 8. The harness implementation

For each PUT, a C harness under `sshpuffin/harness/<lib>/` (e.g. `libssh`, `wolfssh`)
implements that ABI against the library's API and provides the `puffin_*` crypto-FFI
helpers in its `put.c`. Puffin-build compiles and bundles these; there is no separate
crypto static library.

### 9. `build.rs`

The crate's `build.rs` (`sshpuffin/build.rs`):

1. generates Rust FFI bindings from `include/puffin/<proto>.h` with `bindgen`
   (parity with `tlspuffin/build.rs` — same mechanism);
2. discovers every vendor instance in the vendor dir, compiles the C harness against
   each, and bundles them via `puffin-build`'s `harness::bundle` (which also emits the
   `has_put="<name>"` cfg per PUT);
3. emits ASAN / coverage link flags when the corresponding features are active.

### 10. Vendor presets and builder

Add a vendor under `puffin-build/vendors/<lib>/`: a `presets.toml` (repo/branch/version
per named preset) and a `builder.cmake`; for differential fuzzing also an
`instrument_claims.cmake` that patches the library to emit the claim. Adding an
individual preset follows the [How To](./howto) three-step (preset → support matrix
→ CI matrix); see also [`mk_vendor`](../references/mk_vendor) and the
[support matrix](../references/support-matrix).

### 11. PUT registration

`sshpuffin/src/put_registry.rs` includes the generated bundle and adapts each C PUT
into the registry via the `registration_c!` macro and the generic C-PUT bridge
(`sshpuffin/src/cput/`, `CSshPut`). `ssh_registry()` collects whatever PUTs the bundle
linked, so a build with only one vendor yields a single-PUT binary automatically.

## Tests and CI

- **Unit tests.** Mirror the SSH tests: a PUT-determinism test (a trace must replay
  byte-identically — precondition for differential fuzzing) and the
  protocol-parametric encode/`try_read`/re-encode round-trip
  (`puffin::test_utils::zoo_read_encode`), which every protocol opts into. Gate
  PUT-touching tests with `#[cfg(has_put = "<name>")]`.
- **CI.** Add a `cli-<proto>` build/smoke job and, for differential fuzzing, a
  `differential-<proto>` job that asserts "no differences" over the seed corpus, in
  `.github/workflows/run-validation.yml`; extend `.github/tlspuffin.matrix.json` for
  new presets.

## Checklist — the cost of a new protocol

| # | Touch-point | File(s) |
|---|---|---|
| 1 | `ProtocolTypes` + `ProtocolBehavior` impls | `<proto>puffin/src/protocol.rs` |
| 2 | Message types + `Codec` + deframer | `.../ssh/message.rs`, `.../ssh/deframe.rs` |
| 3 | Term signature + `fn_*` symbols (+ flags) | `.../ssh/mod.rs`, `.../ssh/fn_*.rs` |
| 4 | Seed corpus (`create_corpus`) | `.../ssh/seeds.rs` |
| 5 | Claim mirror + security policy | `.../claim.rs`, `.../violation.rs` |
| 6 | Query matcher | `.../query.rs` |
| 7 | C harness ABI header | `.../include/puffin/<proto>.h` |
| 8 | C harness per PUT (+ `puffin_*` helpers) | `.../harness/<lib>/` |
| 9 | `build.rs` (bindgen + bundle + flags) | `<proto>puffin/build.rs` |
| 10 | Vendor presets + builder (+ claim patch) | `puffin-build/vendors/<lib>/` |
| 11 | PUT registry + C-PUT bridge | `.../put_registry.rs`, `.../cput/` |
| 12 | Binary entry point | `<proto>puffin/src/main.rs` |
| 13 | Unit tests (determinism, round-trip) | `.../ssh/*` test modules |
| 14 | CI jobs + preset matrix | `.github/workflows/run-validation.yml`, `.github/tlspuffin.matrix.json` |
| ★ | *(differential only)* knowledge/claim comparison, decryption recipes, `uniformise_put_config` | see [differential fuzzing](./differential-fuzzing) |
