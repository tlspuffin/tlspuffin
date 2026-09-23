---
title: 'Integrating a new protocol'
---

`puffin` is protocol- and target-agnostic; a concrete fuzzer is built by extending
it at two layers (see [Overview](./overview)):

- **Layer 2 — the protocol crate.** A new crate `<proto>puffin`
  that instantiates `puffin` to one protocol: its message types and wire codec, the
  term algebra (function symbols), a seed corpus, claims, and the security policy.
- **Layer 3 — the PUT (harness + vendor).** A C harness exposing a small ABI, one
  or more vendor libraries built by `mk_vendor` (`puffin-build/`), and the glue that links them into
  the fuzzer as Programs Under Test.

This page is the end-to-end checklist of every integration touch-point, using
[`sshpuffin`](https://github.com/tlspuffin/tlspuffin/tree/main/sshpuffin) (SSH, with
the libssh and wolfSSH PUTs) as the worked example. It complements two focused
guides:

- [How To](./howto) (adding a vendor preset, layer 3).
- Differential-specific protocol integration work (only
  if you want differential fuzzing): [Adding differential fuzzing to a protocol](./differential-fuzzing).

The reference traits are
[`ProtocolBehavior`](https://tlspuffin.github.io/api/puffin/protocol/trait.ProtocolBehavior.html),
[`ProtocolTypes`](https://tlspuffin.github.io/api/puffin/protocol/trait.ProtocolTypes.html)
and [`Put`](https://tlspuffin.github.io/api/puffin/put/trait.Put.html).

## Layer 2 — the protocol crate

Create a new workspace crate `<proto>puffin` (mirror `sshpuffin/`). Like `tlspuffin`,
it is a **library** (`src/lib.rs` declares the modules) with a thin **binary**
(`src/main.rs`) handing the registry to the shared CLI:

```rust
use sshpuffin::put_registry::ssh_registry;

pub fn main() -> ExitCode {
    puffin::cli::main("Fuzzes the SSH protocol at the symbolic level", ssh_registry())
}
```

The library target is what lets the tests live under `tests/` (see
[Tests and CI](#tests-and-ci)).

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

`ProtocolBehavior` also requires `create_corpus` (§4) and `try_read_bytes` (§2), and
lets you revisit the term-zoo generation budgets (`ZOO_MAX_DEPTH` / `ZOO_MAX_SIZE` /
`ZOO_MAX_TRIES`) — the defaults are tuned for TLS, and are a property of the
protocol, so review them. The fuzzer builds its zoo of generated terms at startup and
spends up to `ZOO_MAX_TRIES` attempts on every symbol that is not `[no_gen]` (§3).

`ProtocolTypes` declares the `Matcher` (§6) and `PUTConfig` types, exposes the term
`signature()` (§3), and — only if you do differential fuzzing — the
`differential_fuzzing_*` hooks documented in [that guide](./differential-fuzzing).
It also has one optional hook, `preprocess_trace`: a per-execution rewrite of the
trace, for values that depend on a message's position in the trace rather than on
its content. It defaults to `None` (use the trace as is, no copy). sshpuffin uses it
to renumber AES-GCM packet counters: seeds write the `fn_u32_auto` atom as the
counter, and the pass replaces it by the packet's position since the last NEWKEYS,
so a mutation that deletes or reorders steps keeps the nonces valid.

### 2. Messages and the wire codec

Define the protocol's message enum and payload structs (`sshpuffin/src/ssh/message.rs`)
and give each a `puffin::codec::Codec` (`encode`/`read`) implementation. Derive
`Extractable` so that the values inside an output message become knowledge the
attacker can query (`#[extractable_no_recursion]` stops at a leaf such as a byte
blob), and, for differential fuzzing, `Comparable`. A **deframer**
(`sshpuffin/src/ssh/deframe.rs`) turns a raw byte stream from the PUT back into a
flight of messages; the opaque-flight `read` runs the deframer so a concatenation of
drains re-frames into one flight.

`try_read_bytes` (`sshpuffin/src/ssh/message.rs`) decodes a bitstring as a given
type; it is the type table of the protocol. List in it every type that can be
knowledge, and every type that can be the argument of an `[opaque]` symbol: puffin
re-reads such an argument after applying a payload to it (§3). `encode` and `read`
must be inverses, which `test_term_read_encode` checks (see [Tests and CI](#tests-and-ci)).

Give each *role* its own type rather than a bare byte blob (`SshBytes`): sshpuffin
has `SharedSecret`, `ExchangeHash`, `SessionId`, `VersionString`, `AlgoName`,
`Username`, `ServiceName`, `ChannelId`, `SshMsgNumber`, … Type-directed mutations
(e.g. `ReplaceMatchMutator`) then only swap a value for another of the same role, which
is exactly the class of substitutions the interesting attacks live in.

### 3. The term algebra (function symbols)

The mutator only ever builds terms from the **signature**: the set of typed function
symbols registered with `define_signature!` (`sshpuffin/src/ssh/mod.rs`). Each `fn_*`
is an ordinary Rust function (`sshpuffin/src/ssh/fn_{constants,message,crypto}.rs`)
whose arguments and return type define its slot in the algebra.

Flags on a symbol (see `FunctionAttributes`) tell puffin how the symbol's encoding
relates to its arguments', which decides where a payload (a bit-level mutation of a
sub-term's bytes, placed by `MakeMessage`) can be placed:

- **no flag** — the encoding contains each argument's encoding (a message or field
  builder). puffin finds a payload's position in the parent's bytes.
- `[opaque]` — the encoding contains none of the arguments' encodings: hashes, KDFs,
  DH, encryption, decryption, signatures. puffin applies a payload to the argument,
  re-reads it with `try_read_bytes`, then applies the symbol.
- `[get]` — an accessor returning a field of its argument (`fn_server_ecdh_pubkey`),
  or a truncating conversion (TLS's `fn_u32_to_u16`); a payload under it that is not
  found in the output is dropped, not an error.
- `[list]` — an element-by-element list builder (TLS's `fn_append_certificate`,
  sshpuffin's `fn_namelist_append`), and the empty list it starts from: puffin finds the
  appended element at the end of the list. Encode the list type *without* its length
  prefix (the message field holding it writes the prefix), so that a list's encoding is
  inside the one it extends. Build a list this way rather than with a symbol taking
  several elements at once: when an element's bytes occur more than once, puffin
  positions it by its right-hand siblings, which separators between elements (commas in
  an SSH name-list) break.
- `[no_gen]` — never the root of a generated term. Use it for probe/reproducer atoms
  and recipe helpers (`fn_u32_auto`, `fn_decrypted_message`), and for every symbol the
  zoo cannot build an evaluable term for (sshpuffin: the KDFs need an exchange hash,
  the decryptions a real ciphertext), or each campaign spends `ZOO_MAX_TRIES` on it.

A wrong or missing flag makes payload evaluation fail with `Error::TermBug`; the
term-zoo tests catch that, and a missing `[no_gen]` (see [Tests and CI](#tests-and-ci)).
In sshpuffin each flag carries a one-line reason, with a legend above
`define_signature!`.

A type that only appears as knowledge (never built by a symbol) still has to be in the
signature's type table for traces that query it to deserialize: register a `[no_gen]`
symbol returning it, as sshpuffin's `fn_raw_message_flight` does for
`RawSshMessageFlight`.

### 4. Seeds

`create_corpus` (at the top of `sshpuffin/src/ssh/seeds.rs`, next to `build_corpus`)
returns the initial traces. Hand-write at least one complete, honest handshake per
role, and:

- add an explicit `OutputAction` step after each input the peer has to answer, with a
  comment naming the reply (puffin also reads the peer after every input, but explicit
  steps show the round-trips and give the mutator reply points);
- build later messages from the peer's replies rather than from constants, when the
  protocol makes them depend on it (sshpuffin reads the channel number the server
  confirmed, the blob a `PK_OK` echoes, the server's rekey replies, out of its decrypted
  output with `fn_decrypted_message`);
- keep seeds that diverge across PUTs out of the differential corpus (register them
  behind a feature such as `rich-corpus` instead).

### 5. Claims and the security policy

- **Claim** (`sshpuffin/src/claim.rs`) — a `#[repr(C)]` Rust mirror of the C
  `struct Claim` (§7), holding the transport state the harness reports at a claim
  point. The harness can only report what the library exposes: sshpuffin patches each
  vendor to export its session id (`puffin-build/vendors/<lib>/instrument_claims.cmake`),
  and the vendor's `vendorinfo.sh` names that symbol so the build records the library
  as claim-instrumented (§10).
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

The vtable's `rng_reseed` is the **determinism hook**: puffin calls it before every
execution (`determinism_reseed_all_factories`), and the harness must reset every
source of randomness of the library to a fixed seed (sshpuffin: a custom OpenSSL
`RAND_METHOD` for libssh, the wolfSSL seed callback for wolfSSH, rewound at each agent
creation). A trace must replay byte-identically: objectives have to reproduce, and
differential fuzzing compares two PUTs on the same trace.

### 8. The harness implementation

For each PUT, a C harness under `sshpuffin/harness/<lib>/` (e.g. `libssh`, `wolfssh`)
implements that ABI against the library's API and provides the `puffin_*` crypto-FFI
helpers in its `put.c`. Puffin-build compiles and bundles these; there is no separate
crypto static library. Drive the library until it has nothing more to send before
returning from `progress`, so that a reply is not split over two reads.

### 9. `build.rs`

The crate's `build.rs` (`sshpuffin/build.rs`):

1. generates Rust FFI bindings from `include/puffin/<proto>.h` with `bindgen`
   (parity with `tlspuffin/build.rs` — same mechanism);
2. discovers every vendor instance in the vendor dir, compiles the C harness against
   each, and bundles them via `puffin-build`'s `harness::bundle` (which also emits the
   `has_put="<name>"` cfg per PUT); when the vendor dir has none, it builds a default
   preset, which must be the one your PUT tests are gated on (sshpuffin:
   `LIBSSH_PRESET = "libssh0114"`), or those tests silently compile out;
3. emits ASAN / coverage link flags when the corresponding features are active.

### 10. Vendor presets and builder

Add a vendor under `puffin-build/vendors/<lib>/`: a `presets.toml` (repo/branch/version
per named preset) and a `builder.cmake`; for differential fuzzing also an
`instrument_claims.cmake` that patches the library to emit the claim. Optionally add a
`vendorinfo.sh`, sourced when the vendor's `.metadata` is written
(`puffin-build/cmake/builder/cmake/vendorinfo.sh.in`): it sets `CLAIM_SYMBOLS`, the
symbols whose presence marks the library as claim-instrumented, and defines
`detected_version`, which reads the version from the installed headers so that a
stale vendor is reported. Adding an individual preset follows the [How To](./howto)
three-step (preset → support matrix → CI matrix); see also
[`mk_vendor`](../references/mk_vendor) and the [support matrix](../references/support-matrix).

### 11. PUT registration

`sshpuffin/src/put_registry.rs` includes the generated bundle and adapts each C PUT
into the registry via the `registration_c!` macro and the generic C-PUT bridge
(`sshpuffin/src/cput/`, `CSshPut`). `ssh_registry()` collects whatever PUTs the bundle
linked, so a build with only one vendor yields a single-PUT binary automatically.

## Tests and CI

- **Tests** go under `<proto>puffin/tests/`, as in `tlspuffin` and `sshpuffin`:
  - `term_zoo.rs` — the term-zoo tests of `puffin::test_utils`, shared by all
    protocols: build a `ZooTest` with your signature and registry, then
    `term_read_encode` (codec round-trip), `term_payloads_eval` and
    `term_payloads_mutate_eval` (flags: must report no `TermBug`), and a run of
    `ZooTest::run` checking every symbol without `[no_gen]` evaluates;
  - `determinism.rs` — a trace replays byte-identically on each PUT;
  - `traces.rs` — seeds executed on the PUTs reach their expected outcome.

  Gate the tests that need a PUT with `#[cfg(has_put = "<name>")]` (a whole file with
  `#![cfg(...)]`). PUT executions in one test binary must not overlap: the libraries'
  random generators are process-global, so serialise them with a mutex (see
  `sshpuffin/tests/traces.rs`).
- **CI.** In `.github/workflows/run-validation.yml`: run `just test <proto>` in the
  unit-test job and check that the PUT-gated tests actually ran (a missing vendor
  compiles them out silently; sshpuffin greps their names in the test log); add a
  `cli-<proto>` build/smoke job and, for differential fuzzing, a
  `differential-<proto>` job that asserts "no differences" over the seed corpus.
  Extend `.github/tlspuffin.matrix.json` for new presets.

## Checklist — the cost of a new protocol

| # | Touch-point | File(s) |
|---|---|---|
| 1 | `ProtocolTypes` + `ProtocolBehavior` impls (+ `preprocess_trace` if needed) | `<proto>puffin/src/protocol.rs` |
| 2 | Message types + `Codec` + deframer + `try_read_bytes` type table | `.../ssh/message.rs`, `.../ssh/deframe.rs` |
| 3 | Term signature + `fn_*` symbols (+ flags) | `.../ssh/mod.rs`, `.../ssh/fn_*.rs` |
| 4 | Seed corpus (`create_corpus`) | `.../ssh/seeds.rs` |
| 5 | Claim mirror + security policy | `.../claim.rs`, `.../violation.rs` |
| 6 | Query matcher | `.../query.rs` |
| 7 | C harness ABI header (+ `rng_reseed`) | `.../include/puffin/<proto>.h` |
| 8 | C harness per PUT (+ `puffin_*` helpers) | `.../harness/<lib>/` |
| 9 | `build.rs` (bindgen + bundle + flags + default preset) | `<proto>puffin/build.rs` |
| 10 | Vendor presets + builder (+ claim patch, `vendorinfo.sh`) | `puffin-build/vendors/<lib>/` |
| 11 | PUT registry + C-PUT bridge | `.../put_registry.rs`, `.../cput/` |
| 12 | Library + binary entry point | `<proto>puffin/src/lib.rs`, `<proto>puffin/src/main.rs` |
| 13 | Tests (term zoo, determinism, traces) | `<proto>puffin/tests/` |
| 14 | CI jobs + preset matrix | `.github/workflows/run-validation.yml`, `.github/tlspuffin.matrix.json` |
| ★ | *(differential only)* knowledge/claim comparison, decryption recipes, `uniformise_put_config`, and a triage script sorting the objectives into classes (`evaluation-ddyf/<proto>/`) | see [differential fuzzing](./differential-fuzzing) |
