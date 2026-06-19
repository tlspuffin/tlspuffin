# sshpuffin — Differential DY Fuzzing (DDYF) + Second PUT — Plan

_Created 2026-06-17. Branch `pr/openssh-rework`. Companion to `SSHPUFFIN_PROGRESS_REPORT.md`._

## Goal

Enable **differential Dolev–Yao fuzzing** for SSH: run one symbolic trace against
two SSH implementations and flag behavioral divergences (execution status,
evaluated knowledge, claims, security claims). This requires (a) implementing
the currently-dummy DDYF hooks, (b) adding a second SSH PUT, and (c) real claims.

## Background (already in place)

- DDYF engine: `puffin/src/differential.rs`, CLI subcommands `differential`,
  `differential-experiment`, `differential-execute --first-target X --second-target Y`.
- It compares a `TraceDifference`: `Status`, `Knowledges`, `Claims`, `SecurityClaim`.
- Five hooks on `SshProtocolTypes` (in `sshpuffin/src/protocol.rs`), all dummy:
  - `differential_fuzzing_whitelist` → `None`
  - `differential_fuzzing_terms_to_eval` → `vec![]`
  - `differential_fuzzing_claims_blacklist` → `None`
  - `differential_fuzzing_uniformise_put_config` → identity
  - `differential_fuzzing_filter_diff` → `true`
- tlspuffin implements all five (`tlspuffin/src/protocol.rs:652-769`) — reference.
- Claims are stubbed: `SshClaim`/`SshClaimInner` dummy (`sshpuffin/src/claim.rs`),
  `register_claimer` is a no-op in `harness/libssh/src/put.c`.
- PUT registration: `build.rs` discovers every libssh in `vendor/` and registers
  each as a PUT. Rust PUTs are also supported (`harness::Kind::Rust` →
  `sshpuffin/src/rust_put/<vendor>`), as tlspuffin does for openssl/wolfssl/etc.

## Candidate second implementations

| Candidate | Lang | C/S | Path | Value | Effort |
|---|---|---|---|---|---|
| libssh 0.10.4 (vs 0.11.4) | C | C+S | reuse harness (preset exists) | low | trivial |
| wolfSSH | C | C+S | new C harness | high | medium |
| libssh2 | C | C only | new C harness | medium | low-med |
| russh | Rust | C+S | Rust PUT (`src/rust_put/russh`) | high | medium |
| Dropbear | C | C+S | app not lib | high | high |
| TinySSH | C | S only | new C harness | medium | medium |
| OpenSSH | C | C+S | app not lib | highest | very high |

**Decision:** Phase 0 = libssh 0.10.4. Real cross-impl Phase = **wolfSSH**
(confirmed 2026-06-17). Rationale: it is a library with embedder-supplied auth
callbacks (`wolfSSH_CTX_SetUserAuth`) and no privsep/PAM/fork/user-db, so the
full handshake — including userauth and channels — is harnessable in-memory at
the same effort as the existing libssh `put.c` (unlike OpenSSH, whose sshd auth
layer needs a real system context). Cost: extra wolfSSL/wolfCrypt build dep
(a wolfssl builder/preset already exists in puffin-build), and lower protocol
maturity than libssh/OpenSSH.

## Phases (Phase 2 and 3 SWAPPED per request)

### Phase 0 — Version differential (no new harness)
1. Ensure both `libssh0114-asan` and `libssh0104-asan` build & register
   (adjust `build.rs::ensure_libssh_vendors` to keep both).
2. Add algorithm config fields to `SshDescriptorConfig` (kex, cipher, hostkey,
   mac) and honor them in `put.c` via `ssh_options_set` /
   `ssh_bind_options_set`.
3. Implement `differential_fuzzing_uniformise_put_config` to pin a common set
   (curve25519-sha256, chacha20-poly1305@openssh.com, rsa-sha2-256).
4. `differential-execute libssh0104-asan libssh0114-asan seeds/seed_client_attacker_full.trace`
   → iterate until a clean (empty-diff) run on the success seed.

**Exit criterion:** differential pipeline runs end-to-end across two versions.

### Phase 1 — Implement the DDYF hooks
1. `differential_fuzzing_whitelist`: compared knowledge restricted to payload
   types (`SshMessage`, per-message payloads, `SshBytes`).
2. `differential_fuzzing_terms_to_eval`: add `fn_decrypt_packet(onwire, key, seqno)`
   (inverse of `fn_encrypt_packet`) in `fn_crypto.rs`; build post-exec decryption
   recipes so encrypted record-layer output compares as plaintext `SshMessage`.
3. `differential_fuzzing_filter_diff`: suppress known-benign diffs (banner text,
   optional ext-info) as they surface.

### Phase 3 — Second SSH implementation  ← (was Phase 3, now before claims)
1. Choose wolfSSH (C) or russh (Rust).
2. C route: `puffin-build/vendors/wolfssh/{presets.toml,builder.cmake}`,
   builtin builder name, `sshpuffin/harness/wolfssh/src/put.c` implementing the
   same `SSH_PUT_INTERFACE` (socketpair model + FD-leak fix reused).
   Rust route: `sshpuffin/src/rust_put/russh/` with `registration_rust`.
3. Extend `build.rs` to discover/compile the new harness.
4. `differential libssh0114-asan <new>`.

### Phase 2 — Real claims + DY properties  ← (now last)
1. Real `SshClaim` (KexComplete / AuthSucceeded / SessionEstablished; carrying
   session id, exchange hash, negotiated algorithms, derived keys).
2. Implement `register_claimer` in `put.c` (deferred-claim-queue pattern from
   `tlspuffin/harness/boringssl/src/put.c`).
3. Wire `claim.rs` ↔ C `CLAIMER_CB` / `claim-interface.h`.
4. `differential_fuzzing_claims_blacklist`: drop impl-specific claims.
5. Define DY security properties in `violation.rs` (auth bypass, key leakage,
   wrong-key acceptance).

## How DDYF comparison works (verified in source)

Pipeline (`puffin/src/trace.rs::compare`, `puffin/src/protocol.rs` CompareKnowledge):
1. Each PUT's outputs → a *positional* list of knowledge items (via `Extractable`).
   - `#[extractable_ignore]` → field is not extracted as knowledge.
   - `#[extractable_no_recursion]` → field is one knowledge item, no recursion.
2. Both lists filtered by `differential_fuzzing_whitelist` (Option<Vec<TypeId>>),
   then **zipped by index** (length mismatch → padded with `()` → shows as
   `X != ()` diffs).
3. Per position: same type → `comparable` structural diff (`#[comparable_ignore]`
   fields excluded); different type → `DifferentTypes`.

KEY: today the PUT output knowledge is all OPAQUE (`RawSshMessage`, `OnWireData`,
`BinaryPacket`, `Vec<u8>`, `u8`, banner `String`) — there is NO `SshMessage` in
knowledge. So structural comparison + field annotations only become useful once
`differential_fuzzing_terms_to_eval` parses/decrypts PUT output into `SshMessage`.

Determinism note: `rng_reseed` is implemented (custom OpenSSL `RAND_METHOD` in
`harness/libssh/src/rng.c`, reseed pointer in `SSH_PUT_INTERFACE`), BUT system
OpenSSL is 3.0.14 which ignores the legacy `RAND_METHOD` for X25519 keygen, so
full determinism is not achievable this way. Per design, cross-vendor KDF/seed
divergence is EXPECTED and handled by annotations + blacklist, not by RNG.

## Status log
- [~] Phase 0 — substantially done
  - [x] Both `libssh0114-asan` and `libssh0104-asan` register as PUTs.
  - [x] `differential-execute` runs end-to-end (pipeline validated).
  - [x] `rng_reseed` infra added (limited by OpenSSL 3.x; documented above).
  - [x] Determined that meaningful comparison needs Phase 1 (decryption recipes
        + whitelist + field annotations), NOT RNG determinism or uniformise.
- [x] Phase 1 — COMPLETE (plaintext handshake + encrypted record layer):
  - [x] `fn_decrypt_packet` (inverse of `fn_encrypt_packet`) + roundtrip tests.
  - [x] `differential_fuzzing_whitelist`: SshMessage, SshMessageFlight,
        KexInitMessage, KexEcdhReplyMessage (opaque/ciphertext types excluded).
  - [x] `#[comparable_ignore]` on divergent fields: KexInit `cookie`,
        KexEcdhInit `ephemeral_public_key`, KexEcdhReply `ephemeral_public_key`
        + `signature` (host key KEPT — same embedded key, a diff = real finding).
  - [x] Verified: ALL seeds give same-vs-same = 0 (deterministic comparison via
        annotations, not RNG); 0114-vs-0104 surfaces the genuine KexInit
        divergence (kex-strict-s-v00@openssh.com / Terrapin CVE-2023-48795 +
        zlib). `filter_diff` left permissive (cross diffs are real signal).
  - [x] `differential_fuzzing_terms_to_eval` — DONE. `server_decryption_recipes`
        (seeds.rs) reconstructs the s2c key from observed KEX output and
        decrypts the server's encrypted responses with `fn_decrypt_packet`.
        Emits recipes at both strict (0,1,2) and non-strict (3,4,5) s2c seqnos;
        wrong seqno fails the tag and is skipped, keeping stores aligned.
        Verified: 0114 decrypts at 0,1 (strict) and 0104 at 3,4 (non-strict),
        both → [ServiceAccept, UserAuthSuccess]; decrypted layer compares EQUAL,
        so only the pre-NewKeys KexInit diffs remain. PHASE 1 COMPLETE.
- [x] Phase 3 (wolfSSH) — DONE (cross-implementation differential runs):
  - wolfSSL (--enable-ssh) + wolfSSH built static with ASAN+sancov via
    harness/wolfssh/build_wolfssh_vendor.sh; staged as vendor/wolfssh-asan.
  - harness/wolfssh/src/put.c drives wolfSSH's embeddable API; build.rs
    discovers wolfssh vendors and builds the harness alongside libssh.
  - wolfssh-asan registers; the AES-GCM seeds complete on BOTH wolfSSH and
    libssh (wolfSSH lacks chacha20-poly1305, so the chacha20 seeds are
    libssh-only), giving structural KEX + encrypted-record comparison across
    vendors. wolfSSH also emits claims and records authentication identity, so
    the Phase 2 oracles cover it symmetrically with libssh.
  Original scoping note (kept for reference):
  - puffin-build has NO cross-vendor dependency mechanism. Each vendor fetches
    ONE source URL (`SOURCES`) and runs CONFIGURE/BUILD/INSTALL. wolfSSH needs
    wolfSSL at build time (`--with-wolfssl=<prefix>`), so the wolfssh
    `builder.cmake` must fetch+build BOTH libraries (nested ExternalProject or
    shell steps): build wolfSSL (autotools, asan+sancov) → install to a prefix →
    build wolfSSH (`--with-wolfssl=<prefix>`, asan+sancov) → install.
  - Then a new C harness `sshpuffin/harness/wolfssh/src/put.c` implementing
    SSH_PUT_INTERFACE against wolfSSH (`wolfSSH_accept/connect`, `wolfSSH_set_fd`,
    `wolfSSH_CTX_SetUserAuth` callback returning SUCCESS), reusing the socketpair
    model + FD-leak fix from the libssh harness.
  - Effort: large, multiple build-debug cycles, long from-source compiles that
    compete with the running campaigns for CPU. Low protocol-maturity target.
- [x] Phase 1 extension — AES-256-GCM decryption recipes added alongside
      ChaCha20 (`server_decryption_recipes_aesgcm`); both recipe sets emitted, so
      the encrypted-layer differential covers wolfSSH's GCM responses too. The
      libssh-vs-wolfSSH AES-GCM differential surfaces a real divergence
      (UserAuthSuccess-first vs ServiceAccept-first), clean within one vendor.
- [x] Phase 2 (claims + DY properties) — DONE:
  - Claims subsystem: SshClaim/SshClaimInner carry negotiated kex/cipher/MAC and
    the server's authentication belief (method / user / verified-key
    fingerprint). The libssh AND wolfSSH harnesses emit claims via a notify
    trampoline (CAgent registers an extern "C" callback pushing onto the
    GlobalClaimList; reclaimed on Drop).
  - Negotiation-level matching-conversation oracle (kex/cipher/MAC must agree
    crosswise between the two honest endpoints).
  - Entity-authentication / impersonation oracle: a server that completes
    PUBLICKEY auth for any key other than the attacker-controlled A
    (ATTACKER_PUBKEY_SHA256) is impersonation — A is the only client key with a
    signing function in the term algebra, so no honest trace can authenticate as
    another key. Wired symmetrically for libssh and wolfSSH; end-to-end seeds
    (chacha20 libssh-only, aesgcm both vendors) complete as A with the oracle
    clean (true negative).
  - Two-honest-party relay seed (`seed_handshake_two_party`): both client and
    server are real PUTs; the required shape for matching conversation.
- [~] Matching conversation / Terrapin (transcript integrity):
  - The wire-byte-digest approach was tried and REVERTED — wrong layer (libssh
    flips its cipher at packet-processing time, not byte-I/O time, so a byte gate
    is asymmetric across peers). Lesson recorded.
  - Trace-analysis primitive `delivered_to(trace, ctx, agent)` added instead:
    re-evaluates the trace's input recipes to recover what each honest party
    received on the wire, with no PUT introspection. Detects a dropped/injected
    relay message (the Terrapin truncation primitive). Remaining: the full
    within-trace two-view oracle + fuzzer-objective wiring.
- [ ] CVE positive demonstration (e.g. CVE-2018-10933 auth bypass): BLOCKED on
      building a vulnerable PUT. libssh 0.8.3's CMake OpenSSL detection is
      fixable via OPENSSL_ROOT_DIR, but the build then needs a clean nix-shell
      (outside it, clang mixes nix-glibc and /usr/include). Better long-term: the
      trace-analysis path above, which needs no patched/old vendor.
