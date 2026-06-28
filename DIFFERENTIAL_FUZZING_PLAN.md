# sshpuffin — Differential DY Fuzzing (DDYF) + Second PUT — Plan

_Created 2026-06-17. Updated 2026-06-28. Branch `pr/ssh/ssh-rework`. Companions:
`SSHPUFFIN_PROGRESS_REPORT.md`, `GRADIENT_ANALYSIS_DDYF.md`, `DY_CLAIM_COVERAGE_FEEDBACK.md`._

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
- [x] Matching conversation / Terrapin — DONE via a CLAIMS-based oracle (the
      byte-stream path was completed then RETIRED):
  - The wire-byte digest and the trace-analysis `delivered_to`/`matching_conversation_violation`
    byte-stream oracle were both built, but the byte-stream comparison
    OVER-APPROXIMATES: it flags corruption of fields SSH explicitly does not
    protect — padding and SSH_MSG_IGNORE (RFC 4251 §9.3.6) — which were the bulk
    of the bit-level campaign false positives. So `check_trace_security_violation`
    now returns `None`; the property is judged by the claims oracle.
  - The claims-based oracle (`violation.rs::check_violation`) checks, between the
    two honest endpoints that both reached `PHASE_DONE`:
      * **KEX-transcript agreement** — same SSH session id (exchange hash H, RFC
        4253 §7.2/§8); cross-vendor peers that don't expose it fall back to the
        algorithm-agreement checks.
      * **Channel-data integrity** — per-direction post-NEWKEYS message-type
        digest, compared crosswise (server-sent == client-received, and vice
        versa). A dropped/injected/reordered secure-channel message (Terrapin's
        stripped EXT_INFO) breaks the equality. Padding/IGNORE never enter the
        digest, so this is FP-free by construction.
    Backed by a libssh patch (`puffin-build/vendors/libssh/instrument_claims.cmake`)
    exposing the session id + parse-layer digests + per-direction packet counts.
  - **Terrapin (CVE-2023-48795) is DEMONSTRATED**: `seed_terrapin_s2c` +
    `test_terrapin_s2c_detected_and_mitigated` — fires on libssh 0.10.4
    (matching-conversation violation = fuzzer objective) and is strict-kex-
    mitigated on 0.11.4. The c2s direction is structurally impossible (the client
    sends a single mandatory post-NEWKEYS packet).
  - Intermediate **phase claims + packet counts** were added (for the
    claim-coverage feedback's liveness-depth signal); the oracle considers only
    `phase==DONE` claims, so intermediate ones are coverage-only.
- [x] Autonomous Terrapin DISCOVERY (mutation, not detection) — empirically
      CHARACTERISED as not reachable by undirected DY mutators:
  - A focused 6 h × 10 solo-core hunt on libssh0104 from the single honest
    packet-granular substrate seed (`seed_handshake_two_party_packet_complete`),
    ~5 M execs/core, produced **0 objectives**. The FP-free oracle never
    misfired, and undirected mutation never landed the coordinated drop-EXT_INFO
    + inject-cleartext-IGNORE pair (the all-or-nothing seqno barrier — see
    `GRADIENT_ANALYSIS_DDYF.md`). This is the clean negative motivating the
    `TruncateWithCompensation` invariant-preserving mutator.
- [x] Protocol-agnostic **claim-trajectory coverage feedback** (see
      `DY_CLAIM_COVERAGE_FEEDBACK.md`): coverage over the per-execution claim
      sequence (states + transitions), via `Claim::coverage_key`. A/B vs
      edge-only showed it never hurts edge coverage and modestly increases
      DY-state exploration, but the reachable DY-state space here is small
      (~140 cells), so its leverage is limited without richer protocol state or
      the compensation mutator.
- [ ] CVE-2018-10933 (libssh server auth bypass) positive demonstration: still
      only covered CONCEPTUALLY by the entity-authentication oracle (a server
      completing publickey auth for a non-attacker key is impersonation). Not
      demonstrated against a vulnerable PUT (libssh 0.8.x build still blocked on
      OpenSSL detection in the nix toolchain).

## Findings from the 2026-06-28 differential re-run (+ per-seed verification)

Re-ran `differential-experiment` and then verified each seed directly with
`differential-execute -j`:

- **Version `libssh0104` vs `libssh0114` — WORKS, seeds clean.** All 13 seeds
  give empty diff (verified per-seed, not inferred). Fuzzing objectives are all
  `Execution status difference` (strict-kex/version acceptance divergences), 0
  Claims / 0 SecurityClaim — consistent with the 6 h Terrapin-discovery negative.
- **Cross-vendor `libssh0114` vs `wolfssh` — WAS broken, now FIXED.** Per-seed
  diff showed two distinct causes (not the ordering one originally guessed):
  1. **Asymmetric phase claims (regression, FIXED).** Intermediate phase claims
     were emitted only by libssh, giving a `Claims` diff on every AES-GCM seed
     (the whole diff for those seeds — no Status/Knowledge diff). Fixed by giving
     them a distinct `TypeShape` (`SshProgressClaim`) and dropping them via
     `differential_fuzzing_claims_blacklist`. AES-GCM client seeds now diff-clean.
  2. **Genuine acceptance divergences (not a bug).** chacha20/ctr seeds → `Status`
     diff (wolfSSH lacks those ciphers); server-attacker / ext-info / rekey seeds
     → `Claims` `SshClaimInner vs ()` (wolfSSH does not reach the completion
     claim for those flows). These are real cross-vendor behaviour, so they are
     excluded from the cross-vendor seed baseline rather than compared.
  Result: the cross-vendor differential is re-baselined on a curated subset of
  the 3 verified-clean AES-GCM client seeds (`launch_diff.sh` → `diff_xvendor/`),
  runs with a non-empty corpus, and surfaces only mutation-driven `Status` diffs.

## Toward freezing DDYF v1 (next steps, prioritised)

The single-PUT DY oracle is in good shape (precise, Terrapin-demonstrated). To
freeze a coherent *differential* v1, in order:

1. **[DONE 2026-06-28] Decouple coverage claims from oracle/differential
   claims.** Intermediate phase claims now carry a distinct `TypeShape`
   (`SshProgressClaim`, via `SshClaim::id`) and are dropped via
   `differential_fuzzing_claims_blacklist`; the claim-coverage observer is
   unaffected (keys off `coverage_key`). Cross-vendor AES-GCM seeds verified
   diff-clean; the cross-vendor differential no longer starves.
2. **[DONE 2026-06-28] `filter_diff` separates "clean baseline" from "finding"
   — and it is already conservative (the earlier "permissive" note was stale).**
   `differential_fuzzing_filter_diff` keeps all `SecurityClaim` and `Claims`
   diffs, keeps `Status` only on acceptance *disagreement* (one PUT `Success`,
   the other a PUT rejection), and drops `Knowledges` (transcript fingerprints).
   The engine only emits a `Status` diff when a side is `Error::Put`, so
   term/IO/Stream harness errors never reach the filter. Triage of a
   libssh-vs-wolfSSH campaign (2026-06-28) showed the kept objectives are FIVE
   classes, ALL genuine: wolfSSH accepting an oversized banner / unusable
   version that libssh rejects; libssh accepting what wolfSSH rejects; completion
   claim present-vs-absent; and libssh's own socket-level error on an input
   wolfSSH completes. **None are noise to filter** — loosening would risk missing
   a real bug, so the decision is to NOT add conditions. Locked in by
   `cross_vendor_acceptance_divergences_are_all_kept` +
   `claim_presence_difference_is_kept` (regression guard against future
   loosening).
3. **Pin a clean cross-vendor seed.** Ensure at least one `--differential` seed
   (AES-GCM, the cipher both vendors share) runs diff-free end-to-end on
   libssh↔wolfSSH after (1)+(2), as the corpus root.
4. **Re-baseline both differential pairs** (version + cross-vendor) to an
   empty-diff corpus, then run a timed campaign and triage objectives into
   benign (→ extend `filter_diff`/annotations) vs real.
5. **(Optional, raises power) `TruncateWithCompensation` mutator** so the
   version differential can actually *discover* Terrapin (fires on 0.10.4,
   strict-kex-mitigated on 0.11.4 = a clean `SecurityClaim::Different`), rather
   than only detect the hand-built seed.

Definition of "DDYF v1 frozen": both differential pairs start from an empty-diff
corpus, run without starving, and every surfaced diff is either filtered as
known-benign or recorded as a triaged finding — with the claim-type split (1)
and `filter_diff` (2) landed and committed.
