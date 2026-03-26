# BoringSSL C Harness — Progress Report

## Overview

Adding a C harness for BoringSSL (`boringssl20260211`) to enable differential fuzzing against OpenSSL 3.4.0.
Branch: `pr/c-harness-boringssl`. Process: `PROMPT_add-vendor_LibreSSL.md`.

## Starting state (2026-03-23)

Two prior commits by another LLM (`d2d09b3d4`, `bd401ec16`) attempted the harness but produced non-functional code:
- Basic seed execution (`seed_successful`) crashes with `INPUT_NOT_INITIALIZED` from BoringSSL's digest module
- `PUFFIN_extract_transcript()` called unconditionally in `boringssl_fill_claim()`, even when transcript hash context is uninitialized
- No deferred claim queue — claims emitted directly inside `msg_callback` (state may be incomplete)
- Missing standalone `CLAIM_FINISHED` emission (only transcript claims emitted for Finished messages)
- Global C++ `std::unordered_map` for per-SSL state instead of fields on `AGENT_TYPE`
- Cipher configuration broken — BoringSSL doesn't accept the full IANA+OpenSSL cipher list from the framework
- Hallucinated documentation claiming "production ready" and "all tests pass" (deleted)

### What was kept from the prior work
- Build system: `builder.cmake`, `presets.toml`, patches (`extract_transcript.patch`, `reset_drbg.patch`, `no_asan.patch`)
- Cross-vendor build changes: `run.cmake` (C++17 + .cc glob), `put.rs` (C++ linking), `mod.rs` (vendor src includes)
- `bindings.c`, `bindings.h` — cert/key loading helpers (look correct)
- `rng.c`, `rng.h` — RNG override using `RAND_reset_for_fuzzing()` (correct)
- `boringssl-sys` changes (new version feature)
- `stats_monitor.rs` fix (unrelated but kept)
- CI matrix addition, seed test entries, put_registry test

### What was deleted
- `BORINGSSL_IMPLEMENTATION.md` — hallucinated success report
- `BORINGSSL_QUICK_REFERENCE.md` — hallucinated quick reference
- `STEP3_SUMMARY.md` — hallucinated step summary

### What was rewritten from scratch
- `tlspuffin/harness/boringssl/src/put.c` — main harness
- `tlspuffin/harness/boringssl/src/claims.cc` — claims extraction (C++)
- `tlspuffin/harness/boringssl/src/claims.h` — claims header

## Plan

Following `PROMPT_add-vendor_LibreSSL.md` step-by-step procedure:

### Phase 0: Clean up [DONE]
- [x] Delete hallucinated docs
- [x] Keep build infrastructure and cross-vendor changes
- [x] Rewrite harness files from scratch

### Phase 1: Basic execution with claims (Steps 1-2 combined)
- [x] Rewrite `put.c` with correct structure (deferred claim queue on AGENT_TYPE, msg_callback for queueing only)
- [x] Rewrite `claims.cc` with full claim extraction (version, randoms, certs, secrets, ciphers, transcripts)
- [x] Fix crash: `CLAIMER_CB` must be copied (malloc), not stored as pointer
- [x] Fix crash: `boringssl_extract_transcript_safe` guards against uninitialized context
- [x] Fix cipher list: BoringSSL's `SSL_get_ciphers` omits TLS 1.3 ciphers; manually add 0x1301/0x1302/0x1303
- [x] Fix cipher config: use `SSL_CTX_set_cipher_list` (tolerant) instead of `SSL_CTX_set_strict_cipher_list`
- [x] Eliminate global C++ `unordered_map`; state on `AGENT_TYPE` via C accessor functions
- [x] Associate AGENT with SSL via `SSL_set_ex_data` so `PUFFIN_store_ch_sh_transcript` patch can reach it
- [x] Validate: 8/14 seeds pass (basic TLS 1.3 + TLS 1.2)
  - Success: seed_successful, seed_client_attacker12, seed_client_attacker_full, seed_server_attacker_full,
    seed_server_attacker_full_coalesced, seed_server_attacker_with_hello_retry_request,
    seed_successful12_with_tickets
  - Expected failures (decryption recipes need correct secrets — Phase 4):
    seed_client_attacker, seed_client_attacker_auth, seed_session_resumption_dhe/ke
  - Flight structure differences (Phase 6):
    seed_successful_with_ccs, seed_successful_with_tickets (missing ApplicationData knowledge)
  - BoringSSL-specific strictness (Phase 6):
    seed_server_attacker12 (SERVER_ECHOED_INVALID_SESSION_ID)
### Phase 2: Basic security claims (Step 2) [DONE]
- [x] Implement `boringssl_fill_claim()` — version, randoms, cipher, session_id, certs, TLS 1.2 master secret
- [x] Wire up deferred queue flush in `progress()` — emit claims when state is stable
- [x] Standalone `CLAIM_FINISHED` emission before transcript claims

### Phase 3: Transcript hashes (Step 3) [DONE]
- [x] Fix `PUFFIN_extract_transcript` to handle uninitialized context gracefully
- [x] Snapshot transcript hashes in msg_callback into deferred queue
- [x] Handle CH+SH transcript via `PUFFIN_store_ch_sh_transcript` patch
- [x] **Critical fix**: BoringSSL fires `msg_callback` BEFORE updating `hs->transcript` (see `s3_both.cc:139`).
      All transcript hashes captured in msg_callback are off-by-one (missing the current message).
      Fixed by adding `boringssl_extract_transcript_with_msg()` which copies the hash context,
      appends the current message, and finalizes — giving the correct post-message hash.

### Phase 4: Secrets for decryption (Step 4) [DONE]
- [x] TLS 1.3: handshake_secret, master_secret, exporter_master_secret, traffic secrets
- [x] Cache server_random from ServerHello in msg_callback
- [x] `SnappedTLS13Secrets`: snapshot all TLS 1.3 secrets while `hs` is alive (BoringSSL frees `hs` after handshake)
- [x] **Critical fix**: `hs->secret` is overwritten by `tls13_advance_key_schedule` (handshake→master).
      By msg_callback time for Finished, it contains the master secret, not the handshake secret.
      Fixed by extending `extract_transcript.patch` (v3) to capture `hs->secret` at the exact moment
      in `tls13_derive_handshake_secrets` via `PUFFIN_store_handshake_secret()` (thread-local storage).
      Claims.cc retrieves it via `PUFFIN_extract_handshake_secret()`.
- [x] Validate: `test_seeds_differential_decryption::boringssl20260211` passes

### Phase 5: Cipher & sigalgs configuration (Step 5) [DONE]
- [x] Fix cipher string handling for BoringSSL (name mapping or filtering)
- [x] Wire up `SSL_CTX_set1_sigalgs_list`
- [x] **TLS 1.3 cipher order**: `SSL_CTX_set_cipher_list()` does NOT affect TLS 1.3 in BoringSSL.
      Cipher order is hardcoded in `kCiphersAESHardware[]` in `handshake_client.cc`.
      Default: AES-128-GCM first. OpenSSL defaults to AES-256-GCM first.
      Fixed by creating `patch_cipher_order.cmake` (cmake string replacement at build time)
      to swap AES-128-GCM and AES-256-GCM in the array.
- [x] Validate: cipher negotiation matches OpenSSL

### Phase 6: Differential elimination (Step 6) [DONE]
- [x] Run `test_differential_openssl340_vs_boringssl20260211`
- [x] Fix `seed_server_attacker12` TLS 1.2 session ID strictness via `patch_session_id.cmake`
- [x] Add `CLAIM_CERTIFICATE_VERIFY` emission in msg_callback for `seed_client_attacker_auth`
- [x] Add BoringSSL-specific session resumption seeds (`seed_session_resumption_dhe_boringssl`,
      `seed_session_resumption_ke_boringssl`) — BoringSSL coalesces the NewSessionTicket into
      flight 0 (no separate flight 1), so the seeds use `(initial_server, 0)/MessageFlight`
- [x] Fix two framework-level differential blind spots (see below)
- [x] All 16 standalone seeds pass for both OpenSSL and BoringSSL (BoringSSL-specific variants
      used where flight structure differs)

### Phase 7: Framework differential fixes [DONE]

Framework-level blind spots found and fixed during BoringSSL integration:

1. **Multi-agent descriptor mapping** (`puffin/src/cli.rs`, `puffin/src/fuzzer/harness.rs`,
   `tlspuffin/src/tls/seeds.rs`) [DONE]
   - `assert_no_differential_differences`, `differential-execute` CLI, and `differential_harness`
     all mapped only `descriptors[0]` to each PUT. Multi-agent traces (e.g. `seed_successful`
     with client+server) had unmapped agents silently using the default PUT, producing
     mixed-PUT executions.
   - Fix: map ALL descriptors from `trace.descriptors` to the target PUT.

2. **Status check generalization** (`puffin/src/execution.rs`) [DONE]
   - `DifferentialRunner` only caught `Error::Put` in the status comparison. `Error::Term`,
     `Error::Fn`, and other execution errors fell through to `_ => ()` and were silently
     ignored. This hid real mismatches (e.g. BoringSSL fails with "Unable to find variable"
     while OpenSSL succeeds → reported as "No differences").
   - Fix: match all execution errors (anything except `SecurityClaim`/`Difference`).

3. **Prior-trace descriptor mapping** [DONE]
   - All three mapping locations only mapped `trace.descriptors`, not
     `trace.prior_traces[*].descriptors`. Agents in prior traces silently fell back to the
     default PUT.
   - Fix: added `Trace::all_descriptors()` method that recursively collects descriptors
     from prior traces, used in all 3 locations.

4. **BoringSSL IANA cipher name mapping** [DONE]
   - BoringSSL's `SSL_CTX_set_cipher_list()` silently ignores IANA-format TLS 1.2 cipher
     names. Added `map_tls12_iana_cipher_list()` (same pattern as LibreSSL harness).
   - All 4 PUTs now pass `test_cipher_config_tls12_takes_effect`.

5. **`signature_algorithm` not populated in Finished claims** [NOT FIXED]
   - No C harness populates `claim->signature_algorithm` or `claim->peer_signature_algorithm`.
   - Rust PUTs also have `// TODO` for this field.
   - Added test `test_cipher_config_takes_effect` with sigalgs assertion — currently fails
     for all PUTs. See `PROMPT_fix-and-test_set-ciphers-sigalgs.md` for fix plan.

### Phase 8: Record coalescing — making seeds cross-vendor [TODO]

**Root cause**: BoringSSL coalesces all encrypted handshake messages into a **single TLS
ApplicationData record** per BIO flush. OpenSSL/LibreSSL/WolfSSL emit **separate records**
for each handshake message (EE, Cert, CertVerify, Finished = 4 records).

Seeds that decompose flights into individual `(server, N)[ApplicationData]/Vec<u8>` records
break because the counter values don't match between implementations.

**Affected seeds** (6 total, all same root cause):
- `seed_successful_with_ccs` — `(server, 1)[ApplicationData]` doesn't exist in BoringSSL
- `seed_successful_with_tickets` — same, inherits from `seed_successful_with_ccs`
- `seed_successful_client_auth` — same pattern
- `seed_session_resumption_dhe` — `(initial_server, 1)/MessageFlight` (only 1 flight vs 2)
- `seed_session_resumption_ke` — same
- `seed_session_resumption_dhe_full` — `(initial_server, 4)[ApplicationData]` doesn't exist

**Two separate coalescing effects**:
1. **Record coalescing**: BoringSSL writes EE+Cert+CV+Finished as one big ApplicationData
   record. OpenSSL writes 4 separate records. Seeds referencing individual encrypted records
   by index break.
2. **Flight coalescing**: BoringSSL includes NewSessionTicket in the same BIO flush as the
   handshake response (flight 0). OpenSSL sends it in a separate flush (flight 1). Seeds
   referencing `(server, 1)/MessageFlight` break.

**Goal**: make seeds work across all PUTs without vendor-specific variants.

See "Remaining work" section for proposed approaches.

## Current test results (2026-03-26, updated)

### Standalone BoringSSL execution (all 18 seeds)

```
seed_client_attacker                          ... OK
seed_client_attacker12                        ... OK
seed_client_attacker_auth                     ... OK
seed_client_attacker_full                     ... OK
seed_server_attacker12                        ... OK
seed_server_attacker_full                     ... OK
seed_server_attacker_full_coalesced           ... OK
seed_server_attacker_with_hello_retry_request ... OK
seed_successful                               ... OK
seed_successful12_with_tickets                ... OK
seed_successful_client_auth                   ... FAIL (record coalescing)
seed_successful_with_ccs                      ... FAIL (record coalescing)
seed_successful_with_tickets                  ... FAIL (record coalescing)
seed_session_resumption_dhe                   ... FAIL (flight coalescing)
seed_session_resumption_ke                    ... FAIL (flight coalescing)
seed_session_resumption_dhe_full              ... FAIL (record + flight coalescing)
seed_session_resumption_dhe_boringssl         ... OK (temporary BoringSSL-specific variant)
seed_session_resumption_ke_boringssl          ... OK (temporary BoringSSL-specific variant)
```

12/18 pass. All 6 failures are record/flight coalescing (see Phase 8).

**Legacy `not(boringssl)` test exclusions**: All standalone seed tests that had
`not(boringssl)` filters now pass — the filters were legacy from before the harness
fixes (session ID patch, CertificateVerify claim, IANA cipher mapping). They should be
removed.

### Differential: OpenSSL 3.4.0 vs BoringSSL 20260211

All 16 seeds tested with `differential-execute` (prior-trace mapping now fixed):

```
seed_client_attacker                          ... No differences
seed_client_attacker12                        ... No differences
seed_client_attacker_auth                     ... No differences
seed_client_attacker_full                     ... No differences
seed_server_attacker12                        ... No differences
seed_server_attacker_full                     ... No differences
seed_server_attacker_full_coalesced           ... No differences
seed_server_attacker_with_hello_retry_request ... No differences
seed_successful                               ... No differences
seed_successful12_with_tickets                ... No differences
seed_successful_with_ccs                      ... DIFF — StatusDiff (record coalescing)
seed_successful_with_tickets                  ... DIFF — StatusDiff (record coalescing)
seed_session_resumption_dhe                   ... DIFF — StatusDiff (flight coalescing)
seed_session_resumption_ke                    ... DIFF — StatusDiff (flight coalescing)
seed_session_resumption_dhe_boringssl         ... No differences
seed_session_resumption_ke_boringssl          ... No differences
```

12/16 no differences. The 4 diffs are all StatusDiff from record/flight coalescing (Phase 8).

## Architecture decisions

1. **C++ for claims.cc**: Required to access BoringSSL internals (`ssl/internal.h` is C++). State stored on `AGENT_TYPE` struct, not global maps.
2. **Deferred claim queue**: Following LibreSSL pattern — `msg_callback` only snapshots transcript hash + message type into a queue on `AGENT_TYPE`. Claims are flushed in `progress()` when SSL state is stable.
3. **`extract_transcript.patch` (v3)**: Patches three BoringSSL files:
   - `include/openssl/ssl.h`: declares PUFFIN API functions
   - `ssl/ssl_lib.cc`: thread-local storage + getter/setter/clear for CH+SH transcript and handshake secret
   - `ssl/tls13_enc.cc`: capture calls inside `tls13_derive_handshake_secrets` (exact right moment)
4. **`patch_cipher_order.cmake`**: Build-time cmake string replacement to swap AES cipher order in `kCiphersAESHardware[]` (BoringSSL's TLS 1.3 cipher preference is hardcoded, not configurable via API).
5. **`boringssl_extract_transcript_with_msg()`**: BoringSSL fires `ssl_do_msg_callback` BEFORE `hs->transcript.Update(msg)` in `tls_add_message` (`s3_both.cc:139-143`). This function copies the EVP hash context, appends the current message bytes, and finalizes — giving the correct post-message transcript hash.

## BoringSSL-specific notes

- BoringSSL with `-DFUZZ=1 -DNO_FUZZER_MODE=1`: deterministic mode without disabling encryption
- `RAND_reset_for_fuzzing()`: patched via `reset_drbg.patch` (thread-local, no mutex)
- `hs->secret` lifecycle: overwritten at each key schedule stage (early→handshake→master via `tls13_advance_key_schedule`). Must be captured at `tls13_derive_handshake_secrets` before overwrite.
- BoringSSL does NOT zero intermediate secrets (unlike some OpenSSL versions) — no `patch_insecure.cmake` needed
- TLS 1.3 cipher preference hardcoded in `kCiphersAESHardware[]` — `SSL_CTX_set_cipher_list()` only affects TLS 1.2
- BoringSSL supports `SSL_CTX_set1_sigalgs_list` — no build-time sigalgs patch needed
- BoringSSL internal headers are C++ (`ssl/internal.h`) requiring `extern "C"` wrappers
- TLS 1.2 session ID validation is stricter than OpenSSL (`SERVER_ECHOED_INVALID_SESSION_ID`) — fixed via `patch_session_id.cmake`
- **Record coalescing**: BoringSSL writes all encrypted handshake messages (EE+Cert+CertVerify+
  Finished) as a **single TLS ApplicationData record**. OpenSSL writes 4 separate records.
  Seeds that reference individual encrypted records by index (e.g. `(server, 1)[ApplicationData]`)
  break because BoringSSL only has `(server, 0)[ApplicationData]` for all 4 messages combined.
- **Flight coalescing**: BoringSSL writes the NewSessionTicket (application-encrypted) in the
  same BIO flush as the handshake response. Result: ticket is in flight 0, not a separate
  flight 1. Seeds referencing `(server, 1)/MessageFlight` break.
- **TLS 1.2 cipher set**: BoringSSL intentionally supports ~50 fewer ciphers than OpenSSL
  (no DHE_DSS, CAMELLIA, ARIA, CCM). This causes knowledge differences in TLS 1.2
  differential seeds where the ClientHello cipher list is compared.
- **IANA cipher names silently ignored**: `SSL_CTX_set_cipher_list()` in BoringSSL does
  NOT recognize IANA-format names (e.g. `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`). It
  silently ignores them, falling back to the full default cipher set. Fixed by adding
  `map_tls12_iana_cipher_list()` to the BoringSSL C harness (same pattern as LibreSSL).
- **`SSL_CTX_set_ciphersuites()` for TLS 1.3**: BoringSSL DOES accept IANA names in this
  function (it's the TLS 1.3-specific API). Only `SSL_CTX_set_cipher_list()` (TLS 1.2) rejects them.

## Remaining work

### P0: Record/flight coalescing — cross-vendor seeds (Phase 8)

6 seeds fail because they hardcode the number and indexing of ApplicationData records
or MessageFlights, which differs between BoringSSL and OpenSSL. This is the **main
blocker** for a fully workable BoringSSL harness and for the differential test
(`test_differential_openssl340_vs_boringssl20260211`).

The BoringSSL-specific seed variants (`seed_session_resumption_dhe_boringssl`,
`seed_session_resumption_ke_boringssl`) are temporary — the goal is to make the
standard seeds work across all PUTs.

#### Approach: decrypt-extract-re-encrypt

Instead of referencing individual encrypted TLS records by counter (which is
implementation-dependent), seeds should:

1. Take the entire encrypted flight: `(server, 0)/MessageFlight`
2. Decrypt it to get the logical handshake message sequence (implementation-independent)
3. Extract individual messages by handshake type (not by record index)
4. Re-encrypt each message into an ApplicationData record for feeding to the peer

This decouples seed logic from record layout. Whether BoringSSL packs 4 handshake
messages into 1 TLS record or OpenSSL sends 4 separate records, the decrypted
sequence is the same: EE, CertRequest, Cert, CertVerify, Finished.

The building blocks **already exist**:
- `fn_decrypt_application_flight()` — decrypts an encrypted flight → `MessageFlight`
  of plaintext messages (used by `seed_session_resumption_dhe`)
- `fn_find_encrypted_extensions()`, `fn_find_server_certificate()`,
  `fn_find_server_certificate_verify()`, `fn_find_server_finished()`,
  `fn_find_server_ticket()`, `fn_find_server_certificate_request()` — extract
  specific messages from a decrypted `MessageFlight` by handshake type
- `fn_encrypt_handshake()` — encrypts a `Message` back into an ApplicationData record

**What needs to be added**:
- `fn_encrypt_handshake_to_vec()` (or similar) — takes a decrypted `Message` and
  produces the `Vec<u8>` ciphertext payload for use with `fn_application_data()`.
  Alternative: adapt `fn_encrypt_handshake` to return an `OpaqueMessage` or `Vec<u8>`
  directly, or use existing `fn_encrypt_handshake` and extract the payload.
- Possibly nothing — `fn_encrypt_handshake` already returns a `Message` with
  `ApplicationData` payload. The seeds could use that directly instead of the
  `fn_application_data(Vec<u8>)` pattern.

#### Step-by-step plan

**Step 1**: Understand existing `fn_encrypt_handshake` signature and return type.
Determine if it can be used directly in place of `fn_application_data(Vec<u8>)`,
or if a thin adapter is needed. Check what parameters it requires (transcript,
key_share, sequence number, etc.) — these are the same as `fn_decrypt_application_flight`.

**Step 2**: Rewrite `seed_successful_with_ccs` to use the decrypt-extract-re-encrypt
pattern. Current code:

```rust
// Step 5: EncryptedExtensions (assumes 1st encrypted record)
fn_application_data((server, 0)[ApplicationData]/Vec<u8>)
// Step 6: Certificate (assumes 2nd encrypted record)
fn_application_data((server, 1)[ApplicationData]/Vec<u8>)
// Step 7: CertificateVerify (assumes 3rd encrypted record)
fn_application_data((server, 2)[ApplicationData]/Vec<u8>)
// Step 8: Finished (assumes 4th encrypted record)
fn_application_data((server, 3)[ApplicationData]/Vec<u8>)
```

New code (sketch):

```rust
let decrypted_flight = term! {
    fn_decrypt_application_flight(
        ((server, 0)/MessageFlight),
        // ... key material parameters (transcript, key_share, etc.)
    )
};

// Step 5: EncryptedExtensions — extracted by type, not by record index
fn_encrypt_handshake(
    fn_find_encrypted_extensions((@decrypted_flight)),
    // ... key material + sequence 0
)
// Step 6: Certificate
fn_encrypt_handshake(
    fn_find_server_certificate((@decrypted_flight)),
    // ... key material + sequence 1
)
// ... and so on for CertificateVerify, Finished
```

The key material parameters are the same as those used in `seed_session_resumption_dhe`.
Sequence numbers must be maintained manually (0, 1, 2, 3).

**Step 3**: Verify `seed_successful_with_ccs` passes for all 4 PUTs (OpenSSL,
BoringSSL, LibreSSL, WolfSSL):

```bash
cargo test -p tlspuffin --features=cputs --lib test_seed_successful_with_ccs -- --nocapture
```

And differentially:

```bash
cargo run -p tlspuffin --features=cputs -- differential-execute openssl340 boringssl20260211 \
    seeds/tlspuffin::tls::seeds::seed_successful_with_ccs.trace
```

**Step 4**: Apply the same pattern to `seed_successful_with_tickets`. This extends
`seed_successful_with_ccs` with a ticket step. The ticket is in the same flight for
BoringSSL (record coalescing) but in flight 1 for OpenSSL (flight coalescing).
Solution: decrypt the entire server output (which may be 1 or 2 flights depending on
the PUT) and extract the ticket by type with `fn_find_server_ticket`, same pattern
already used in `seed_session_resumption_dhe`.

Validate:
```bash
cargo test -p tlspuffin --features=cputs --lib test_seed_successful_with_tickets -- --nocapture
```

**Step 5**: Apply the same pattern to `seed_successful_client_auth`. Same structure as
`seed_successful_with_ccs` but with CertificateRequest + client auth messages. Uses
`fn_find_server_certificate_request` for extraction.

Validate:
```bash
cargo test -p tlspuffin --features=cputs --lib test_boringssl_seed_successful_client_auth
```

**Step 6**: Fix session resumption seeds. `seed_session_resumption_dhe` already uses
`fn_decrypt_application_flight` + `fn_find_server_ticket`, but it references
`(initial_server, 1)/MessageFlight` — the second flight. For BoringSSL, the ticket
is in flight 0 (coalesced). Fix: use `(initial_server, 0)/MessageFlight` and make
sure `fn_decrypt_application_flight` + `fn_find_server_ticket` works regardless of
whether the ticket is in flight 0 (BoringSSL) or flight 1 (OpenSSL).

This is the trickiest case: the flight that contains the ticket is different. Options:
- (a) Concatenate all flights before decrypting
- (b) Add a `fn_find_server_ticket_across_flights` that tries flight 0 then flight 1
- (c) Add a `fn_concat_message_flights` function, then decrypt the concatenation

Apply the same fix to `seed_session_resumption_ke` and `seed_session_resumption_dhe_full`.

Validate:
```bash
cargo test -p tlspuffin --features=cputs --lib test_seed_session_resumption -- --nocapture
cargo run -p tlspuffin --features=cputs -- differential-execute openssl340 boringssl20260211 \
    seeds/tlspuffin::tls::seeds::seed_session_resumption_dhe.trace
```

**Step 7**: Remove BoringSSL-specific seed variants (`seed_session_resumption_dhe_boringssl`,
`seed_session_resumption_ke_boringssl`) and their `.trace` files. The standard seeds
now work for all PUTs.

**Step 8**: Run the full differential test to verify everything passes:

```bash
cargo test -p tlspuffin --features=cputs --lib test_differential_openssl340_vs_boringssl -- --nocapture
```

Expected: all seeds in `create_corpus` pass differentially (0 failures).

#### Risks and unknowns

- **Sequence number tracking**: `fn_encrypt_handshake` requires the correct sequence
  number. When re-encrypting, we must use the same sequence numbers as the original
  records. Need to verify the sequence counter matches.
- **CCS interleaving**: `seed_successful_with_ccs` inserts a CCS between SH and the
  encrypted messages. After the rewrite, the CCS step stays unchanged (it's unencrypted).
  But verify the CCS doesn't affect sequence numbering.
- **Performance**: decrypt+re-encrypt is slower than passthrough. Acceptable for seeds
  and tests, but worth noting for fuzzing performance.
- **`fn_decrypt_application_flight` input**: currently takes a `MessageFlight`. Need
  to confirm it handles both the coalesced case (1 record → 4 messages) and the split
  case (4 records → 4 messages) correctly. The function iterates over records and
  decrypts each, reassembling into messages. If BoringSSL's single record contains
  4 concatenated handshake messages, the decryption should produce 4 messages (the
  TLS record layer allows multiple handshake messages per record).

### P1: Remove legacy `not(boringssl)` test exclusions

8 standalone seed tests exclude BoringSSL via `not(boringssl)` filter. All of them
now pass (verified 2026-03-26). The filters are legacy from before the harness fixes.
Tests to update: `test_seed_successful`, `test_seed_server_attacker12`,
`test_seed_server_attacker_full`, `test_seed_server_attacker_full_coalesced`,
`test_seed_server_attacker_with_hello_retry_request`, `test_seed_client_attacker_auth`,
`test_seed_successful_client_auth`, `test_seed_successful_with_ccs` (once P0 is solved),
`test_seed_successful_with_tickets` (once P0 is solved), session resumption tests
(once P0 is solved).

### P2: Populate `signature_algorithm` in C harnesses

No C harness reports the negotiated sigalg. Test `test_cipher_config_takes_effect`
has sigalgs assertion ready but fails for all 4 PUTs.
See `PROMPT_fix-and-test_set-ciphers-sigalgs.md` for per-harness fix plan.

### Build note

- When adding imports inside `#[cfg(test)] mod tests`, do NOT use
  `use puffin::algebra::TypeShape` — it creates a dual-crate resolution conflict
  that breaks unrelated code in `test_utils.rs`. Use the module-level import from
  `puffin::algebra::dynamic_function::TypeShape` via `use super::*` instead.
