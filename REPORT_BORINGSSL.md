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

### Phase 6: Differential elimination (Step 6) [IN PROGRESS]
- [x] Run `test_differential_openssl340_vs_boringssl20260211`
- [x] 7/8 BoringSSL tests pass (all TLS 1.3 seeds pass)
- [ ] Remaining: `seed_server_attacker12` fails with `SERVER_ECHOED_INVALID_SESSION_ID`
      — BoringSSL is stricter about TLS 1.2 session ID validation than OpenSSL

## Current test results (2026-03-25)

```
test_precomputations::boringssl20260211                        ... ok
test_seed_successful_mitm::boringssl20260211 - should panic    ... ok
test_trigger_alert::boringssl20260211                          ... ok
test_seed_client_attacker12::boringssl20260211                 ... ok
test_seed_client_attacker::boringssl20260211                   ... ok
test_seed_client_attacker_full::boringssl20260211              ... ok
test_seeds_differential_decryption::boringssl20260211          ... ok
test_differential_openssl340_vs_boringssl20260211              ... FAILED (seed_server_attacker12 only)
```

**7 passed, 1 failed** (TLS 1.2 session ID strictness — structural BoringSSL difference)

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
- TLS 1.2 session ID validation is stricter than OpenSSL (`SERVER_ECHOED_INVALID_SESSION_ID`)
