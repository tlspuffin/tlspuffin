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

### Phase 0: Clean up ~~[DONE]~~
- [x] Delete hallucinated docs
- [x] Keep build infrastructure and cross-vendor changes
- [x] Rewrite harness files from scratch

### Phase 1: Basic execution — no claims (Step 1)
- [ ] Rewrite `put.c` with correct structure (deferred claim queue on AGENT_TYPE, msg_callback for queueing only)
- [ ] Rewrite `claims.cc` as stubs initially
- [ ] Fix cipher configuration for BoringSSL's supported cipher set
- [ ] Validate: all seeds execute without errors

### Phase 2: Basic security claims (Step 2)
- [ ] Implement `boringssl_fill_claim()` — version, randoms, cipher, session_id, certs, TLS 1.2 master secret
- [ ] Wire up deferred queue flush in `progress()` — emit claims when state is stable
- [ ] Validate: `display-execute -tckp` shows correct claim values

### Phase 3: Transcript hashes (Step 3)
- [ ] Fix `PUFFIN_extract_transcript` to handle uninitialized context gracefully
- [ ] Snapshot transcript hashes in msg_callback into deferred queue
- [ ] Handle CH+SH transcript via `PUFFIN_store_ch_sh_transcript` patch
- [ ] Validate: transcript claims show non-zero hashes

### Phase 4: Secrets for decryption (Step 4)
- [ ] Emit standalone `CLAIM_FINISHED` with all secrets before transcript claims
- [ ] TLS 1.3: handshake_secret, master_secret, exporter_master_secret, traffic secrets
- [ ] Cache server_random from ServerHello in msg_callback
- [ ] Validate: `test_seeds_differential_decryption::boringssl20260211`

### Phase 5: Cipher & sigalgs configuration (Step 5)
- [ ] Fix cipher string handling for BoringSSL (name mapping or filtering)
- [ ] Wire up `SSL_CTX_set1_sigalgs_list`
- [ ] Validate: cipher negotiation matches OpenSSL

### Phase 6: Differential elimination (Step 6)
- [ ] Run `test_differential_openssl340_vs_boringssl20260211`
- [ ] Debug and fix remaining differences
- [ ] Validate: all seeds pass differential comparison

## Architecture decisions

1. **C++ for claims.cc**: Required to access BoringSSL internals (`ssl/internal.h` is C++). State stored on `AGENT_TYPE` struct, not global maps.
2. **Deferred claim queue**: Following LibreSSL pattern — `msg_callback` only snapshots transcript hash + message type into a queue on `AGENT_TYPE`. Claims are flushed in `progress()` when SSL state is stable.
3. **`PUFFIN_store_ch_sh_transcript` patch**: Captures CH+SH transcript hash and handshake secret at the exact right moment in `tls13_derive_handshake_secrets`. State stored on `AGENT_TYPE` (passed to claims.cc via function parameter), not in a global map.

## BoringSSL-specific notes

- BoringSSL with `-DFUZZ=1 -DNO_FUZZER_MODE=1`: deterministic mode without disabling encryption
- `RAND_reset_for_fuzzing()`: patched via `reset_drbg.patch` (thread-local, no mutex)
- `PUFFIN_extract_transcript()`: patched via `extract_transcript.patch` — calls `hs->transcript.GetHash()`
- BoringSSL uses OpenSSL cipher names for TLS 1.2 but has a very limited TLS 1.3 cipher set (only 3 ciphers: AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305)
- BoringSSL supports `SSL_CTX_set1_sigalgs_list` — no need for build-time sigalgs patch
- BoringSSL internal headers are C++ (`ssl/internal.h`) requiring `extern "C"` wrappers
