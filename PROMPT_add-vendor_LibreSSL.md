# Prompt: Add a New TLS Vendor with Differential Fuzzing Support

## Goal

Add a new TLS vendor (e.g., `<VENDOR_NAME>` version `<VERSION>`) to the tlspuffin fuzzer. This involves two intertwined tasks:

1. **Build and integrate the vendor library**: set up the build system (`builder.cmake`, `presets.toml`), compile the vendor as a static library with sanitizer instrumentation, and make it available to the fuzzer.

2. **Write a C harness** (`put.c`) that wraps the vendor's TLS API behind the generic `TLS_PUT_INTERFACE` expected by the framework. The harness creates SSL contexts, drives handshakes via memory BIOs, and — critically — extracts internal state (security claims: secrets, transcript hashes, cipher choices) that the fuzzer uses for differential comparison and decryption of encrypted flights.

The end-to-end success criterion: running `cargo run -p tlspuffin --features=cputs -- differential-execute openssl340 <vendor_id> seeds/*.trace` on all seed traces produces **no false-positive differences**. This means the new vendor can participate in differential fuzzing alongside existing PUTs (OpenSSL, WolfSSL, etc.).

Example: we did so for Libressl421 in PR#468, see diff: `git diff origin/tls-agent-support-multiple-versions..origin/pr/c-harness-libressl-clean`.

## Background

This project (tlspuffin/DDYF) does **Differential Dolev-Yao Fuzzing** of cryptographic protocol implementations. It executes the same symbolic DY trace on two TLS implementations (PUTs — Programs Under Test), compares their outputs (execution status, knowledge stores from parsed messages, claims from internal state), and flags meaningful differences. Adding a new vendor means writing the glue code (the C harness) that lets the fuzzer drive that vendor's TLS stack and observe its internal state — so that it can be compared against another vendor running the same protocol trace.

The key challenge is eliminating **false positives** — benign differences between implementations that don't indicate bugs — without being **too loose** (hiding real differences). The paper's philosophy (Section 4.2): use targeted, fine-grained mechanisms, not broad suppression. Prefer fixing root causes (e.g., aligning PUT configurations) over filtering differences.

## Architecture Overview

### Key files and their roles

| File | Role |
|------|------|
| `puffin-build/vendors/<vendor>/` | Build system: `builder.cmake`, `presets.toml`, patches |
| `tlspuffin/harness/<vendor>/src/put.c` | C harness: creates SSL contexts, configures ciphers/groups/sigalgs, extracts claims |
| `tlspuffin/harness/<vendor>/src/bindings.c` | Helper functions: cert/key loading, error handling, BIO compat |
| `tlspuffin/harness/<vendor>/src/rng.c` | RNG override for deterministic execution |
| `tlspuffin/include/puffin/tls.h` | C header defining `TLS_AGENT_DESCRIPTOR` struct passed to PUT harnesses |
| `tlspuffin/src/put.rs` | Rust-to-C bridge: `make_descriptor()` converts Rust config to C struct |
| `tlspuffin/src/put_registry.rs` | PUT registration: auto-generated from build system, discovers available PUTs |
| `tlspuffin/src/claims.rs` | Claim types and extraction helpers shared across PUTs |
| `tlspuffin/src/protocol.rs` | TLS protocol types, `MessageFlight::extract_knowledge`, `TLSDescriptorConfig`, `differential_fuzzing_uniformise_put_config`, `differential_fuzzing_filter_diff`, `differential_fuzzing_decryption_terms` |
| `tlspuffin/src/tls/rustls/msgs/handshake.rs` | TLS message structs with `#[comparable_ignore]` / `#[comparable_synthetic]` annotations for differential comparison |
| `puffin/src/trace.rs` | `TraceContext::compare()` — executes decryption recipes, compares knowledge stores |
| `puffin/src/differential.rs` | `TraceDifference`, `KnowledgeDiff` enums |
| `puffin/src/protocol.rs` | `filter_knowledge`, `find_differences` — generic comparison logic |

### How differential comparison works

1. Both PUTs execute the same trace
2. Each PUT's output messages are parsed into **knowledge stores** (structured message fields)
3. **Decryption recipes** decrypt encrypted flights using keys extracted from PUT claims
4. Knowledge stores are compared element-by-element; shorter stores are padded with `()`
5. Differences are filtered through `differential_fuzzing_filter_diff`

### Configuration alignment flow

`differential_fuzzing_uniformise_put_config` in `protocol.rs` sets common parameters:

- Cipher suites (TLS 1.2 and 1.3)
- Groups/curves
- Signature algorithms

These propagate: `TLSDescriptorConfig` -> `TLS_AGENT_DESCRIPTOR` (C struct) -> harness `put.c` -> vendor API calls.

---

## Critical Rule: Minimize Non-Vendor Changes

**Adding a new vendor should require changes ONLY inside the vendor's own files.** Changing `puffin/` (the generic framework) is forbidden. Changing `tlspuffin/src/protocol.rs`, `tlspuffin/src/put.rs`, `tlspuffin/include/puffin/tls.h`, or other cross-vendor code should be avoided except when strongly motivated and after gaining the user's explicit consent.

**Why this matters:** During the LibreSSL 4.2.1 integration, we ended up modifying 31 files across the codebase — including protocol.rs, handshake.rs, put.rs, tls.h, execution.rs, wolfssl code, openssl code, and build infrastructure. Many of these changes were either:
- **Pre-existing issues** surfaced by testing on macOS (ASAN linking, Nix env, archiver compat) — unrelated to the vendor itself
- **Feature additions** (sigalgs support) that were worthwhile but could have been scoped as a separate PR
- **Compatibility workarounds** (CCS middlebox, ExtendedMasterSecretAck) that were necessary but should be carefully isolated

The ideal outcome: a PR that touches `puffin-build/vendors/<vendor>/`, `tlspuffin/harness/<vendor>/`, and minimal test/CI additions — nothing else.

**If you find yourself needing to modify cross-vendor code:**
1. Stop and ask: "Is this a pre-existing bug/limitation, or truly vendor-specific?"
2. If pre-existing: file it as a separate task/PR
3. If truly needed: explain to the user what change is required and why, get explicit consent
4. Keep the change minimal and document why it was necessary

---

## Step-by-Step Procedure

### Step 0: Build system and vendor preset

Create the build configuration for the new vendor.

**Files to create/modify:**

- `puffin-build/vendors/<vendor>/presets.toml` — define vendor presets:

```toml
[vendor_id-asan]
sources = { repo = "https://github.com/tlspuffin/<vendor>.git", branch = "fuzz-v<VERSION>", version = "<VERSION>" }
builder = { type = "builtin", name = "<vendor>" }
asan = true
sancov = true

[vendor_id]
sources = { repo = "https://github.com/tlspuffin/<vendor>.git", branch = "fuzz-v<VERSION>", version = "<VERSION>" }
builder = { type = "builtin", name = "<vendor>" }
sancov = true
```

- `puffin-build/vendors/<vendor>/builder.cmake` — build configuration. Start minimal:

```cmake
use_languages(C)

# Patch RNG for deterministic execution
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy
  "${CMAKE_CURRENT_LIST_DIR}/arc4random_prng.c"
  "<SOURCE_DIR>/crypto/compat/arc4random.c")

# Build system (cmake_builder or autotools_builder depending on vendor)
cmake_builder(
  CMAKE_FLAGS
    -DBUILD_SHARED_LIBS=OFF
    -D<VENDOR>_TESTS=OFF
  CFLAGS
    -g -fPIC -fvisibility=hidden
    -I${CMAKE_SOURCE_DIR}/../../tlspuffin-claims
    $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>
    $<$<BOOL:${asan}>:-fsanitize=address>
    $<$<BOOL:${asan}>:-static-libsan>
)

# Feature flags — start with what you can validate, add more later
set(tls12 yes)
set(tls13 yes)
```

- `.github/tlspuffin.matrix.json` — add the new vendor to the CI build matrix

**Build and validate:**

```bash
./tools/mk_vendor make <vendor>:<vendor_id>
cargo build --release --bin=tlspuffin --features=cputs
```

### Step 1: First harness — no claims, basic execution

**Goal:** Successfully execute all seed traces against the new vendor. No claims, no differential comparison yet.

**Files to create:**
- `tlspuffin/harness/<vendor>/src/put.c` — main harness
- `tlspuffin/harness/<vendor>/src/bindings.c` — cert/key loading, error helpers
- `tlspuffin/harness/<vendor>/include/bindings.h` — header for bindings
- `tlspuffin/harness/<vendor>/src/rng.c` — RNG override
- `tlspuffin/harness/<vendor>/include/rng.h` — header for RNG

**Use the OpenSSL harness as a template** (`tlspuffin/harness/openssl/src/put.c`). Key components:

1. **Agent creation** (`create_client`, `create_server`):
   - Create `SSL_CTX` with appropriate method (`TLS_method()`)
   - Set TLS version min/max based on `descriptor->tls_version`
   - Set certificates, private keys, and trust store
   - Set up memory BIOs for I/O
   - For now: skip ciphers/groups/sigalgs configuration (use vendor defaults)
   - For now: set the `CLAIMER_CB` to a no-op or leave it `NULL`

2. **PUT interface**: Implement `REGISTER()` returning a `TLS_PUT_INTERFACE` struct with function pointers for `create`, `rng_reseed`, `supports`, and the agent interface (`progress`, `reset`, `shutdown`, `descriptor`).

3. **Default groups**: Constrain to `"X25519:P-256:P-384"` when no config given — many vendors offer non-standard or post-quantum groups by default that the fuzzer's Rust message parser doesn't support.

**Validation:**

```bash
# Execute each seed individually and check for successful execution
cargo run -p tlspuffin --features=cputs -- --put <vendor_id> execute seeds/tlspuffin::tls::seeds::seed_successful.trace
cargo run -p tlspuffin --features=cputs -- --put <vendor_id> execute seeds/tlspuffin::tls::seeds::seed_client_attacker.trace
# ... all seeds

# Inspect output in detail
cargo run -p tlspuffin --features=cputs -- --put <vendor_id> display-execute -tckp seeds/tlspuffin::tls::seeds::seed_successful.trace
```

**Relevant unit tests:**

```bash
# Run the basic seed execution tests for the new vendor
cargo test -p tlspuffin --features=cputs -- test_seed_successful::<vendor_id>
cargo test -p tlspuffin --features=cputs -- test_seed_client_attacker::<vendor_id>
```

**Vendor-specific quirks found during LibreSSL integration:**
- LibreSSL internal headers require `__BEGIN_HIDDEN_DECLS` / `__END_HIDDEN_DECLS` macros to be defined as empty before inclusion
- Default groups may include non-standard curves; always constrain with `SSL_CTX_set1_groups_list`
- BIO and error handling may differ subtly from OpenSSL — test `bindings.c` carefully

### Step 2: Add security claims

**Goal:** The harness emits `SecurityClaim` structs via the `CLAIMER_CB` callback during handshake progress. These claims capture the internal state needed for differential comparison.

**Approach:** Use `msg_callback` (or equivalent) to intercept handshake messages and emit claims. For OpenSSL-API-compatible libraries, `SSL_CTX_set_msg_callback` works. For others, you may need a vendor-specific interception mechanism.

**Claims to emit at this stage:**
- `CLAIM_TLS_VERSION` — negotiated TLS version
- `CLAIM_PEER_CERTIFICATE` — peer certificate received
- `CLAIM_PEER_CERTIFICATE_CHAIN` — full certificate chain
- `CLAIM_HANDSHAKE` / `CLAIM_ALERT` — raw handshake/alert messages (for knowledge extraction)

The `fill_claim` function populates a `SecurityClaim` struct. Required fields:
- `protocol_version`, `peer_authentication`
- `server_key_exchange.group` — negotiated key exchange group
- `master_secret` (TLS 1.2) or empty placeholder (TLS 1.3, populated in Step 4)
- `server_random`, `client_random`
- `chosen_cipher` — must be IANA cipher suite ID (not vendor-internal name)

**If the vendor uses different cipher names than IANA/OpenSSL:**
LibreSSL uses IANA names (e.g., `TLS_AES_256_GCM_SHA384`) while the framework uses OpenSSL names. You'll need a mapping table. This mapping is vendor-specific and belongs entirely in `put.c` — do NOT add it to shared code.

**Validation:**

```bash
# Check that claims are being emitted
cargo run -p tlspuffin --features=cputs -- --put <vendor_id> display-execute -tckp seeds/tlspuffin::tls::seeds::seed_successful.trace
# Look for claim output lines — verify protocol_version, cipher, master_secret fields
```

**Relevant unit tests:**

```bash
# Tests that verify claims are populated
cargo test -p tlspuffin --features=cputs -- test_seed_successful::<vendor_id>
# Check that the harness catches SecurityClaims on single PUT
```

### Step 3: Add transcript hash claims

**Goal:** Emit transcript hash claims at key protocol stages. These are needed for decryption recipes.

**What to add in `put.c`:**
- `CLAIM_TRANSCRIPT_CH` — hash after ClientHello
- `CLAIM_TRANSCRIPT_CH_SH` — hash after ServerHello
- `CLAIM_TRANSCRIPT_CH_SF` — hash after ServerFinished
- `CLAIM_TRANSCRIPT_CH_CF` — hash after ClientFinished (for client auth)

**This requires access to vendor internals** — the harness needs to read the transcript hash state from internal structures. This is why `builder.cmake` copies internal headers to the install prefix.

For LibreSSL, transcript hash extraction required:
- Including `<libressl_internal/ssl_local.h>` to access `ssl->s3->hs`
- Computing the hash by accessing the `EVP_MD_CTX` from the handshake context
- Handling edge cases: frozen transcript buffers in TLS 1.3, Hello Retry Request

**Update `builder.cmake`:**

```cmake
set(transcript_extraction yes)
set(client_authentication_transcript_extraction yes)
```

**Validation:**

```bash
# Verify transcript claims appear in output
cargo run -p tlspuffin --features=cputs -- --put <vendor_id> display-execute -tckp seeds/tlspuffin::tls::seeds::seed_successful.trace
# Look for CLAIM_TRANSCRIPT_* entries with non-zero hash values
```

**Relevant unit tests:**

```bash
# Tests specifically requiring transcript extraction
cargo test -p tlspuffin --features=cputs -- test_seed_successful::<vendor_id>
# Filtered tests that require transcript_extraction capability
cargo test -p tlspuffin --features=cputs -- test_seed_client_attacker_full::<vendor_id>
```

### Step 4: Add Finished claims with secret values for decryption

**Goal:** The `CLAIM_FINISHED` claim must include all secret values needed by decryption recipes. This enables the differential fuzzer to decrypt encrypted flights and compare plaintext contents.

**Required secret values in `CLAIM_FINISHED`:**

For TLS 1.3:
- `server_handshake_traffic_secret`
- `client_handshake_traffic_secret`
- `exporter_master_secret`
- `server_random`, `client_random` (cached from ServerHello/ClientHello)
- `chosen_cipher` (as IANA ID)

For TLS 1.2:
- `master_secret` (48 bytes)
- `server_random`, `client_random`
- `chosen_cipher`

**Common challenge: vendors zero intermediate secrets.** Many TLS libraries `explicit_bzero` intermediate key material after derivation for security. For fuzzing, we need those secrets preserved. Approach:
1. Check if the vendor zeros secrets after key schedule derivation
2. If yes, add a build-time patch (e.g., `patch_insecure.cmake` for LibreSSL):

```cmake
# Example: patch tls13_key_schedule.c to preserve secrets
file(READ "${FILE}" content)
string(REPLACE "secrets->init_done = 1;" "secrets->init_done = 1; secrets->insecure = 1;" content "${content}")
file(WRITE "${FILE}" "${content}")
```

**TLS 1.3 server_random caching:** In TLS 1.3, by the time `CLAIM_FINISHED` fires, the server random is needed but may not be directly accessible. Use `msg_callback` to cache the server random when the ServerHello message arrives:

```c
// In msg_callback, when processing ServerHello (server write):
memcpy(agent->cached_server_random, msg + 6, SSL3_RANDOM_SIZE);
```

**Validation:**

```bash
# Run the decryption-specific test
cargo test -p tlspuffin --features=cputs -- test_seeds_differential_decryption::<vendor_id>
```

This test runs 4 seed traces and verifies that at least one decryption term evaluates successfully for each. If it fails, the secrets are either missing, wrong, or the cipher ID doesn't match.

**Debugging decryption failures:**

```bash
# Compare claims between two PUTs to spot differences in secret values
cargo run -p tlspuffin --features=cputs -- --put openssl340 display-execute -tckp seeds/tlspuffin::tls::seeds::seed_successful.trace > /tmp/openssl_claims.txt
cargo run -p tlspuffin --features=cputs -- --put <vendor_id> display-execute -tckp seeds/tlspuffin::tls::seeds::seed_successful.trace > /tmp/vendor_claims.txt
diff /tmp/openssl_claims.txt /tmp/vendor_claims.txt
```

### Step 5: Add cipher and sigalgs configuration

**Goal:** The harness correctly consumes `cipher_string_tls12`, `cipher_string_tls13`, and `sigalgs_list` from the descriptor so that `differential_fuzzing_uniformise_put_config` can align all PUTs.

**Cipher configuration in `put.c`:**

```c
// TLS 1.3 ciphers
if (descriptor->cipher_string_tls13 != NULL) {
    SSL_CTX_set_ciphersuites(ssl_ctx, descriptor->cipher_string_tls13);
}
// TLS 1.2 ciphers
if (descriptor->cipher_string_tls12 != NULL) {
    SSL_CTX_set_cipher_list(ssl_ctx, descriptor->cipher_string_tls12);
}
```

**Cipher name mapping:** If the vendor uses different names than OpenSSL (e.g., LibreSSL uses IANA names), implement the mapping entirely within the vendor's `put.c`. Do NOT add mapping tables to shared code.

**Sigalgs configuration:**
- If the vendor supports `SSL_CTX_set1_sigalgs_list`: use it
- If NOT (like LibreSSL): add a no-op comment in `put.c` and consider a build-time patch to reorder the vendor's default sigalgs preference. For LibreSSL, this was `patch_sigalgs.cmake` which reorders the default list in `ssl_sigalgs.c` to put SHA256 first (matching OpenSSL's default).

**Update `builder.cmake`:**

```cmake
set(allow_setting_tls12_ciphers yes)
set(allow_setting_tls13_ciphers yes)
```

**Validation:**

```bash
# Run cipher-related tests
cargo test -p tlspuffin --features=cputs -- test_seed_successful::<vendor_id>

# Verify cipher negotiation matches between PUTs
cargo run -p tlspuffin --features=cputs -- --put openssl340 display-execute -tck seeds/tlspuffin::tls::seeds::seed_successful.trace 2>&1 | grep cipher
cargo run -p tlspuffin --features=cputs -- --put <vendor_id> display-execute -tck seeds/tlspuffin::tls::seeds::seed_successful.trace 2>&1 | grep cipher
```

### Step 6: Eliminate all differential differences

**Goal:** No false-positive differences on any seed trace when running differential comparison.

**Run the differential test:**

```bash
cargo test -p tlspuffin --features=cputs -- test_differential_openssl340_vs_<vendor_id>
```

Or manually:

```bash
for seed in seeds/*.trace; do
  echo "=== $(basename $seed) ==="
  cargo run -p tlspuffin --features=cputs -- differential-execute openssl340 <vendor_id> "$seed" 2>&1 | grep -E "^(No diff|Diff)"
done
```

**Common remaining differences and their fixes:**

| Difference | Cause | Fix | Where |
|-----------|-------|-----|-------|
| `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` in ClientHello | Vendor adds SCSV pseudo-cipher | Already filtered in `handshake.rs` `#[comparable_synthetic]` | Cross-vendor (existing) |
| `ExtendedMasterSecretAck` in ServerHello | Optional extension (RFC 7627) | Already filtered in `handshake.rs` `#[comparable_synthetic]` | Cross-vendor (existing) |
| `RenegotiationInfo` in ServerHello | Optional renegotiation extension | Already filtered in `handshake.rs` | Cross-vendor (existing) |
| `ChangeCipherSpec` in TLS 1.3 flights | Middlebox compatibility | Already filtered in `extract_knowledge` (protocol.rs) | Cross-vendor (existing) |
| `DigitallySignedStruct.scheme` | Different sigalgs preference | Configure sigalgs (Step 5) or build-time patch | Vendor `put.c` or `patch_sigalgs.cmake` |
| Extra `ApplicationData` records | Different number of `NewSessionTickets` | Handled by `differential_fuzzing_whitelist` + `DifferentTypes` filter | Cross-vendor (existing) |
| Decryption asymmetry | One PUT decrypts, other doesn't | Fix secrets in Step 4. Asymmetric case is handled by existing trace comparison. | Vendor `put.c` |

**If you discover a new difference type:**

1. **Is it already handled by existing filters?** Check `differential_fuzzing_filter_diff` in `protocol.rs` and `#[comparable_synthetic]` annotations in `handshake.rs`.
2. **Can you fix the root cause in the vendor harness?** E.g., align configuration, fix a claim value. This is always preferred.
3. **If you must modify cross-vendor code:** STOP. Explain to the user what change is needed and why. Get explicit consent. Prefer changes to `differential_fuzzing_filter_diff` over modifying comparison logic.
4. **NEVER modify `puffin/` code** (the generic framework) — it should be vendor-agnostic.

**Final validation:**

```bash
# All vendor-specific unit tests pass
cargo test -p tlspuffin --features=cputs -- ::<vendor_id>

# Differential decryption works
cargo test -p tlspuffin --features=cputs -- test_seeds_differential_decryption::<vendor_id>

# No differences on all seeds
cargo test -p tlspuffin --features=cputs -- test_differential_openssl340_vs_<vendor_id>

# Existing vendor diffs not regressed
cargo test -p tlspuffin --features=cputs -- test_differential_openssl340_vs_wolfssl540
```

---

## Anti-patterns to avoid

| Don't | Why | Do instead |
|-------|-----|------------|
| Modify `puffin/` framework code | Generic framework should be vendor-agnostic | Fix in vendor harness or `differential_fuzzing_filter_diff` |
| Modify `protocol.rs` without consent | High blast radius, affects all vendors | Ask user, explain motivation, get approval |
| Add new fields to `tls.h` / `put.rs` for a single vendor | Adds cross-vendor complexity | Use vendor-specific approach (build-time patch, config file) |
| `#[comparable_ignore]` on meaningful fields | Permanently removes from ALL comparisons | Use `#[comparable_synthetic]` or `differential_fuzzing_filter_diff` |
| Filter all `MessagePayload` vs `()` broadly | Hides cases where one PUT sends extra handshake messages | Filter by source (`Source::Agent` or `Source::Label("Decryption")`) |
| Filter `ApplicationData` in `extract_knowledge` | Breaks DY model tests (attacker needs `ApplicationData` knowledge) | Handle count differences in comparison/filter layer |
| Broad string-match filters | May match unintended diffs | Use the most specific match string possible |
| Bundle platform fixes with vendor work | Inflates the PR, hard to review | Separate macOS/Nix/toolchain fixes into their own PR |

---

## Key principle

From the paper (Section 4.2): *"This requires particular care and fine-grained control to avoid introducing blind spots in our oracle and miss bugs."* Every filter should be:

1. **Targeted**: match the specific benign difference, not a broad category
2. **Documented**: explain WHY the difference is benign
3. **Verified**: confirm it doesn't hide meaningful differences in other seeds

---

## Lessons Learned from LibreSSL 4.2.1 Integration

### What worked well

1. **Incremental approach**: Building the harness step by step (basic execution -> claims -> transcript -> decryption -> ciphers -> differential) made debugging tractable. Each step had clear validation criteria.

2. **Using OpenSSL harness as template**: LibreSSL's API is close enough to OpenSSL's that the template provided ~70% of the code. The remaining 30% was vendor-specific (cipher name mapping, internal header access patterns, msg_callback-based claims).

3. **Build-time patches instead of runtime workarounds**: `patch_insecure.cmake` and `patch_sigalgs.cmake` kept the harness code clean. Instead of complex runtime workarounds for missing APIs, we patched the source at build time.

4. **`msg_callback` for claims extraction**: For libraries without `register_claimer`-style hooks, `SSL_CTX_set_msg_callback` is a reliable alternative. It provides all handshake message bytes and can be used to build a claim queue.

5. **Dedicated unit tests per feature**: `test_seeds_differential_decryption` for decryption, `test_differential_openssl340_vs_<vendor>` for full differential — each validates a specific capability.

### What did NOT work well

1. **Too many cross-vendor changes**: The PR ended up touching 31 files, including protocol.rs, handshake.rs, put.rs, tls.h, execution.rs, wolfssl, and openssl harnesses. Many of these should have been separate PRs:
   - macOS compatibility (`.cargo/config.toml`, `shell.nix`, `CMakeLists.txt`, ASAN linking) — pure platform issues, not vendor-specific
   - Sigalgs support across all PUTs — a cross-vendor feature that happened to be discovered during LibreSSL work
   - CCS flight classification fix in protocol.rs — should be a one-line bugfix PR

2. **Iterative debugging led to scattered changes**: When differential tests failed, the natural instinct was to fix things wherever needed — adding a filter here, an import there. This resulted in small changes spread across many files. A better discipline: **always ask "can I fix this inside put.c?"** before touching anything else.

3. **Sigalgs as a cross-cutting concern**: LibreSSL lacks `SSL_CTX_set1_sigalgs_list`, which meant the sigalgs alignment had to be done at build time. But supporting sigalgs also required adding the field to `tls.h`, `put.rs`, `protocol.rs`, and all other harnesses. This is a legitimate cross-vendor change, but it should have been done as a **prerequisite PR** before the LibreSSL PR, not mixed in.

4. **Redundant test functions**: We initially created per-seed decryption tests (`test_seed_client_attacker_full_differential_decryption`, `test_seed_server_attacker_full_differential_decryption`) that were subsets of the comprehensive `test_seeds_differential_decryption`. The comprehensive test covering all 4 seeds was sufficient; the per-seed tests were removed during cleanup.

5. **Intermediate file states during rebase**: Because put.c was touched by 10 of 17 original commits, rebasing into logical groups required carefully reconstructing intermediate file states. Lesson: plan the commit structure BEFORE starting, and develop each feature on its own branch if possible.

### Vendor-specific issues encountered

- **Build system**: LibreSSL 4.x uses cmake (not autotools like 3.x). VERSION files must be created manually for the cmake build. The `.sym` files need stubs.
- **Secret preservation**: LibreSSL zeros intermediate TLS 1.3 secrets (`extracted_early`, `extracted_handshake`, `extracted_master`) after derivation. Patched via `secrets->insecure = 1` in `tls13_key_schedule.c`.
- **Internal headers**: Required `ssl_local.h`, `tls13_internal.h`, `tls_internal.h`, `tls12_internal.h`, `tls_content.h`, `bytestring.h` for claims extraction. Must define `__BEGIN_HIDDEN_DECLS` / `__END_HIDDEN_DECLS` as empty macros.
- **No sigalgs API**: LibreSSL lacks `SSL_CTX_set1_sigalgs_list`. Handled via `patch_sigalgs.cmake` (reorders default list at build time).
- **Cipher name mapping**: LibreSSL uses IANA cipher names, framework uses OpenSSL names. Required a ~325-line mapping table in `put.c` (function `iana_to_openssl_name`).
- **CCS middlebox compatibility**: LibreSSL sends dummy `ChangeCipherSpec` in TLS 1.3 flights.
- **Default groups**: LibreSSL may offer non-standard groups. Constrained to `"X25519:P-256:P-384"`.
- **No TLS 1.3 session resumption**: LibreSSL supports 0-RTT but not full TLS 1.3 session resumption. Set `tls13_session_resumption = no`.
- **Hello Retry Request handling**: TLS 1.3 HRR requires special-casing in transcript hash computation — the hash context carries a stale CH1 prefix that must be handled differently.
- **Cached randoms**: Server random must be cached from msg_callback during ServerHello processing, as it's needed later for `CLAIM_FINISHED` but not easily accessible at that point. Must be reset on `use_clear` path.

### Recommended PR structure for a new vendor

Instead of one large PR, split into:

1. **PR 1 (optional)**: Platform/toolchain fixes (if any discovered during development)
2. **PR 2 (optional)**: Cross-vendor feature additions (e.g., sigalgs support) as a prerequisite
3. **PR 3**: The vendor harness itself — should touch ONLY:
   - `puffin-build/vendors/<vendor>/` (new files)
   - `tlspuffin/harness/<vendor>/` (new files)
   - `.github/tlspuffin.matrix.json` (add vendor to CI)
   - `tlspuffin/Cargo.toml` / `Cargo.lock` (if new deps needed)
   - `tlspuffin/build.rs` (if build script needs vendor guard)
   - `tlspuffin/tests/traces.rs` (add vendor error patterns)
   - `tlspuffin/src/tls/seeds.rs` (add vendor-specific differential tests)
   - CI workflow additions
