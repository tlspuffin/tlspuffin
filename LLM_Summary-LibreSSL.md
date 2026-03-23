# Prompt: Add Differential Fuzzing Support for a New TLS Vendor

## Goal

Add differential fuzzing support for a new TLS vendor (e.g., `<VENDOR_NAME>` version `<VERSION>`) against `openssl340` in tlspuffin. When running `cargo run -p tlspuffin --features=cputs -- differential-execute openssl340 <vendor_id> seeds/*.trace` on all seeds, there should be **no false-positive differences**.
Example: we did so for Libressl421 in PR#468, see diff: `git diff origin/tls-agent-support-multiple-versions..origin/pr/c-harness-libressl-clean`.

## Background

This project (tlspuffin/DDYF) does **Differential Dolev-Yao Fuzzing** of cryptographic protocol implementations. It executes the same symbolic DY trace on two TLS implementations (PUTs — Programs Under Test), compares their outputs (execution status, knowledge stores from parsed messages, claims from internal state), and flags meaningful differences.

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
| `tlspuffin/src/tls/rustls/msgs/handshake.rs` | TLS message structs with `#[comparable_ignore]` annotations for randomized fields |
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

These propagate: `TLSDescriptorConfig` → `TLS_AGENT_DESCRIPTOR` (C struct) → harness `put.c` → vendor API calls.

## Step-by-Step Procedure

### Step 0: Build system and vendor preset

Create the build configuration for the new vendor.

**Files to create/modify:**

- `puffin-build/vendors/<vendor>/presets.toml` — define vendor presets (source repo, branch, version):

```toml
[vendor_id]
sources = { repo = "https://github.com/tlspuffin/<vendor>.git", branch = "fuzz-v<VERSION>", version = "<VERSION>" }
builder = { type = "builtin", name = "<vendor>" }
sancov = true
```

- `puffin-build/vendors/<vendor>/builder.cmake` — build configuration. Key considerations:
    - **Build system**: Does the vendor use cmake, autotools, or something else? LibreSSL 4.x uses cmake, older versions use autotools.
    - **RNG override**: The fuzzer needs deterministic execution. Override `arc4random` with a controlled PRNG (copy `arc4random_prng.c/.h`).
    - **Internal headers**: The harness needs access to internal structures (for claims). Copy internal headers to the install prefix:

```cmake
list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_INSTALL_PREFIX}/include/<vendor>_internal")
list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy
  "<SOURCE_DIR>/ssl/ssl_local.h"
  # ... other internal headers
  "${CMAKE_INSTALL_PREFIX}/include/<vendor>_internal/"
)
```

- **Secret preservation**: For TLS 1.3 claims, the vendor may zero intermediate secrets after derivation. Patch to keep them. For LibreSSL, this was done via `patch_insecure.cmake` setting `secrets->insecure = 1` in `tls13_key_schedule.c`.
- **Capability flags**: Set `tls12`, `tls13`, `tls12_session_resumption`, `tls13_session_resumption`, `transcript_extraction`, etc.

**Build the vendor:**

```bash
./tools/mk_vendor make <vendor>:<vendor_id>
cargo build --release --bin=tlspuffin --features=cputs
```

### Step 1: Create the C harness

Create `tlspuffin/harness/<vendor>/src/put.c` (+ `bindings.c`, `rng.c`, headers). Use the OpenSSL harness (`tlspuffin/harness/openssl/src/put.c`) as a template.

**Key components:**

1. **Agent creation** (`create_client`, `create_server`):
    - Create `SSL_CTX` with appropriate method (`TLS_method()`)
    - Set TLS version min/max based on `descriptor->tls_version`
    - Set cipher lists (`SSL_CTX_set_ciphersuites` for TLS 1.3, `SSL_CTX_set_cipher_list` for TLS 1.2)
    - Set groups (`SSL_CTX_set1_groups_list`) — provide defaults if vendor uses unsupported groups
    - Set sigalgs (`SSL_CTX_set1_sigalgs_list`) if the vendor supports it
    - Set certificates, private keys, and trust store
    - Configure client/server authentication
    - Set up memory BIOs for I/O

2. **Claims extraction**: The harness must emit claims via the `CLAIMER_CB` callback. Required claims:
    - `CLAIM_FINISHED` — emitted when the handshake completes. Must include:
        - `master_secret` (TLS 1.2) or derived secrets (TLS 1.3)
        - `server_random`, `client_random`
        - `chosen_cipher` (as IANA cipher suite ID)
        - `server_handshake_traffic_secret`, `client_handshake_traffic_secret` (TLS 1.3)
        - `exporter_master_secret` (TLS 1.3)
    - `CLAIM_TRANSCRIPT_*` — transcript hashes at various stages
    - `CLAIM_TLS_VERSION` — negotiated TLS version

   This requires access to vendor internals (hence the internal headers). For LibreSSL, this meant including `<libressl_internal/ssl_local.h>` and accessing `ssl->s3->hs` for TLS 1.3 secrets.

3. **RNG override** (`rng.c`): Override the vendor's PRNG for determinism. For OpenSSL-API-compatible libraries, override `RAND_METHOD`. For LibreSSL, override `arc4random` at build time.

4. **PUT interface registration**: Implement `REGISTER()` returning a `TLS_PUT_INTERFACE` struct with function pointers for `create`, `rng_reseed`, `supports`, and the agent interface (`progress`, `reset`, `shutdown`, `descriptor`).

**Vendor-specific quirks found during LibreSSL integration:**

- LibreSSL's `SSL_CTX_set_ciphersuites()` may not exist or may require mapping standard cipher names to OpenSSL names
- LibreSSL doesn't expose `SSL_CTX_set1_sigalgs_list` — this is handled via fallback filter
- LibreSSL requires `__BEGIN_HIDDEN_DECLS`/`__END_HIDDEN_DECLS` macros when including internal headers
- Default groups may include post-quantum or non-standard curves; constrain to `"X25519:P-256:P-384"` when no config given

### Step 2: Establish baseline and identify differences

```bash
# Run all seeds with differential execution to see the raw differences:
for seed in seeds/*.trace; do
  echo "=== $(basename $seed) ==="
  cargo run -p tlspuffin --features=cputs -- differential-execute openssl340 <vendor_id> "$seed" 2>&1 | grep -E "^(No diff|Diff)"
done

# Also run single-PUT executions to understand what each PUT produces:
cargo run -p tlspuffin --features=cputs -- --put openssl340 display-execute -tckp seeds/tlspuffin::tls::seeds::seed_successful.trace
cargo run -p tlspuffin --features=cputs -- --put <vendor_id> display-execute -tckp seeds/tlspuffin::tls::seeds::seed_successful.trace
```

### Step 3: Fix CCS middlebox compatibility misalignment

**Problem:** TLS 1.3 middlebox compatibility — some implementations prepend a dummy `ChangeCipherSpec` record to encrypted flights. This shifts the knowledge store indices, causing every subsequent knowledge item to be misaligned.

**Check:** In `display-execute` output, look for `ChangeCipherSpec` in TLS 1.3 flights from the new vendor but not from OpenSSL (or vice versa).

**Fix:** Already handled in `MessageFlight::extract_knowledge` in `protocol.rs`:

```rust
for msg in &self.messages {
    if !matches!(msg.payload, MessagePayload::ChangeCipherSpec(_)) {
        msg.extract_knowledge(knowledges, None, source)?;
    }
}
```

This filters CCS from knowledge extraction. Verify this works for your vendor. If the vendor does NOT send CCS but another vendor does, this existing filter handles it.

> **Warning:** Do NOT filter `ApplicationData` here — the DY model needs `ApplicationData` knowledge items for building attack terms. Tests like `test_seed_successful_with_ccs` will fail if you filter `ApplicationData`.

### Step 4: Align PUT configuration

**Problem:** Different default cipher suites, groups, or signature algorithms cause benign differences.

**Check:** Compare the negotiated parameters (cipher suite, key share group, signature scheme) between PUTs using `display-execute -tck` output.

**Fix:** In `differential_fuzzing_uniformise_put_config` (`protocol.rs`), ensure the vendor supports the configured values:

```rust
agent.protocol_config.set_cipher_string_12(String::from(
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
));
agent.protocol_config.set_cipher_string_13(String::from(
    "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
));
agent.protocol_config.groups = Some(String::from("P-256:P-384"));
agent.protocol_config.sigalgs = Some(String::from(
    "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256"
));
```

**If the vendor doesn't support a configuration API** (e.g., LibreSSL lacks `SSL_CTX_set1_sigalgs_list`):

1. Check what APIs the vendor provides: `grep -r "SSL_CTX_set1_sigalgs" vendor/<vendor_id>/include/`
2. If unavailable, leave the harness as a no-op with a comment
3. Add a targeted filter in `differential_fuzzing_filter_diff` as fallback

**Adding a new config field** (follow `groups` / `sigalgs` as a pattern):

1. Add field to `TLSDescriptorConfig` struct in `protocol.rs` (with `Default` = `None`)
2. Add field to `TLS_AGENT_DESCRIPTOR` in `include/puffin/tls.h`
3. Extract and pass as `CString` in `put.rs` (`make_descriptor`)
4. Use in each harness `put.c` (OpenSSL, LibreSSL, WolfSSL, new vendor)

### Step 5: Fix default groups if needed

**Problem:** Some vendors may offer non-standard or post-quantum groups by default that the fuzzer's Rust code doesn't support.

**Check:** If the vendor fails to create agents or negotiate, check if it's offering unsupported groups.

**Fix:** In the vendor's `put.c`, set default groups when none configured:

```c
if (descriptor->group_list != NULL) {
    SSL_CTX_set1_groups_list(ssl_ctx, descriptor->group_list);
} else {
    // Constrain to groups the fuzzer's Rust code supports.
    SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384");
}
```

### Step 6: Handle SCSV and extension differences

**Problem:** Some implementations add `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` to `ClientHello` or differ in optional extensions like `ExtendedMasterSecretAck`.

**Check:** Look for `InnerDifference` diffs mentioning these in the differential output.

**Fix:** Add targeted string-matching filters in `differential_fuzzing_filter_diff`:

```rust
if diff.contains("TLS_EMPTY_RENEGOTIATION_INFO_SCSV") { return false; }
if diff.contains("ExtendedMasterSecretAck") { return false; }
```

Only add filters for differences you've verified are benign. Document why each filter exists.

### Step 7: Handle signature scheme differences

**Problem:** Different implementations may choose different RSA-PSS hash algorithms (e.g., SHA256 vs SHA512) for `CertificateVerify` when using RSA certificates.

**Preferred fix:** Configure sigalgs to force agreement (Step 4). If the vendor API doesn't support sigalgs configuration, add a targeted filter:

```rust
if diff.contains("DigitallySignedStructChange { scheme: Different") { return false; }
```

> **Warning:** Do NOT add `#[comparable_ignore]` to `DigitallySignedStruct.scheme` — this is too loose as it permanently removes the field from all comparisons, not just differential fuzzing.

### Step 8: Handle encrypted message count differences

**Problem:** In TLS 1.3, one PUT may send more `ApplicationData` records than the other (e.g., different numbers of `NewSessionTickets`). The shorter knowledge store gets padded with `()`, producing `DifferentTypes` diffs.

**Check:** Compare flight sizes between PUTs using `display-execute` output. Count `ApplicationData` messages per flight.

**Fix:** Add a targeted filter for `DifferentTypes` where one side is `()` and the other is a `MessagePayload`. Restrict by **source** to avoid hiding unexpected type mismatches:

```rust
TraceDifference::Knowledges(KnowledgeDiff::DifferentTypes {
    first_type, second_type, first_source, second_source, ..
}) => {
    if (first_type == "()" && second_type.contains("MessagePayload"))
        || (second_type == "()" && first_type.contains("MessagePayload"))
    {
        // Only suppress from known-safe sources:
        //   Source::Agent: extra encrypted ApplicationData (NewSessionTickets)
        //   Source::Label(Some("Decryption")): asymmetric decryption success
        let (non_unit_source, _) = if first_type == "()" {
            (second_source, first_source)
        } else {
            (first_source, second_source)
        };
        let is_expected = matches!(non_unit_source, Source::Agent(_))
            || matches!(non_unit_source,
                Source::Label(Some(label)) if label == "Decryption"
            );
        if is_expected { return false; }
    }
}
```

### Step 9: Handle decryption recipe differences

**Problem:** Decryption recipes may succeed for one PUT but fail for the other, or produce different amounts of plaintext.

**Investigation:**

1. Run with `-p` flag to see decrypted knowledge
2. Check which recipes succeed/fail per PUT
3. Check if the claims (secrets) differ between PUTs

**Possible causes:**

- One PUT exposes a different/wrong claim value (different secret names or indices)
- One PUT encrypts more messages in a flight (extra extensions, `NewSessionTickets`)
- Recipe references wrong flight/sequence number

**Current approach:** Decrypted knowledge is added whenever a PUT succeeds, even if only one PUT succeeds. Asymmetric decryption is logged but not suppressed. Count mismatches from asymmetric success are handled by the `DifferentTypes` filter (Step 8).

```rust
match (self_eval, other_eval) {
    (Ok(self_decrypted), Ok(other_decrypted)) => {
        // Both succeed — add both
        self_store.add_raw_boxed_knowledge(self_decrypted, ...);
        other_store.add_raw_boxed_knowledge(other_decrypted, ...);
    }
    (Ok(self_decrypted), Err(_)) => {
        log::trace!("Decryption succeeded only for first PUT (term: {})", t);
        self_store.add_raw_boxed_knowledge(self_decrypted, ...);
    }
    (Err(_), Ok(other_decrypted)) => {
        log::trace!("Decryption succeeded only for second PUT (term: {})", t);
        other_store.add_raw_boxed_knowledge(other_decrypted, ...);
    }
    (Err(_), Err(_)) => { /* Both failed, skip */ }
}
```

**Fixes (in order of preference):**

1. Fix the recipe term to reference the correct claim/flight
2. If count differs due to extra plaintext messages, filter specific message types from decrypted knowledge comparison
3. If the vendor doesn't expose the required secret, the recipe simply fails for that PUT and the asymmetric case is handled

### Step 10: Verify everything

```bash
# All unit tests pass
cargo test -p tlspuffin --features=cputs 2>&1 | grep -E "^test result:|FAILED"

# All seeds show no differences
for seed in seeds/*.trace; do
  echo "=== $(basename $seed) ==="
  cargo run -p tlspuffin --features=cputs -- differential-execute openssl340 <vendor_id> "$seed" 2>&1 | grep -E "^(No diff|Diff)"
done

# Existing vendor diffs not regressed
for seed in seeds/*.trace; do
  cargo run -p tlspuffin --features=cputs -- differential-execute openssl340 wolfssl540 "$seed" 2>&1 | grep -E "^(No diff|Diff)"
done
```

## Anti-patterns to avoid

| Don't | Why | Do instead |
|-------|-----|------------|
| `#[comparable_ignore]` on meaningful fields | Permanently removes from ALL comparisons | Use `differential_fuzzing_filter_diff` for differential-only filtering |
| Filter all `MessagePayload` vs `()` broadly | Hides cases where one PUT sends extra handshake messages | Filter by source (`Source::Agent` or `Source::Label("Decryption")`) |
| Skip decryption when one PUT fails | Hides real decryption issues and asymmetric secret exposure | Add knowledge for whichever PUT succeeds; handle count mismatches in filter |
| Filter `ApplicationData` in `extract_knowledge` | Breaks DY model tests (attacker needs `ApplicationData` knowledge) | Handle count differences in comparison/filter layer |
| Broad string-match filters | May match unintended diffs | Use the most specific match string possible |
| Hardcode vendor-specific workarounds in generic code | Makes the framework fragile | Use the protocol-specific hooks (`differential_fuzzing_filter_diff`, `differential_fuzzing_uniformise_put_config`) |

## Key principle

From the paper (Section 4.2): *"This requires particular care and fine-grained control to avoid introducing blind spots in our oracle and miss bugs."* Every filter should be:

1. **Targeted**: match the specific benign difference, not a broad category
2. **Documented**: explain WHY the difference is benign
3. **Verified**: confirm it doesn't hide meaningful differences in other seeds

## Reference: LibreSSL 4.2.1 integration specifics

The following vendor-specific issues were encountered during the LibreSSL 4.2.1 integration and may recur for other vendors:

- **Build system**: LibreSSL 4.x uses cmake (not autotools like 3.x). VERSION files must be created manually for the build.
- **Secret preservation**: LibreSSL zeros intermediate TLS 1.3 secrets (`extracted_early`, `extracted_handshake`, `extracted_master`) after derivation. Patched via `secrets->insecure = 1` in `tls13_key_schedule.c`.
- **Internal headers**: Required `ssl_local.h`, `tls13_internal.h`, `tls_internal.h`, `tls12_internal.h`, `tls_content.h`, `bytestring.h` for claims extraction.
- **Hidden decls macros**: LibreSSL internal headers require `__BEGIN_HIDDEN_DECLS` / `__END_HIDDEN_DECLS` to be defined (as empty macros) before inclusion.
- **No sigalgs API**: LibreSSL lacks both `SSL_CTX_set1_sigalgs_list` and `SSL_CTX_set1_sigalgs`. The sigalgs config is a no-op; the `DigitallySignedStructChange` filter catches remaining scheme differences.
- **CCS middlebox compatibility**: LibreSSL sends dummy `ChangeCipherSpec` in TLS 1.3 flights. Already handled by the CCS filter in `extract_knowledge`.
- **Default groups**: LibreSSL may offer post-quantum or non-standard groups by default. Constrained to `"X25519:P-256:P-384"` when no config given.
- **No TLS 1.3 session resumption**: LibreSSL supports 0-RTT but not full TLS 1.3 session resumption. Set `tls13_session_resumption = no` in `builder.cmake`.
- **Cipher name mapping**: LibreSSL may use different cipher suite names than OpenSSL. The harness may need to map standard names to LibreSSL-recognized names.
