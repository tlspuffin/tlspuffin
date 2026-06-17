# Differential Dolev–Yao Fuzzing (DDYF) on sshpuffin — Results

_Last updated: 2026-06-17. Branch `pr/openssh-rework`._
_Implementation plan and roadmap live in `DIFFERENTIAL_FUZZING_PLAN.md`; this
file records the working setup and the findings._

---

## 1. What DDYF does here

Differential fuzzing runs **one symbolic (Dolev–Yao) trace against two SSH
implementations** and reports where their observable behavior diverges. A
`TraceDifference` can be one of four kinds:

- **Status** — the two PUTs reach different execution outcomes / step counts.
- **Knowledges** — the structured messages they emit differ (the focus here).
- **Claims** — emitted security claims differ (not yet populated for SSH).
- **SecurityClaim** — a DY security property is violated by one PUT (Phase 2).

The fuzzer drives the handshake symbolically (including the crypto, via the
pure-Rust mapper in `src/ssh/fn_crypto.rs`), so both implementations are fed
identical traces and their replies are compared field-by-field.

## 2. PUTs under comparison

| PUT id | libssh version | Released | Instrumentation |
|---|---|---|---|
| `libssh0114-asan` | 0.11.4 | 2024 | ASAN + sancov |
| `libssh0104-asan` | 0.10.4 | Jul 2023 | ASAN + sancov |

Both are registered from `vendor/` (see plan for the build/registration note).
This is a **version differential** (Phase 0/1). A second, independent
implementation (wolfSSH) is planned for Phase 3.

## 3. How the comparison is made meaningful

Two complementary mechanisms, both verified in `puffin` source:

1. **Type whitelist** (`SshProtocolTypes::differential_fuzzing_whitelist`) —
   only structured, semantically-meaningful knowledge is compared:
   `SshMessage`, `SshMessageFlight`, `KexInitMessage`, `KexEcdhReplyMessage`.
   Opaque types (`RawSshMessage`, `OnWireData`, `BinaryPacket`, `Vec<u8>`,
   raw flights, banner `String`) are excluded — they carry ciphertext, framing
   and version strings that legitimately differ and would drown out real signal.

2. **Field annotations** (`#[comparable_ignore]` on mapper structs) — within the
   compared types, inherently-divergent fields are excluded from the diff:
   - `KexInitMessage.cookie` (16 random bytes)
   - `KexEcdhInitMessage.ephemeral_public_key` (client ephemeral X25519 key)
   - `KexEcdhReplyMessage.ephemeral_public_key` and `.signature`
   - `KexEcdhReplyMessage.public_host_key` is **kept** — both PUTs use the same
     embedded host key, so a difference there would be a genuine finding.

### Why not RNG determinism?

SSH servers/clients generate random ephemeral keys and cookies every run, so a
naïve comparison shows hundreds of diffs even for a PUT against *itself*. We
added a deterministic-RNG hook (`harness/libssh/src/rng.c`, a custom OpenSSL
`RAND_METHOD`, reseeded per trace via the PUT interface), but the system OpenSSL
is 3.0.14, which **ignores the legacy `RAND_METHOD` for X25519 keygen** (it pulls
randomness from the provider RNG). Full RNG determinism is therefore not
achievable that way — and, by design, cross-vendor KDF/seed-expansion divergence
is *expected* anyway. The correct lever is the annotation/whitelist mechanism
above, which makes the comparison deterministic regardless of RNG.

## 4. Result: clean, zero-false-positive comparison

Measured with `differential-execute` on the seed corpus
(`#diffs` = number of reported `Differences in knowledges`):

| Seed | same (0114 vs 0114) | cross (0114 vs 0104) |
|---|---|---|
| `seed_client_attacker_full` | **0** | 3 |
| `seed_server_attacker_full` | **0** | 3 |
| `seed_successful`           | **0** | 6 |
| `seed_auth_structured`      | **0** | 6 |
| `seed_none_auth_probe`      | **0** | 6 |

- **same-vs-same = 0 on every seed** → no false positives; the comparison is
  fully deterministic via annotations.
- **cross-version diffs are all genuine** (analysis below). Seeds with two real
  agents (`seed_successful`, …) report the same logical differences on both the
  client- and server-side KEXINIT, hence `cross=6` vs `cross=3` for the
  single-agent attacker seeds. The redundancy across the knowledge hierarchy
  (flight → `SshMessage` → `KexInitMessage`) is expected, not extra findings.

## 5. Finding analysis — do the diffs correspond to protocol changes?

All differences are in the **server (and client) KEXINIT** algorithm
advertisement. Full lists extracted from each PUT:

### 5.1 `kex-strict-s-v00@openssh.com` — added in 0.11.4 ✅ security-relevant
```
0.11.4 kex_algorithms: [ curve25519-sha256, curve25519-sha256@libssh.org,
                         ecdh-sha2-nistp256/384/521,
                         diffie-hellman-group18-sha512, …-group16-sha512,
                         …-group-exchange-sha256, …-group14-sha256,
                         kex-strict-s-v00@openssh.com ]   ← present
0.10.4 kex_algorithms: [ … same … , diffie-hellman-group14-sha256 ]  ← absent
```
The **strict key-exchange marker**, i.e. the **Terrapin mitigation
(CVE-2023-48795)**. The server advertises it to signal strict KEX (sequence
reset at NEWKEYS, rejecting unexpected messages during key exchange). libssh
introduced it in 0.10.6 / 0.11.0 (Dec 2023); 0.10.4 (Jul 2023) predates it.
**Genuine, security-critical protocol change.**

### 5.2 Plain `zlib` compression — removed in 0.11.4 ✅ security-relevant
```
0.11.4 compression: [ none, zlib@openssh.com ]
0.10.4 compression: [ none, zlib@openssh.com, zlib ]   ← extra "zlib"
```
0.10.4 also offers plain `zlib` (RFC 4253), which compresses **before**
authentication; `zlib@openssh.com` is the delayed (post-auth) variant. Pre-auth
compression is a known exposure, so dropping plain `zlib` is deliberate
hardening. **Genuine protocol/policy change.**

### 5.3 Trailing empty cipher-list entry — 0.10.4 only ⚠️ real but benign
```
0.11.4 encryption: [ chacha20-poly1305@openssh.com, aes256-gcm@…, aes128-gcm@…,
                     aes256-ctr, aes192-ctr, aes128-ctr ]
0.10.4 encryption: [ …same…, aes128-ctr, "" ]   ← trailing empty element
```
0.10.4 emits a **trailing comma** in its encryption name-list
(`…aes128-ctr,`), which the shared `NameList` parser splits into a trailing
empty element. Because both PUTs use the same parser and only 0.10.4 shows it,
the difference is on the wire — a list-construction artifact in 0.10.4 cleaned
up in 0.11.x. Not security-relevant, but a real byte-level divergence (and a
minor name-list hygiene issue).

### Summary

| Difference | Real protocol change? | Significance |
|---|---|---|
| `kex-strict-s-v00@openssh.com` added | Yes | Terrapin / CVE-2023-48795 mitigation |
| plain `zlib` removed | Yes | removes pre-auth compression (hardening) |
| trailing `""` in cipher list | Yes (wire-level) | benign list-construction cleanup |

**Every reported cross-version difference maps onto documented libssh evolution
between 0.10.4 and 0.11.4, with zero false positives.** The two substantive
findings are exactly the kind of security-hardening changes a differential SSH
fuzzer should surface.

## 6. How to reproduce

Environment (this machine; Nix store paths):
```bash
export LIBCLANG_PATH=/nix/store/glcl2kq3dc1qw4qdw52f7mqs1ci3k80r-clang-14.0.6-lib/lib
export PATH="/nix/store/vvflx70q27229r0glx2ld1ciw40rr11n-clang-wrapper-14.0.6/bin:/home/lhirschi/.rustup/toolchains/1.94.0-x86_64-unknown-linux-gnu/bin:$PATH"
export LD_LIBRARY_PATH=/nix/store/k0rqiflg1vkn1kj96br5pfxj40p3srz4-zstd-1.5.7/lib

# Build (both libssh vendors are discovered from vendor/)
cargo build -p sshpuffin --release --features asan

# Regenerate the on-disk seed corpus if the signature/seeds changed
./target/release/sshpuffin seed

# One-shot differential on a single trace (prints the TraceDifference)
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./target/release/sshpuffin differential-execute \
    libssh0114-asan libssh0104-asan seeds/seed_client_attacker_full.trace

# Same PUT twice = determinism check (expect 0 differences)
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  ./target/release/sshpuffin differential-execute \
    libssh0114-asan libssh0114-asan seeds/seed_client_attacker_full.trace

# Dump a PUT's structured knowledge (to inspect the algorithm lists)
./target/release/sshpuffin -T libssh0114-asan display-execute -k \
    seeds/seed_client_attacker_full.trace

# Differential CAMPAIGN (continuous fuzzing across two PUTs)
ASAN_OPTIONS=verify_asan_link_order=1:detect_leaks=0:abort_on_error=1 \
  ./target/release/sshpuffin -c 0-3 -p 1339 \
    differential libssh0114-asan libssh0104-asan
```

## 7. Code touchpoints

| Concern | Location |
|---|---|
| Whitelist / `terms_to_eval` / filter hooks | `sshpuffin/src/protocol.rs` (`impl ProtocolTypes`) |
| `#[comparable_ignore]` field annotations | `sshpuffin/src/ssh/message.rs` (KexInit/KexEcdhInit/KexEcdhReply) |
| Encrypt / decrypt DY functions | `sshpuffin/src/ssh/fn_crypto.rs` (`fn_encrypt_packet`, `fn_decrypt_packet`) |
| Deterministic RNG hook | `sshpuffin/harness/libssh/src/rng.c`, `include/rng.h`, interface in `include/puffin/ssh.h` |
| PUT reseed wiring | `sshpuffin/src/libssh/mod.rs` (`Factory::rng_reseed`) |
| DDYF comparison engine | `puffin/src/trace.rs::compare`, `puffin/src/protocol.rs` (`CompareKnowledge`), `puffin/src/differential.rs` |

## 7b. Post-NewKeys encrypted layer (DONE)

`differential_fuzzing_terms_to_eval` now decrypts the server's encrypted
responses so they are compared structurally. For each libssh server agent,
`server_decryption_recipes` (in `seeds.rs`) reconstructs the server→client (s2c)
key from the observed KEX output (same derivation as the attacker-full seed, but
the 'D' direction) and applies `fn_decrypt_packet` to each encrypted output.

The s2c sequence number after NEWKEYS depends on **strict KEX**: 0.11.4 resets
the counter to 0, 0.10.4 continues (first encrypted = 3). Recipes are emitted at
both conventions (0,1,2 and 3,4,5); the wrong seqno fails the Poly1305 tag and
is skipped, so the two PUTs' decrypted stores fill in message order and align.

Result on `seed_client_attacker_full`:
- 0.11.4 decrypts at seqno 0,1 (strict); 0.10.4 at seqno 3,4 (non-strict).
- Both yield `[ServiceAccept(ssh-userauth), UserAuthSuccess]`.
- The decrypted post-NewKeys layer compares **EQUAL** across versions — the auth
  layer behaves identically; only the pre-NewKeys KEXINIT differs (§5).
- Bonus: *which* recipes succeed directly reveals the strict-kex seqno-reset
  behavior (a real, observable behavioral difference between the versions).

**Phase 1 is therefore complete**: both the plaintext handshake and the
encrypted record layer are compared, with zero false positives.

## 8. Current limitations & next steps

- **Claims/SecurityClaim comparison inactive** (Phase 2): see below.
- **Claims/SecurityClaim comparison inactive.** `SshClaim` is a dummy and
  `register_claimer` is a no-op (Phase 2): no auth/secret/session claims are
  emitted yet, so the Claims and SecurityClaim diff channels are silent.
- **Single implementation family.** Only libssh-vs-libssh (version differential).
  A genuinely independent implementation (wolfSSH, Phase 3) would turn
  divergences into cross-implementation interoperability/security findings.
- **`NameList` codec** treats a trailing separator as a distinguishable empty
  token — correct for surfacing wire differences (see §5.3); keep as-is rather
  than normalize.
