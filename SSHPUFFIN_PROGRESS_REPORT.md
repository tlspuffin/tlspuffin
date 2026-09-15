# sshpuffin — Progress Report & Handover

_Last updated: 2026-06-17. Branch: `pr/openssh-rework`._

This document describes the state of the sshpuffin SSH protocol fuzzer, the work
done so far, the approach, and what remains. It is written so another engineer
(or LLM) can continue without prior context.

---

## 1. What sshpuffin is

sshpuffin is a **Dolev–Yao (DY) protocol fuzzer for SSH**, built on the `puffin`
framework and modeled closely on the sibling project `tlspuffin`. The fuzzer
manipulates SSH messages as **symbolic terms** (a "mapper" of typed function
symbols), evaluates them into concrete bytes, and drives them against a real
SSH implementation (the **PUT** — Program Under Test), currently **libssh
0.11.4** built with ASAN + sancov.

Key idea: instead of mutating raw bytes, the fuzzer mutates a **term algebra**.
Each SSH message field is a typed sub-term the fuzzer can extract from observed
traffic and recompose, enabling structurally-valid-but-adversarial messages.

### Repository layout (sshpuffin-specific)

```
sshpuffin/
  src/ssh/
    message.rs       # SSH message types + Codec + Extractable derives
    fn_message.rs    # DY constructor fns for every SSH message
    fn_constants.rs  # DY constant fns (algorithm names, service names, u32s, …)
    fn_crypto.rs     # DY crypto fns (ECDH, exchange hash, KDF, encryption, signing)
    seeds.rs         # Seed traces (the initial corpus) + their execution tests
    mod.rs           # SSH_SIGNATURE: the registered set of all fn symbols
    deframe.rs       # Wire deframer: bytes -> RawSshMessage
  harness/libssh/
    src/put.c        # C harness: wraps libssh via socketpair, drives KEX/AUTH/channels
  build.rs           # Builds libssh vendor + compiles C harness, generates FFI bindings
  Cargo.toml         # Rust crypto deps: x25519-dalek, sha2, chacha20, poly1305, rsa, ssh-key
```

---

## 2. The approach (how a DY trace works here)

A `Trace` is a list of `Step`s over one or more `AgentDescriptor`s (each a libssh
client or server instance). Two step kinds:

- `OutputAction(agent)` — pull the agent's pending output and add it to the
  **knowledge base**, indexed by `(agent, counter)` and type.
- `InputAction(agent, term)` — evaluate `term` to bytes and feed them to the agent.

Terms are written with the `term! { … }` macro:
- `((agent, n)[None]/Type)` extracts the n-th knowledge item of `Type` from `agent`.
- `fn_foo(arg1, arg2)` applies a registered function symbol.
- Zero-arg fns are written bare: `fn_new_keys` (no parens).
- A zero-arg fn used as an **argument** must be parenthesized: `fn_outer((fn_inner))`.
- `@var` splices a precomputed Rust `term!` variable (used to share sub-terms).

Every fn symbol used in any term **must** be registered in `SSH_SIGNATURE` in
`mod.rs`, or evaluation panics.

### Crypto is in the mapper (pure Rust)

The decisive design choice: **crypto primitives are DY function symbols**, using
pure-Rust RustCrypto crates (NOT libssh FFI, NOT a C helper). This lets the
fuzzer treat key exchange, key derivation, encryption and signing as ordinary
composable terms. The fuzzer (acting as one peer) can therefore complete a real
handshake and operate the **encrypted record layer** — sending well-formed
encrypted post-NewKeys messages, or adversarial variants thereof.

`fn_crypto.rs` provides (all matching libssh's `curve25519-sha256` +
`chacha20-poly1305@openssh.com` exactly):

| Function | Purpose |
|---|---|
| `fn_client_ecdh_privkey` / `fn_client_ecdh_pubkey` | Deterministic X25519 keypair (fixed seed) |
| `fn_ecdh_shared_secret(priv, peer_pub)` | X25519 DH → 32 raw bytes |
| `fn_banner_id(raw)` | Banner string without `\r\n` (for V_C/V_S) |
| `fn_kexinit_payload(msg)` | KexInit wire payload (for I_C/I_S) |
| `fn_server_ecdh_pubkey(reply)` | Extract Q_S from KexEcdhReply |
| `fn_server_hostkey_raw(raw)` | Extract raw K_S outer-string bytes from the reply packet |
| `fn_kex_exchange_hash(v_c,v_s,i_c,i_s,k_s,q_c,q_s,K)` | H = SHA-256(...) per RFC |
| `fn_derive_enc_key_c2s` / `_s2c` | RFC 4253 §7 KDF, 64 bytes (keys 'C'/'D') |
| `fn_encrypt_packet(msg, key, seqno)` | ChaCha20-Poly1305 packet → `RawSshMessage::OnWire` |
| `fn_server_rsa_pubkey` / `_bytes` | Embedded RSA host key as `SshPublicKey` / raw K_S |
| `fn_sign_exchange_hash(h)` | rsa-sha2-256 signature over H (PKCS#1v1.5, `rsa` crate) |
| `fn_rsa_sha2_256_signature(sig)` | Wrap raw sig bytes in an `SshSignature` |

**Crypto correctness details (important, easy to get wrong):**
- Exchange-hash buffer order: `V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K`; V/I/Q are
  SSH strings (`u32 len || data`); K_S is appended raw (already an outer SSH
  string); K is an **mpint** (strip leading zero bytes big-endian, prepend `00`
  if high bit set, then `u32` length).
- ChaCha20-Poly1305@openssh: key split `k2 = key[0..32]` (body), `k1 = key[32..64]`
  (length field). Nonce = 8-byte big-endian seqno (`ChaCha20Legacy`, 64-bit
  nonce). Poly1305 key = first 32 bytes of k2 keystream at counter 0. **Body is
  encrypted starting at counter 1 → `cipher.seek(64)` before `apply_keystream`**
  (this was the subtle bug that produced "Invalid padding"). Tag is Poly1305 over
  `enc_len || enc_body`.
- Sequence numbers reset to 0 at NewKeys. In the seeds, binary packets sent
  before the first encrypted one count toward the seqno (KexInit=0,
  KexEcdhInit=1, NewKeys=2, then ServiceRequest=3, …). Watch this if you add steps.
- `ssh-key`'s `PublicKey::to_bytes()` returns the blob **without** an outer
  length prefix; `fn_server_rsa_pubkey_bytes` re-adds it for the K_S position.
- RSA signing: `RsaPrivateKey::try_from(&RsaKeypair)` failed ("cryptographic
  error"); building from raw mpint components via `from_components(n,e,d,[p,q])`
  works.

---

## 3. Seeds (initial corpus) — `seeds.rs`

| Seed | Roles present | What it exercises |
|---|---|---|
| `seed_successful` | client + server (both real libssh) | Baseline mutual handshake |
| `seed_auth_structured` | client + server | Structured ServiceRequest/UserAuthRequest |
| `seed_disconnect_early` | client + server | Disconnect during banner exchange |
| `seed_none_auth_probe` | client + server | "none" auth method probe |
| `seed_auth_wrong_password` | client + server | Password auth failure/retry |
| `seed_server_attacker` | client only | Fuzzer is server (pre-crypto, KEX only) |
| `seed_client_attacker` | server only | Fuzzer is client (pre-crypto, KEX only) |
| **`seed_client_attacker_full`** | server only | **Fuzzer = client, FULL handshake + encrypted ServiceRequest/UserAuth/ChannelOpen/exec** |
| **`seed_server_attacker_full`** | client only | **Fuzzer = server, signs exchange hash, FULL handshake + encrypted ServiceAccept/UserAuthSuccess** |

The two `*_full` seeds are the breakthrough: a single real libssh agent, with the
fuzzer synthesizing **all** messages for the opposing role, all the way through
the encrypted record layer. This is the tlspuffin `seed_client_attacker` /
`seed_server_attacker` pattern.

Both `*_full` seeds have execution tests in `seeds.rs #[cfg(test)] mod tests`
that assert the libssh agent reaches a successful state. **All 8 tests pass**
(1 legacy seed is `#[ignore]`d).

---

## 4. Results so far

- **Old ceiling:** ~756/11221 edges (6%). Everything past NewKeys was unreachable
  because post-handshake traffic is AEAD-encrypted and the fuzzer couldn't
  produce valid ciphertext.
- **Now:** with full-handshake seeds, coverage immediately reaches
  **~1621/11263 edges (14%)** and climbs — auth handlers, channel handlers, and
  the cipher/MAC paths are now exercised.
- No objectives (crashes) found yet at time of writing.

### Running 8-hour ASAN campaign
- Binary: `sshpuffin_asan_8h` (built `--release --features asan`).
- Launched: `2026-06-17 ~08:03 UTC`, cores **0-3**, 4 clients.
- Experiment dir: `experiments/2026-06-17--libssh-0.11.4-4c8h-asan-full-handshake--08-03-*/`.

---

## 5. How to build & run (exact environment)

This machine needs explicit toolchain/library paths (Nix store):

```bash
export LIBCLANG_PATH=/nix/store/glcl2kq3dc1qw4qdw52f7mqs1ci3k80r-clang-14.0.6-lib/lib
export PATH="/nix/store/vvflx70q27229r0glx2ld1ciw40rr11n-clang-wrapper-14.0.6/bin:/home/lhirschi/.rustup/toolchains/1.94.0-x86_64-unknown-linux-gnu/bin:$PATH"
export LD_LIBRARY_PATH=/nix/store/k0rqiflg1vkn1kj96br5pfxj40p3srz4-zstd-1.5.7/lib

# Build (release). Add --features asan for an ASAN PUT.
cargo build -p sshpuffin --release [--features asan]

# Run the mapper/seed tests (verifies crypto matches libssh end-to-end)
cargo test -p sshpuffin --release

# Regenerate the on-disk seed corpus (REQUIRED after changing SSH_SIGNATURE or
# seeds — stale ./seeds traces from an old signature break the campaign import)
./target/release/sshpuffin seed         # writes ./seeds/

# Launch an experiment campaign (uses ./seeds as initial corpus)
ASAN_OPTIONS=verify_asan_link_order=1:detect_leaks=0:abort_on_error=1 \
  ./sshpuffin_asan_8h -c 0-3 experiment -t "title"
```

### Operational gotchas (learned the hard way)
- **Core affinity:** the login shell is restricted to a cpuset. Launching on
  cores **outside** that set (e.g. `-c 32-35`) silently spawns **no client
  children** — the broker sits at `clients: 1, execs: 0` forever. Use low cores
  (`0-3`). Check `cat /sys/devices/system/cpu/online` vs the shell's allowed set.
- **Stale seeds:** always `rm -rf seeds/ && <bin> seed` after changing the
  signature or seeds; otherwise the campaign fails to import.
- **ASAN_OPTIONS:** `abort_on_error=1` is required so crashed workers restart;
  `detect_leaks=0` avoids LSan noise from libssh.
- **FD leak (fixed):** `put.c` must close `put_fd` explicitly after `ssh_free()`
  when the session errored early (guard with `fcntl(fd, F_GETFD) != -1`).
  Without it, workers exhaust file descriptors and `socketpair()` starts failing.
  `REGISTER()` also raises `RLIMIT_NOFILE` to the hard limit.
- Don't commit `seeds/`, `experiments/`, `log/`, or vendor build artifacts.

---

## 6. Message model — `message.rs`

- `SshBytes(Vec<u8>)` — the u32-length-prefixed SSH string; the core extractable
  byte type (replaced raw `Vec<u8>` so the fuzzer can swap individual fields).
- `SshPublicKey { algorithm, key_data }`, `SshSignature { algorithm, signature_data }`
  — structured; note RSA pubkeys store `[mpint e][mpint n]` raw in `key_data`
  (see the `ssh-rsa` special-case in their `Codec` impls).
- `RawSshMessage`: `Banner(String) | Packet(BinaryPacket) | OnWire(OnWireData)`.
  Encrypted packets are sent as `OnWire` (opaque bytes); plaintext structured
  messages go through `Packet` via `fn_packet`.
- `SshMessage`: the full enum of typed protocol messages with `Codec`.

---

## 7. What remains to do (priority order)

1. **Watch the 8h campaign** for objectives. Triage any crash in
   `experiments/.../objective/` with `tools/analyze-crashes.sh`.
2. **Security claims / DY properties** (originally task #4, still open):
   - Implement claim extraction in `put.c` (`register_claimer` is currently a
     no-op) — e.g. surface auth-success, session keys, channel state from libssh.
   - Define DY violation properties in `src/violation.rs`
     (`SshSecurityViolationPolicy` currently trivial). Examples: authentication
     bypass (server reaches "authenticated" without a valid credential term),
     key/secret leakage, accepting a message encrypted under the wrong key.
   - This is what turns coverage into actual *security* findings.
3. **More handshake flows / mutation surface:**
   - Rekeying (second KEX after NewKeys).
   - Pubkey auth (`fn_method_publickey`) with a real signed auth request.
   - Multiple channels, channel window adjust, extended data, EOF/close ordering.
   - Other KEX algorithms (currently only curve25519-sha256) and other ciphers
     (only chacha20-poly1305). Each needs matching crypto fns.
4. **Differential fuzzing:** `protocol.rs` has `differential_*` hooks returning
   empty/None. Wire up a second SSH PUT (e.g. another libssh version or OpenSSH)
   and define the term/claim comparison to find behavioral divergences.
5. **Re-enable the `dead_code` lint** in `src/ssh/mod.rs` once the API stabilizes
   (currently globally allowed) to surface genuinely unused fns.
6. **Codec round-trip coverage:** `message.rs` has `test_all_message_codecs_roundtrip`;
   extend it as new message variants/fields are added.

---

## 8. Commit history (this work, on `pr/openssh-rework`)

- FD-leak fix in the libssh harness (`put.c`).
- Structured `SshBytes`/`SshPublicKey`/`SshSignature` mapper + richer constants.
- Client/server attacker seeds (pre-crypto) + algorithm-name constants.
- **Full SSH handshake crypto in the DY mapper + `*_full` attacker seeds** (latest).

Commit messages intentionally contain **no AI/LLM attribution** (user preference).
