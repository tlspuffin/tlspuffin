# Decryption-Differential Fuzzing: libssh vs wolfSSH

A differential Dolev–Yao fuzzing campaign comparing **libssh 0.11.4** and
**wolfSSH 1.4.20** at the level of their *decrypted* SSH transport traffic, using
sshpuffin. The goal was to find cross-vendor behavioural divergences that manifest
in the encrypted record layer — divergences a byte- or status-only differential
cannot see — **without** relying on hand-written security oracles or policies.

## TL;DR

- Built a sound, oracle-free **decryption differential**: the two stacks' encrypted
  s2c output is decrypted with DY recipes and compared as structured messages.
- Ran it at scale (**~1,000,000+ objectives** across many multi-core campaigns).
- **Negative result:** no genuine libssh↔wolfSSH *library* divergence exists under
  decryption in this seed/coverage regime. Every candidate resolved to benign
  implementation latitude or to a **test-harness artifact** (two of which we found
  and fixed).
- The pipeline is validated: it *provably* fires on a real divergence (it surfaced
  a genuine behavioural asymmetry, which we then traced to our own harness), and it
  returns clean once the harness is symmetric.

## What was built

1. **Structural denoising in the data model** (not a post-hoc filter): the
   knowledge whitelist is narrowed to one structured level (`SshMessage`);
   randomised/implementation-defined fields are excluded with `#[comparable_ignore]`
   (KEX cookie, ephemeral keys, signatures, server-chosen channel id / window /
   max-packet size); algorithm name-lists are compared order-insensitively and with
   the extension/Terrapin signalling markers stripped via `#[comparable_synthetic]`.

2. **Configuration uniformisation** (`differential_fuzzing_uniformise_put_config`):
   both PUTs are forced to advertise the *maximal common* algorithm set (measured
   intersection of the two stacks' defaults: curve25519/ecdh/dh-group KEX, AES-GCM
   ciphers, hmac-sha2, rsa-sha2), plumbed through a new FFI descriptor field into
   both C harnesses (libssh `ssh_bind_options_set`, wolfSSH `wolfSSH_CTX_SetAlgoList*`).
   The two stacks also share one embedded RSA host key so `KexEcdhReply.public_host_key`
   is comparable.

3. **Decryption recipes + flight decryption**: DY terms decrypt the server's
   post-NewKeys AES-256-GCM output into structured `SshMessage`s. Because the two
   stacks packetise/batch their socket writes differently, decryption operates at
   the *flight* level (`fn_decrypt_flight_aesgcm`): a socket write's chunks are
   concatenated and every BPP packet is peeled with a running GCM counter — the SSH
   analogue of the TLS `fn_decrypt_handshake_flight`, so capture is independent of
   framing.

4. **Semantic alignment** (`KnowledgeStore::compare`): decrypted messages are
   bucketed by a protocol-defined alignment key (SSH = message *variant*) and
   compared like-with-like, instead of by raw packet position. A message present on
   only one side is reported as a **presence difference** (fail-closed: an omission
   of a security-relevant message is a finding, never silently treated as "equal").

5. **Fail-closed objective filter** with a minimal, documented exception set, and a
   `decrypt-only` build feature that restricts objectives to decryption-recipe
   differences so a campaign's corpus is not polluted by unrelated diffs. (This
   required a puffin fix: `filter_diff` is now applied to *all* differences — status
   diffs previously short-circuited it.)

6. **Thin, symmetric harnesses**: the libssh harness was rewritten to use libssh's
   high-level **server-callbacks + `ssh_event`** API (auth / service / channel
   callbacks), mirroring the wolfSSH harness's delegation to `wolfSSH_accept`, so
   the two harnesses drive their libraries the same way and do not re-implement — or
   mask — protocol behaviour.

7. **TLS-style triaging pipeline** (`sort_objectives_libssh_wolfssh.py`) extended
   with precise **BENIGN buckets** for every decryption-recipe divergence class, so
   a genuinely new divergence would match no BENIGN bucket and stand out for audit.

## The two harness artifacts (found and fixed)

The differential's real value showed here: it surfaced two "divergences" that
looked like library bugs but were artifacts of the *harnesses* — and fixing them
is what made the negative result trustworthy.

- **Unknown-userauth-method acceptance.** The old libssh harness's message loop had
  an `else` branch that accepted *any* non-publickey auth method unconditionally, so
  a malformed method-name (with valid publickey data) was "accepted" by libssh where
  wolfSSH's library correctly rejected it (RFC 4252 §5.1). ~200/300k objectives
  carried this. Fixed by making the harness reject unknown methods — later enforced
  by the library itself once the harness moved to `ssh_set_auth_methods` +
  server callbacks.

- **Channel-numbering "no CHANNEL_SUCCESS".** libssh appeared not to acknowledge a
  `want_reply` exec request where wolfSSH did. Root cause: the seed hard-codes
  `recipient_channel = 0`, which matches wolfSSH's channel numbering but not
  libssh's (libssh picks `sender_channel = 43`), so libssh correctly ignored an exec
  request for a channel it never opened. Addressed to libssh's *actual* channel,
  libssh *does* send `CHANNEL_SUCCESS`. Neither stack is buggy — a seed artifact,
  not a library difference.

## The BENIGN taxonomy (all surviving decryption divergences)

After fixing the harness artifacts, every decrypted-content divergence across the
campaigns falls into one of these classes — all confirmed benign by transport-level
instrumentation of both stacks:

| signature (decrypted s2c) | class | why benign |
|---|---|---|
| `Unimplemented` vs `()` | RFC 4253 §11.4 latitude | libssh answers a *recognised-but-out-of-order* message with SSH_MSG_UNIMPLEMENTED; wolfSSH rejects it for ordering. §11.4's MUST covers only *unrecognised* message numbers, so both are defensible; both reject the input. |
| `UserAuthFailure` / `UserAuthSuccess` vs `()` | auth-reply flush timing | one stack flushes its auth reply before hitting a subsequent malformed packet, the other errors first; both ultimately reject. |
| `ServiceAccept` vs `()` | reply pipelining | RFC-permitted; wolfSSH emits an explicit SERVICE_ACCEPT packet where libssh pipelines past it. |
| `ChannelOpenConfirmation` / `ChannelSuccess` / `ChannelFailure` / `ChannelOpenFailure` vs `()` | channel packetisation / numbering | the stacks packetise channel replies differently, and the seed's fixed `recipient_channel` matches only one stack's numbering. |

Crucially, across the freshest 15,804-objective scan there were **zero content
divergences** (`InnerDifference` — same message kind, different bytes): the strongest
possible bug signal never fired.

## Coverage limits (honest scope)

- **Cipher:** only AES-256-GCM is exercised. ChaCha20-Poly1305 is absent from
  wolfSSH's cipher table; AES-CTR is not compiled into the vendored wolfSSL build
  (0 `AesCtr` symbols) — so GCM is the only cipher both stacks can negotiate here.
- **Direction:** all seeds are client-attacker (fuzzing the *server* stacks). The
  client parsers are not yet exercised (would need server-attacker seeds).
- **Depth:** recipes reach handshake completion and channel setup, not bulk
  post-auth channel *data*.
- **Channel-request accept/reject** cannot yet be compared cross-vendor: querying
  the server's real channel number requires the full CHANNEL_OPEN_CONFIRMATION
  before building the follow-up request, but wolfSSH flushes that packet's tail only
  when it processes the request itself (a chicken-and-egg the seed-term approach
  cannot break — documented; no bug is suspected there).
- **Un-triaged category:** `Knowledges`-other (non-decryption on-wire structured-message
  divergences) has not been characterised.

## Conclusion

The decryption differential is built, sound, and validated at ~1M-objective scale.
It found no genuine libssh↔wolfSSH library bug under decryption; the only real
divergences it surfaced were **our own harness artifacts**, which we fixed. This is
a strong, reproducible **negative result** — and a demonstration that oracle-free
decryption-level differential fuzzing is sound: it fires on real behavioural
asymmetry and, once the harnesses are thin and symmetric, returns clean.
