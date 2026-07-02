# Why the WolfSSL fingerprinting model cannot distinguish every version

**Scope:** the committed live-TCP model `evaluation-ddyf/fingerprinting/reference/wolfssl`
(16 clusters, depth 4, 8 probes, validated 24/24). This report explains, cluster by cluster,
*why* the versions merged into one cluster are not distinguishable — backed by the official
wolfSSL `ChangeLog.md` and the vendored source diffs — and gives a unifying taxonomy.

**Method.** For each merged cluster: (1) verify the vendored version label
(`version.h`), (2) read the official ChangeLog entries for the version bump, (3) scan the
diff of the handshake-relevant sources (`tls.c`, `tls13.c`, `internal.c`) for **server-side,
passively-wire-observable** changes (extension echo `TLSX_SetResponse`, `ServerHello`
shaping, `SendAlert` description, TLS 1.3 receive-path state machine). The fingerprinter is a
Dolev-Yao **client-attacker probing a server** over TCP; it only ever sees the server's
*unencrypted* handshake bytes, alerts, and connection disposition.

---

## The 6 merged groups (of 24 modelled versions)

| Cluster | Versions | Verdict |
|---|---|---|
| C-etm-lo | 5.1.0, 5.1.1 | internal crypto CVE — not observable |
| C-55 | 5.5.2, 5.5.3 | internal memory-safety fix — not observable |
| C-56 | 5.6.0, 5.6.2, 5.6.3 | client-side / config-gated / DTLS / internal — not observable |
| C-58 | 5.7.6, 5.8.0, 5.8.2 | real features but **build/config-masked** (PQC off, OCSP unconfigured) |
| C-59 | 5.9.0, 5.9.1 | cert-verification / DTLS / PKCS7 CVEs — client-side or non-TLS |
| C-00 | 5.0.0, "5.2.1" | **data bug: "5.2.1" is actually 5.0.1** (adjacent patch) |

---

## Per-cluster analysis

### {5.1.0, 5.1.1} — internal crypto fix only
- **ChangeLog 5.1.1:** a single High CVE — *CVE-2022-23408*: "the IV being used is not
  random" for AES-CBC/DES3 in TLS/DTLS 1.2/1.1 (non-AEAD only).
- **Diff:** `tls.c=0, tls13.c=0, internal.c=2` changed lines — essentially no handshake code.
- **Why merged:** the fix randomizes the CBC record IV — an *encrypted record-layer* value.
  A passive observer cannot tell a random from a non-random IV without breaking the cipher,
  and our probes negotiate AEAD anyway. Nothing in the observable handshake changed.
  **Genuinely indistinguishable — correct merge.**

### {5.5.2, 5.5.3} — internal memory-safety fix only
- **ChangeLog 5.5.3:** a single bug fix — a buffer-zeroization overrun that only triggers on
  a failed memory allocation / hardware fault, "(D)TLS 1.3 only and crypto only users are not
  affected."
- **Diff:** `tls.c=0, tls13.c=0, internal.c=12`.
- **Why merged:** a defensive memory-masking fix on an error path; no change to any emitted
  byte, message, or alert. **Genuinely indistinguishable — correct merge.**

### {5.6.0, 5.6.2, 5.6.3} — substantial diff, but nothing server-observable
- **Diffs:** 5.6.0→5.6.2 is large (`tls13.c=224, internal.c=521`); 5.6.2→5.6.3 small
  (`internal.c=119`).
- **ChangeLog 5.6.2** (the big gap) — every item is out of the observable server path:
  - AES cache-timing hardening (internal crypto; opt-in `WOLFSSL_AES_TOUCH_LINES`).
  - TLS 1.3 predictable-IKM CVE — explicitly **client-side** ("does not affect client
    validation of connected servers").
  - RFC 9325 hardening — **opt-in** (`--enable-harden-tls`), off by default.
  - DTLS 1.3 integrity-only cipher suites — **DTLS**, not TLS-over-TCP.
  - TLS 1.3 stateful tickets under `SSL_OP_NO_TICKET`, Ed25519/Ed448 caching optimization —
    config-gated / internal, no default ServerHello change.
- **ChangeLog 5.6.3:** 4 fixes — atomic-macro build option, a Windows `GCM_TABLE_4BIT`
  compile fix, encrypted-memory internal improvements, and "Improvements to SendAlert for
  getting output buffer" (an internal buffer-acquisition refactor — the diff's
  `SendAlert(ssl, alert_fatal, why)` is the *macro definition*, not a new alert).
- **Scan:** no distinct `TLSX_SetResponse` / `ServerHello` / real-alert change in any file.
- **Why merged:** the changes are internal crypto, client-side, DTLS, opt-in, or
  build/refactor. None alter the default server's observable handshake. **Correct merge.**

### {5.7.6, 5.8.0, 5.8.2} — real features, but masked by the stock build/config
(Analyzed separately in depth.)
- **5.7.6→5.8.0** adds two *wire-observable-in-principle* server behaviors: post-quantum
  **ML-KEM key shares** and an **OCSP `status_request` echo**. Both are **masked**:
  - PQC/ML-KEM is **not compiled** into any vendored build (0 `HAVE_PQC`/`MLKEM` defines) —
    the server ignores PQC groups.
  - `status_request` echo is gated on `ssl->ocspRespSz > 0` — it only fires with an OCSP
    responder callback the stock example server never configures.
- **5.8.0→5.8.2:** internal refactor only (downgrade-config plumbing, `TLSX_IsGroupSupported`
  helper, key-share handling); the "new `unexpected_message` alerts" were a diff-alignment
  artifact (both versions have 6). No wire-observable difference; FFI shows none on standard
  handshakes.
- **Why merged:** the library differs, but the *stock example server* does not exercise the
  differing paths. Splitting 5.7.6 from {5.8.0, 5.8.2} would require a **PQC-enabled server
  build + a Mapper extension for PQC groups**; 5.8.0 vs 5.8.2 has no reachable wire
  difference at all. This is the only cluster with a (conditional) path to a split.

### {5.9.0, 5.9.1} — CVE fixes, all client-side or non-TLS-over-TCP
- **ChangeLog 5.9.1:** a large release, but the substantive items are out of the observable
  server handshake:
  - Signature-verification hardening (ECDSA/DSA/ML-DSA/EdDSA digest-size checks) — **certificate
    verification**, i.e. the *client* validating the server, not the server's emitted bytes.
  - DTLS 1.3 ACK heap overflow, "DTLS 1.3 ServerHello legacy_session_id" fix — **DTLS**.
  - PKCS7 / ECCSI overflows — **not TLS handshake**.
  - PQC hybrid KeyShare double-free — a **client** parsing a malicious server's ServerHello.
  - `MD5 disabled by default`, `heapmath deprecated` — build/config.
- **Diff:** very large (`tls.c=1260`) but the scan finds no server-side ServerHello/extension/
  alert change; the churn is crypto, cert-parsing, DTLS, and build.
- **Why merged:** none of the 5.9.1 changes alter what a client sees from a 5.9.x **server**
  over TLS-over-TCP. **Correct merge** for this observation channel.

### {5.0.0, "5.2.1"} — a data-labeling bug (actually {5.0.0, 5.0.1})
- **Finding:** the directory `vendor/wolfssl521` (which the dirname-regex reads as "5.2.1")
  contains wolfSSL **5.0.1** — confirmed three ways: `version.h` = `5.0.1` / `0x05000001`;
  the 5.2.0 EtM block-cipher gating is **absent** (like 5.0.0, unlike 5.2.0); the 5.2.0
  certificate-case `clientState` check is **absent**. A full audit of all vendored dirs shows
  this is the *only* mismatch, and the real 5.2.1 is not vendored at all.
- **Consequence:** the cluster is really **{5.0.0, 5.0.1}** — adjacent patch releases. The
  5.0.0→5.0.1 diff has no server-side wire-observable change (only whitespace/API/config
  churn). Also dissolves the earlier "5.2.1 reverted the EtM gating" *anomaly* — it was simply
  pre-5.2.0 5.0.1 echoing EtM normally; the EtM boundary is a clean pre/post-5.2.0 split.
- **Action:** re-vendor the correct 5.2.1 (and re-mine), or relabel the dir to `wolfssl501`
  so the model reports the version it actually tests.

---

## Unifying taxonomy — five reasons a version bump is invisible to us

Every merge falls into one or more of these, none of which a passive TLS-over-TCP client
probing a **server** can observe:

1. **Internal crypto / memory** — IV randomization (5.1.1), buffer zeroization (5.5.3), AES
   cache-timing (5.6.2). Changes computed/secret values or timing, not handshake structure.
2. **Client-side behavior** — certificate/signature verification (5.9.1), predictable-IKM
   (5.6.2), PQC ServerHello parsing (5.9.1). Irrelevant when the PUT is the **server**.
3. **Build/config-gated features** — PQC/ML-KEM (5.8.0, off), OCSP `status_request` callback
   (5.8.0, unconfigured), RFC 9325 harden-tls (5.6.2, opt-in), ticket options. Present in
   source, dormant in the stock example server.
4. **Different transport / API** — DTLS (5.6.2, 5.9.1), PKCS7 / ECCSI (5.9.1). Not
   TLS-over-TCP.
5. **Build-system / refactor churn** — macro options and `SendAlert` buffer handling (5.6.3),
   whitespace, X509 API. No behavioral change on the wire.

**The through-line:** wolfSSL's patch and even minor releases overwhelmingly fix *internal*
bugs/CVEs and add *opt-in* features. The bytes a stock server puts on the wire during a
handshake — version, cipher, groups, echoed extensions, alerts, connection disposition —
change rarely, and only those changes are fingerprintable passively. The EtM split (5.1.1 |
5.2.0, giving cluster 16) is the exception that proves the rule: a **default-reachable,
observable change in what the server echoes** — precisely because 5.2.0 briefly altered an
extension-echo decision on the default path.

## What could split the remaining merges
- **{5.7.6} vs {5.8.0, 5.8.2}:** rebuild servers with PQC/ML-KEM enabled + add a Mapper PQC
  group/key-share (conditional, only distinguishes PQC-enabled deployments).
- **Everything else:** not splittable on the live-TCP channel. The **decrypt-aware offline
  signature** (which sees claims/decrypted content, ~21 clusters historically) is the only
  route, and it is not a *remote* fingerprint.
- **Data fix:** relabel/re-vendor `wolfssl521` (really 5.0.1) so the model is honest about the
  versions it covers.

## Bottom line
The 6 merges are, with one exception, **correct and expected**: the inter-version differences
live in dimensions a passive remote observer cannot see (internal crypto/memory, client-side
validation, dormant features, non-TCP transports, refactors). 16 clusters is the honest
live-TCP ceiling for this version set and probe channel. The single actionable defect is the
`wolfssl521`→5.0.1 mislabel.
