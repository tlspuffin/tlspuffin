# Why the WolfSSL fingerprinting model cannot distinguish every version

**Scope:** the committed live-TCP model `evaluation-ddyf/fingerprinting/reference/wolfssl`
(16 clusters, depth 4, 8 probes, validated 24/24). This report explains, cluster by cluster,
*why* the versions merged into one cluster are not distinguished — backed by the official
wolfSSL `ChangeLog.md`, vendored source diffs, and (authoritatively) empirical
differential-execute.

> **Vocabulary (use these three levels; do not conflate them).**
> - **TCP-DIST** — distinguishable *in theory* on the wire: some client behaviour over TCP
>   yields a differing server response. A ground-truth property of the binaries.
> - **PUFFIN-DIST (FFI)** — tlspuffin's `differential-execute` on the in-process PUTs finds a
>   *stable, self-consistent* difference. Implies TCP-DIST.
> - **PUFFIN-DIST (live)** — the deployed live-TCP model (probing the stock example server)
>   distinguishes them. This is what the 16 clusters measure.
>
> Implications: `PUFFIN-DIST(live) ⟹ PUFFIN-DIST(FFI) ⟹ TCP-DIST`. The converses fail.
> **¬PUFFIN-DIST does *not* prove ¬TCP-DIST** — a better Mapper / smarter fuzzing could reach a
> wire difference we currently miss. Empirical screens below establish PUFFIN-DIST facts, not
> TCP-DIST impossibility.

> **Headline empirical result (K=6 replay over the full mined corpus, self-consistency
> filtered).** Cluster **C1 {5.7.6, 5.8.0, 5.8.2} is TCP-DIST and the live model
> under-clusters it**: 5.7.6|5.8.0 = **79/767** stable distinguishing probes, 5.8.0|5.8.2 =
> **8/767**, all a clean `Different(IllegalParameter, MissingExtension)` server alert-code
> difference — so PUFFIN-DIST(FFI)=YES, TCP-DIST=YES. But those probes replay to **EMPTY** over
> live-TCP against the stock example server, so PUFFIN-DIST(live)=NO → merged. This is a real
> FFI→live channel gap. **Every other merged pair is ¬PUFFIN-DIST at the FFI level too**
> (0 stable across 767 probes) — strong (not conclusive) evidence of ¬TCP-DIST.

**Method.** For each merged cluster: (1) verify the vendored version label
(`version.h`), (2) read the official ChangeLog entries for the version bump, (3) scan the
diff of the handshake-relevant sources (`tls.c`, `tls13.c`, `internal.c`) for **server-side,
passively-wire-observable** changes (extension echo `TLSX_SetResponse`, `ServerHello`
shaping, `SendAlert` description, TLS 1.3 receive-path state machine). The fingerprinter is a
Dolev-Yao **client-attacker probing a server** over TCP; it only ever sees the server's
*unencrypted* handshake bytes, alerts, and connection disposition.

> **Method caveat (added after the OpenSSL survey).** Changelog + diff reading is
> **hypothesis generation, not proof**, of wire-observability. Two failure modes bit the
> companion OpenSSL analysis and could bite here:
> (1) **Changelogs are structurally blind** to wire side-effects — a security fix can silently
> change *which alert code* a server returns without any changelog mention.
> (2) **Diff scans must be idiom-complete** — wolfSSL emits alerts via
> `SendAlert(ssl, alert_fatal, <description>)`; a scan that greps the wrong forms can conclude
> "nothing observable" from an incomplete search. The authoritative source is **empirical
> differential-execute with K-replay**. Where this report says "not observable," treat the
> claim as verified *only* where an empirical line below says so.

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
- **Empirical (K=6 replay over the full mined corpus).** `differential-execute wolfssl510
  wolfssl511` over all **767** mined probes → **0 differing probes even at 1-shot**.
  So **¬PUFFIN-DIST (FFI)** — 5.1.0/5.1.1 are identical on every probe our system has. This is
  strong evidence of **¬TCP-DIST**, but not proof: a probe outside the corpus, or a Mapper
  extension, could in principle still find a difference. Consistent with the changelog (IV
  randomisation is an encrypted-record change, not handshake-structural).

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

### {5.7.6, 5.8.0, 5.8.2} — **TCP-DIST; the live model under-clusters this** ⚠️
This is the one cluster that is genuinely distinguishable and wrongly merged by the live model.
- **Empirical (K=6, full corpus).** `differential-execute` finds **stable, self-consistent**
  splits on the mined probes: **5.7.6|5.8.0 = 79/767**, **5.8.0|5.8.2 = 8/767**, all a clean
  server alert-code difference `Different(IllegalParameter, MissingExtension)`. So all three are
  **pairwise PUFFIN-DIST(FFI) ⟹ TCP-DIST**. (An earlier draft's PQC/OCSP "masking" story was a
  side-issue; the real, empirically-confirmed distinguisher is the alert code.)
- **But PUFFIN-DIST(live) = NO.** Replaying those same probes over live-TCP against the stock
  example server yields **EMPTY from every version** (6/6), so they don't distinguish live and
  the model merges them. The split exists at the library/FFI level but the live-TCP replay of
  these FFI-mined traces doesn't elicit the alert.
- **Resolved (see `wolfssl-c1-split-analysis.md` for the full, exhaustive analysis).** A
  purpose-built probe (`seed_client_attacker13_no_sigalgs`) isolates the real mechanism:
  5.8.0 hardened the TLS 1.3 missing-`signature_algorithms` check (5.7.6 accepts, 5.8.0/5.8.2
  reject `missing_extension`). It splits **{5.7.6} | {5.8.0, 5.8.2}** live, but **only against a
  TLS-1.3-only server** (`-v 4` / a 1.3-only deployment); on the **default v23 dual-stack** stock
  server it is masked (the server negotiates TLS 1.2 or fails earlier with a version-independent
  `handshake_failure`).
- **5.8.0 vs 5.8.2: no server-observable difference on any config.** An exhaustive
  function-by-function source diff (server-built messages, `DoTls13ClientHello`, 1.2 path,
  key-share/group selection, PSK, record layer) shows every inter-version change is DTLS,
  client-side, internal crypto, a disabled-by-default feature (ECH/PQC), a pure rename, or a
  config-gated path. So on a **default build** C1 is a **genuine merge**; the only achievable
  split is the 2-way {5.7.6}|{5.8.0,5.8.2} on a TLS-1.3-only server. This corrects the earlier
  "single best lead / FFI-provable count ≥ 18 / C1→3" framing below.

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

## Bottom line (empirically re-assessed)
- **C1 {5.7.6, 5.8.0, 5.8.2} is TCP-DIST at the FFI level but a genuine merge on default build.**
  An exhaustive source diff (`wolfssl-c1-split-analysis.md`) shows all three are wire-identical
  on every observable default-config handshake path. The only real server-observable difference
  (5.8.0's missing-`signature_algorithms` hardening) splits **{5.7.6} | {5.8.0, 5.8.2}** only
  against a **TLS-1.3-only server** (`-v 4`); it is masked on the default v23 dual-stack stock
  server. **5.8.0 vs 5.8.2 has no server-observable difference on any config.** So a live split
  of C1 is achievable only as a **2-way** split, and only under a 1.3-only server config — not
  on the stock default.
- **All 5 other merges are ¬PUFFIN-DIST at the FFI level** (0 stable across 639–767 mined
  probes): 5.1.0|5.1.1, 5.5.2|5.5.3, 5.6.0|5.6.2, 5.6.2|5.6.3, 5.9.0|5.9.1, 5.0.0|5.0.1.
  Strong evidence of ¬TCP-DIST, consistent with their changelogs (internal crypto/memory,
  client-side, non-TCP, refactor) — but **not proof**: a better Mapper/fuzzer could still find
  a difference. These are honest ¬PUFFIN-DIST verdicts, not proven TCP-indistinguishability.
- Data defect: the `wolfssl521`→5.0.1 mislabel.

So **16 clusters is the honest ceiling for the stock default-config live model.** C1's FFI-level
distinguishability does not translate to a default-server split; only a TLS-1.3-only reference
server config would yield a 2-way C1 split (→ 17), never the full C1→3.

**Cross-reference:** the companion `openssl-cluster-shatter-survey.md` shows the *positive*
side of the same coin — OpenSSL versions **do** change observably, via server **alert-code
hardening** on error paths (e.g. `INTERNAL_ERROR`→`ILLEGAL_PARAMETER`), which is
changelog-invisible but diff-visible (`SSLfatal(SSL_AD_*)`) and empirically stable. wolfSSL's
analog would be `SendAlert` description changes; the empirical screen above found none between
5.1.0/5.1.1, but that idiom should be the first thing checked for any wolfSSL pair before
declaring it merged.
