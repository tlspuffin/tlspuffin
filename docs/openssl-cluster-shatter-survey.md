# OpenSSL cluster survey — can we shatter the merged clusters?

**Scope:** the committed live-TCP model `reference/openssl` (11 clusters over 61 versions,
3.0.0–3.6.2, labels audited clean). Goal: understand every cluster boundary and rank the
merges by likelihood of a *wire-observable, server-side* split.

> **Correction (this revision).** An earlier version of this document concluded, from the
> changelog, that OpenSSL's inter-version changes were "only cosmetic / internal / config-gated"
> and the clusters were "not shatterable." **That conclusion was wrong and the method was
> unsound.** OpenSSL *does* make wire-observable changes between versions — the server emits
> **different alert codes on error paths** — and these are what create the cluster splits. The
> changelog does not mention them; the source *diff* does; and only *empirical* differential
> execution proves them. See §0 and §3. Conclusions below are now backed by differential-execute
> with K-replay, not changelog reading.

## 0. Method correction — what is a trustworthy source for wire-observability?

| Source | Does it reveal the observable alert-code changes? |
|---|---|
| `CHANGES.md` | **No.** e.g. the 3.4.0→3.4.1 entry lists an RPK CVE, an ECDSA timing CVE, a CMS revert — searching it for `alert`/`illegal`/`internal_error` returns nothing. Changelogs describe *intent/CVEs*, not wire side-effects. |
| Source **diff** | **Yes, if queried with the right idiom.** OpenSSL emits alerts via `SSLfatal(s, SSL_AD_*, …)`. The 3.4.0→3.4.1 diff of `ssl/statem/statem_srvr.c` (35 lines) contains: `SSLfatal(s, SSL_AD_INTERNAL_ERROR, …)` → `SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_KEY_SHARE)`. A scan that only greps `TLSX_*`/`ServerHello`/`SendAlert` (wolfSSL idioms) **misses it** — the original error here. |
| **Empirical** differential-execute (+ K-replay) | **Ground truth.** Exercises the real binaries; idiom- and reachability-independent. This is the authoritative source; source analysis is hypothesis generation only. |

## 1. Cluster structure = error-handling epochs (release waves)

OpenSSL ships coordinated security releases across all maintenance branches on one date. When
such a release changes a **server alert code**, all branches shift together, creating a
behavioral epoch. So clusters cut across minors:

| Cluster | Versions | Epoch |
|---|---|---|
| C0 (24) | 3.0.0–3.0.15, 3.1.0–3.1.7 | early 3.0/3.1 |
| C3 (6) | 3.0.16–3.0.20, 3.1.8 | late 3.0/3.1 |
| C1 (8) | 3.2.0–3.2.3, 3.3.0–3.3.2, 3.4.0 | early 3.2/3.3/3.4 |
| C5 (3) | 3.2.4, 3.3.3, 3.4.1 | mid wave |
| C2 (8) | 3.2.5–3.2.6, 3.3.4–3.3.6, 3.4.2–3.4.4 | late 3.2/3.3/3.4 |
| C6 (2) | 3.3.7, 3.4.5 | latest 3.3/3.4 |
| C4 (5) | 3.5.1–3.5.5 | 3.5 line |
| C7 (2) | 3.6.0–3.6.1 | 3.6 line |
| C8/C9/C10 | 3.5.0 / 3.5.6 / 3.6.2 | singletons |

## 2. The two observable dimensions OpenSSL actually changes

1. **Default supported-groups list** (minor boundaries). Diff of `ssl/t1_lib.c`: the group
   table is byte-identical across 3.2.0/3.3.0/3.4.0, and **ML-KEM is inserted at 3.5.0** —
   exactly where the model splits 3.5 off. New DHE_PSK/ECDHE_PSK ciphersuites + RPK at 3.2.0;
   server-preference + OCSP multi-stapling at 3.6.0.
2. **Server alert codes on error paths** (the wave boundaries). Stable, reproducible
   (differential-execute, 8/8), diff-visible via `SSLfatal(SSL_AD_*)`, changelog-invisible:
   - 3.4.0→3.4.1: `INTERNAL_ERROR` → `ILLEGAL_PARAMETER` (bad key share); `ProtocolVersion` → `RecordOverflow`
   - 3.4.1→3.4.2: `ILLEGAL_PARAMETER` → `DecodeError`

   This is genuine server-side robustness/error-handling hardening — precisely the class the
   changelog-only survey was blind to.

## 3. Are the merges real, or is the model under-clustering? (empirical)

> **Vocabulary.** **TCP-DIST** = distinguishable in theory on the wire. **PUFFIN-DIST(FFI)** =
> `differential-execute` on in-process PUTs finds a stable, self-consistent difference.
> **PUFFIN-DIST(live)** = the deployed live-TCP model distinguishes them.
> `live ⟹ FFI ⟹ TCP-DIST`; converses fail; ¬PUFFIN-DIST does **not** prove ¬TCP-DIST.

Noise-robust K-replay screen (K=6) over the **entire mined probe corpus**, requiring a split
to be stable *and* self-consistent (each version vs itself identical — these error paths are
nondeterministic):

| Pair (same cluster) | probes | 1-shot cand. | **stable splits** | verdict |
|---|---|---|---|---|
| 3.2.0 \| 3.2.3 (C1) | 639 | 0 | **0** | ¬PUFFIN-DIST(FFI) |
| 3.0.0 \| 3.1.7 (C0) | 639 | 0 | **0** | ¬PUFFIN-DIST(FFI) |
| 3.0.16 \| 3.1.8 (C3) | 639 | 0 | **0** | ¬PUFFIN-DIST(FFI) |
| 3.2.5 \| 3.4.4 (C2) | 639 | 0 | **0** | ¬PUFFIN-DIST(FFI) |
| 3.5.1 \| 3.5.5 (C4) | 639 | 0 | **0** | ¬PUFFIN-DIST(FFI) |

**Every tested OpenSSL within-cluster pair is ¬PUFFIN-DIST at the FFI level** — no stable wire
distinguisher in the mined corpus. The only intra-C1 difference ever seen (probe `…5047239`:
`RecordOverflow`↔`ProtocolVersion`) is **nondeterministic** (self-diffs on 3.2.0-vs-3.2.0), so
pooling correctly ignores it.

**Important contrast with the §2 diff-candidates:** the `SSLfatal(SSL_AD_*)` count deltas the
diff flagged for these very pairs (e.g. 3.2.5|3.4.4 adding `DH_KEY_TOO_SMALL`,
`EXCESSIVE_MESSAGE_SIZE`, binder `DECRYPT_ERROR`) **did not confirm empirically** — 0 stable
FFI splits. So those code changes are either unreached by the corpus or unreachable at all.
This is the method lesson made concrete: **diff-candidates are hypotheses; only the empirical
screen is ground truth.** (Compare wolfSSL C1 {5.7.6/5.8.0/5.8.2}, where the analogous alert
change *did* confirm — 79/8 stable FFI splits — so it is genuinely TCP-DIST. OpenSSL shows no
such confirmed case among the tested pairs.)

## 4. A masked lead (for completeness)

3.3→3.4.0 adds integrity-only ciphers `TLS_SHA256_SHA256` (`ssl/` refs 0→13), but they are
**not** in the default TLS 1.3 ciphersuite list (`TLS_AES_256_GCM_SHA384 :
TLS_CHACHA20_POLY1305_SHA256 : TLS_AES_128_GCM_SHA256`), so a default server won't negotiate
them. Config-gated, like wolfSSL PQC/OCSP.

## 5. Have we achieved maximum distinguishing on default config?

**Near it, but not provably at it** — and this is now an empirical statement, not a changelog one:
- The model captures both observable dimensions (group list + alert epochs). The wave splits
  it has are **real stable alert-code changes**.
- For the merges tested (3.2.0|3.2.3), the K-replay screen finds **zero** stable distinguishers
  across the full mined corpus → those merges are correct, the model is *not* under-clustering.
- **Residual uncertainty:** the mined corpus, though large and itself fuzzer-generated, is not
  exhaustive. Because OpenSSL's observable changes concentrate in *error paths* (which are also
  noise-prone), a fresh differential-fuzzing campaign **targeted at error paths with strong
  reproducibility filtering** is the only way to move from "no stable split in the corpus" to a
  proven ceiling. Until then, 11 clusters is a well-supported lower bound, tight on the
  explored input space.

## 6. Conclusion

OpenSSL's versions **do** evolve observably on the wire — chiefly by hardening which alert code
the server returns on bad input, plus default-group changes (ML-KEM at 3.5). The model tracks
these faithfully; the surviving within-epoch merges are empirically confirmed (K-replay) to
have no stable wire distinguisher. Splitting them further would require either a config change
(enable gated features) or a dedicated noise-robust error-path fuzzing campaign — not a
changelog.
