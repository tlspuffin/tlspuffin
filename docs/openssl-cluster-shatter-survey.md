# OpenSSL cluster survey — can we shatter the merged clusters?

**Scope:** the committed live-TCP model `reference/openssl` (11 clusters over 61 versions,
3.0.0–3.6.2, labels audited clean). Goal: survey every cluster-boundary using the official
OpenSSL `CHANGES.md` (refined with `ssl/` source diffs) and rank each merge by the
likelihood of a *wire-observable, server-side* split.

**Observation channel (reminder):** a Dolev-Yao client-attacker probes the PUT **as a
server** over TCP. Only the server's unencrypted handshake bytes, echoed extensions,
negotiated cipher/group, alerts, and connection disposition are observable.

---

## 1. The cluster structure is *release waves*, not minor versions

Unlike wolfSSL, OpenSSL ships coordinated security fixes across all maintenance branches on
the same day, so clusters cut **across** minors into behavioral epochs:

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

Two merge types to attack: **cross-minor merges** (within C0, C1 — the high-value targets)
and **within-minor patch runs** (like wolfSSL, mostly internal).

## 2. Minor-boundary survey (CHANGES.md)

| Boundary | Model | What changed (CHANGES) | Wire-observable on default server? |
|---|---|---|---|
| 3.0 → 3.1.0 | **MERGED (C0)** | cosmetic `s_client/s_server` messages only | **No** — nothing on the wire |
| 3.2 → 3.3.0 | **MERGED (C1)** | `SSL_OP_PREFER_NO_DHE_KEX` (opt-in), groups-config tweaks | **No** — config-gated, off by default |
| 3.3 → 3.4.0 | **MERGED (C1)** | integrity-only ciphers `TLS_SHA256_SHA256`; empty renegotiate ext (client-side); X.509 exts | **No (masked)** — see §4 |
| 3.1 → 3.2.0 | SPLIT | **DHE_PSK/ECDHE_PSK ciphersuites**, RPK negotiation, QUIC | **Yes** — new cipher/negotiation behavior |
| 3.4 → 3.5.0 | SPLIT | **default group list changed + ML-KEM added**; multi key-share | **Yes** — the dominant OpenSSL fingerprint |
| 3.5 → 3.6.0 | SPLIT | `SSL_OP_SERVER_PREFERENCE`, TLS 1.3 OCSP multi-stapling | **Yes** — server-preference / stapling |

**The confirmed observable dimension is the default supported-groups list.** Diff of
`ssl/t1_lib.c`: the group table is **byte-identical across 3.2.0 / 3.3.0 / 3.4.0** (brainpool
+ ffdhe + ECC), and **3.5.0 is the version that inserts ML-KEM** — precisely the boundary
where the model splits. This is why C1 cannot be split on groups.

## 3. Patch-wave survey (what the model already distinguishes)

The epoch boundaries (C1→C5→C2, C0→C3) are coordinated security releases. Their CHANGES
entries are subtle handshake-behavior fixes, e.g.:
- **3.2.3→3.2.4** (C1→C5): RFC 7250 raw-public-key abort fix (largely client-side).
- **3.2.4→3.2.5** (C5→C2): aligned no_renegotiation-alert behavior (mostly DTLS).

These produce fine-grained differences the sig-prefix probes pick up, but they are
CVE-driven micro-behaviors, not extendable feature levers.

## 4. Why the top shatter lead is masked

**3.3 → 3.4.0 via integrity-only ciphers** was the most promising merged-boundary lead:
`TLS_SHA256_SHA256` support appears in 3.4.0 (`ssl/` refs 0 → 13). **But** the default TLS 1.3
ciphersuite list in 3.4.0 is only:
```
TLS_AES_256_GCM_SHA384 : TLS_CHACHA20_POLY1305_SHA256 : TLS_AES_128_GCM_SHA256
```
Integrity-only suites are **not** default — they require explicit
`SSL_CTX_set_ciphersuites`. A stock 3.4.0 server will not negotiate them, so a probe offering
`TLS_SHA256_SHA256` is refused by both 3.3 and 3.4 → **masked**, exactly like wolfSSL's
non-compiled PQC and unconfigured OCSP.

## 5. Ranked shatter targets

| Target | Split would yield | Lever | Verdict |
|---|---|---|---|
| C1: 3.3 \| 3.4.0 | separate 3.4.x from 3.2/3.3 | integrity-only ciphers | **Conditional** — needs a server that enables them + a Mapper cipher-suite addition |
| C1: 3.2 \| 3.3.0 | separate 3.2 from 3.3 | `SSL_OP_PREFER_NO_DHE_KEX` | **Low** — opt-in config only |
| C0: 3.0 \| 3.1.0 | separate 3.0.x from 3.1.x | — | **None** — no default wire change |
| C0/C1 patch runs | separate adjacent patches | — | **None** — internal/CVE/DTLS |

The **only** systematic, default-reachable lever OpenSSL exposes — the supported-groups list
(incl. ML-KEM) — is already fully exploited by the model at the boundaries where it changes
(3.5.0). Within the surviving clusters it is constant.

## 6. Conclusion (parallels the wolfSSL analysis)

OpenSSL's within-cluster merges are, with no default-reachable exception found, **not
shatterable on the stock server**. The inter-version changes inside a cluster are internal
crypto, client-side, opt-in/config-gated features, or DTLS — none alter the default server's
observable handshake. The clusters faithfully track the few things OpenSSL *does* change on
the default wire path (group list/ML-KEM, new ciphersuites/RPK, server-preference/stapling),
which is exactly what separates the clusters that *are* distinct.

**11 clusters is the honest live-TCP ceiling for this OpenSSL version set on stock servers.**

### What could enable further splits (all require leaving "stock")
- **Config-matched servers** exposing the gated features: enable integrity-only ciphersuites
  (splits 3.4.x), enable OCSP stapling (may sharpen 3.6), set non-default group priorities.
  Each also needs a small **Mapper addition** (integrity cipher-suite id; already have EtM as
  the template) — but such splits only fingerprint deployments that *turn the feature on*.
- **Decrypt-aware offline signature** — sees claims/decrypted content; not a remote fingerprint.
