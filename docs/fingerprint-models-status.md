# DDYF Fingerprinting Models — Status & Decision Trees

_Generated 2026-07-04 from the committed reference models
(`evaluation-ddyf/fingerprinting/reference/`) using `tree_report.py`._

Both models are **live-TCP** fingerprints: a Dolev-Yao client-attacker probes the PUT as a
**server** over TCP and observes only the unencrypted handshake flight, alerts, and connection
disposition. Each server is classified by replaying a small set of decision probes and matching
the wire response (canonical signature).

## Summary

| Metric | wolfSSL | OpenSSL |
|---|---|---|
| Versions covered | 24 | 61 |
| **Distinguishable clusters (tree leaves)** | **16** | **11** |
| **Tree depth** (max probes to classify) | **4** | **4** |
| **Decision probes used** | **8** | **4** |
| Live validation (recognised / consistent) | 24/24, 24/24 | 60/61, 60/61 |
| Validation walks | 5 | 5 |
| Probing parameters | N_POOL=30, DOM=21, retry=3, timeout=8.0s | sig-prefix len=10 (pooled) |

Notes:
- **wolfSSL 16 clusters** is the honest ceiling for the stock **default-config** live model.
  Cluster `{5.7.6, 5.8.0, 5.8.2}` (C1) is a confirmed genuine merge on default config; it can
  only be split 2-way ({5.7.6} | {5.8.0, 5.8.2}) against a **TLS-1.3-only** server — see
  `docs/wolfssl-c1-split-analysis.md`.
- Cluster `{5.0.0, 5.2.1}` is really **{5.0.0, 5.0.1}** — the `wolfssl521` directory is a
  mislabel (contains 5.0.1). See `docs/wolfssl-cluster-merge-analysis.md`.
- **OpenSSL clusters are release-wave epochs**: coordinated same-day security releases move all
  maintenance branches together, so clusters cut across minor versions. See
  `docs/openssl-cluster-shatter-survey.md`.
- The 1 non-recognised OpenSSL server (60/61) is a single noise-prone edge; the split rests on
  pooling out-voting nondeterministic error-path alerts.

Each branch below is labelled with the exact wire response at each flight step
(`N: <records>` / `Alert(<desc>)` / `(Terminated)` = TCP close), making every distinguisher
human-verifiable.

---

## wolfSSL decision tree (16 clusters, depth 4, 8 probes)

```

Decision Tree for WOLFSSL [Live (TCP)]
===================================
Versions: 24
Clusters: 16
Probes:   8
Depth:    4
Source:   evaluation-ddyf/fingerprinting/reference/wolfssl/tree.json
===================================

└── [Probe] 20260609-223621285-33c7da567f17ae4f.trace
    │
    ├── (1: (Terminated))
    │   ├── [Probe] 20260610-010911646-2c2af137200ba09d.trace
    │   │   │
    │   │   ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 4: (Terminated))
    │   │   │   ├── [Cluster] {5.6.0, 5.6.2, 5.6.3}
    │   │   │
    │   │   └── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 4: (Terminated))
    │   │       └── [Probe] 20260609-222832145-30ea54344987b100.trace
    │   │           │
    │   │           ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 1: Alert(HandshakeFailure) | 2: (Terminated))
    │   │           │   ├── [Cluster] {5.6.4}
    │   │           │
    │   │           └── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 1: Alert(UnexpectedMessage) | 2: (Terminated))
    │   │               └── [Probe] 20260609-222833190-062338c391042522.trace
    │   │                   │
    │   │                   ├── (0: Alert(HandshakeFailure) | 1: (Terminated))
    │   │                   │   ├── [Cluster] {5.7.0}
    │   │                   │
    │   │                   └── (0: Alert(UnexpectedMessage) | 1: (Terminated))
    │   │                       └── [Cluster] {5.6.6}
    │
    ├── (0: Alert(MissingExtension) | 1: (Terminated))
    │   ├── [Probe] 20260610-010911646-2c2af137200ba09d.trace
    │   │   │
    │   │   ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 4: (Terminated))
    │   │   │   ├── [Probe] seed_client_attacker12_etm.trace
    │   │   │   │   │
    │   │   │   │   ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 5: (Terminated))
    │   │   │   │   │   ├── [Probe] 20260609-222826816-e4c49967a70ff749.trace
    │   │   │   │   │   │   │
    │   │   │   │   │   │   ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 1: Alert(UnexpectedMessage) | 2: (Terminated))
    │   │   │   │   │   │   │   ├── [Cluster] {5.2.0}
    │   │   │   │   │   │   │
    │   │   │   │   │   │   └── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 2: (Terminated))
    │   │   │   │   │   │       └── [Cluster] {5.3.0}
    │   │   │   │   │
    │   │   │   │   └── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 5: (Terminated))
    │   │   │   │       └── [Cluster] {5.1.0, 5.1.1}
    │   │   │
    │   │   ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 4: (Terminated))
    │   │   │   ├── [Cluster] {5.5.2, 5.5.3}
    │   │   │
    │   │   └── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 4: (Terminated))
    │   │       └── [Cluster] {5.4.0}
    │
    ├── (0: Alert(MissingExtension) | 1: (Terminated))
    │   ├── [Cluster] {5.0.0, 5.2.1}
    │
    ├── (0: Alert(DecodeError) | 1: (Terminated))
    │   ├── [Probe] 20260610-010911646-2c2af137200ba09d.trace
    │   │   │
    │   │   ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 4: (Terminated))
    │   │   │   ├── [Probe] 20260609-223948410-9d8cf6eeba3b5691.trace
    │   │   │   │   │
    │   │   │   │   ├── (0: Alert(BadRecordMac) | 1: (Terminated))
    │   │   │   │   │   ├── [Cluster] {5.7.4}
    │   │   │   │   │
    │   │   │   │   └── (1: (Terminated))
    │   │   │   │       └── [Cluster] {5.7.6, 5.8.0, 5.8.2}
    │   │   │
    │   │   ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 4: (Terminated))
    │   │   │   ├── [Cluster] {5.7.2}
    │   │   │
    │   │   └── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 2: Alert(UnexpectedMessage) | 3: (Terminated))
    │   │       └── [Probe] 20260609-222849778-18c1fbc4990d2b63.trace
    │   │           │
    │   │           ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 2: Alert(HandshakeFailure) | 3: (Terminated))
    │   │           │   ├── [Cluster] {5.8.4}
    │   │           │
    │   │           └── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 1: Alert(IllegalParameter) | 2: (Terminated))
    │   │               └── [Cluster] {5.9.0, 5.9.1}
    │
    └── (1: (Terminated))
        └── [Cluster] {5.5.4}
```

---

## OpenSSL decision tree (11 clusters, depth 4, 4 probes)

```

Decision Tree for OPENSSL [Live (TCP)]
===================================
Versions: 61
Clusters: 11
Probes:   4
Depth:    4
Source:   evaluation-ddyf/fingerprinting/reference/openssl/tree.json
===================================

└── [Probe] 20260530-204752305-e7af3188d2cd4bd0.trace
    │
    ├── (0: Alert(HandshakeFailure) | 1: (Terminated))
    │   ├── [Probe] 20260607-223951010-666587518dcd84d2.trace
    │   │   │
    │   │   ├── (0: HelloRetryRequest | 1: Alert(DecodeError) | 2: (Terminated))
    │   │   │   ├── [Probe] 20260530-212050106-38039c5796ff7415.trace
    │   │   │   │   │
    │   │   │   │   ├── (0: Alert(ProtocolVersion) | 1: (Terminated))
    │   │   │   │   │   ├── [Cluster] {3.3.7, 3.4.5}
    │   │   │   │   │
    │   │   │   │   └── (0: Alert(RecordOverflow) | 1: (Terminated))
    │   │   │   │       └── [Cluster] {3.2.5, 3.2.6, 3.3.4, 3.3.5, 3.3.6, 3.4.2, 3.4.3, 3.4.4}
    │   │   │
    │   │   ├── (0: HelloRetryRequest | 1: Alert(DecodeError) | 2: (Terminated))
    │   │   │   ├── [Probe] 20260602-165047239-50d6883ba2e9f7af.trace
    │   │   │   │   │
    │   │   │   │   ├── (0: Alert(ProtocolVersion) | 1: (Terminated))
    │   │   │   │   │   ├── [Probe] 20260530-212050106-38039c5796ff7415.trace
    │   │   │   │   │   │   │
    │   │   │   │   │   │   ├── (0: Alert(ProtocolVersion) | 1: (Terminated))
    │   │   │   │   │   │   │   ├── [Cluster] {3.5.6}
    │   │   │   │   │   │   │
    │   │   │   │   │   │   └── (0: Alert(RecordOverflow) | 1: (Terminated))
    │   │   │   │   │   │       └── [Cluster] {3.5.0}
    │   │   │   │   │
    │   │   │   │   └── (0: Alert(RecordOverflow) | 1: (Terminated))
    │   │   │   │       └── [Cluster] {3.5.1, 3.5.2, 3.5.3, 3.5.4, 3.5.5}
    │   │   │
    │   │   └── (0: HelloRetryRequest | 1: Alert(IllegalParameter) | 2: (Terminated))
    │   │       └── [Probe] 20260530-212050106-38039c5796ff7415.trace
    │   │           │
    │   │           ├── (0: Alert(ProtocolVersion) | 1: (Terminated))
    │   │           │   ├── [Cluster] {3.0.16, 3.0.17, 3.0.18, 3.0.19, 3.0.20, 3.1.8}
    │   │           │
    │   │           └── (0: Alert(RecordOverflow) | 1: (Terminated))
    │   │               └── [Cluster] {3.2.4, 3.3.3, 3.4.1}
    │
    ├── (0: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone | 1: Alert(DecodeError) | 2: (Terminated))
    │   ├── [Probe] 20260530-212050106-38039c5796ff7415.trace
    │   │   │
    │   │   ├── (0: Alert(ProtocolVersion) | 1: (Terminated))
    │   │   │   ├── [Cluster] {3.6.2}
    │   │   │
    │   │   └── (0: Alert(RecordOverflow) | 1: (Terminated))
    │   │       └── [Cluster] {3.6.0, 3.6.1}
    │
    └── (0: Alert(HandshakeFailure) | 1: (Terminated))
        └── [Probe] 20260530-212050106-38039c5796ff7415.trace
            │
            ├── (0: Alert(ProtocolVersion) | 1: (Terminated))
            │   ├── [Cluster] {3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.0.7, 3.0.8, 3.0.9, 3.0.10, 3.0.11, 3.0.12, 3.0.13, 3.0.14, 3.0.15, 3.1.0, 3.1.1, 3.1.2, 3.1.3, 3.1.4, 3.1.5, 3.1.6, 3.1.7}
            │
            └── (0: Alert(RecordOverflow) | 1: (Terminated))
                └── [Cluster] {3.2.0, 3.2.1, 3.2.2, 3.2.3, 3.3.0, 3.3.1, 3.3.2, 3.4.0}
```
