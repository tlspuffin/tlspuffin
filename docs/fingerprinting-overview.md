# DDYF TLS-library version fingerprinting — overview

Entry point for the version-fingerprinting work built on tlspuffin's differential fuzzer (DDYF).
It identifies the **version** of a remote TLS library by probing it as a **server** over TCP and
matching the wire response (handshake flight, alerts, connection disposition) against a decision
tree of pre-mined distinguishers.

## What it does

A Dolev-Yao client-attacker replays a small set of **decision probes** against the target server;
each probe's canonical wire signature selects a branch, and ≤4 probes land the server in a
**cluster** of indistinguishable versions. Two models ship:

| Model | Versions | Clusters | Tree depth | Probes | Live validation |
|---|---|---|---|---|---|
| WolfSSL 5.x | 24 (5.0.0–5.9.1) | **16** | 4 | 8 | 24/24 recognised, consistent |
| OpenSSL 3.x | 61 (3.0.0–3.6.2) | **11** | 4 | 4 | 60/61 recognised, consistent |

Full trees, per-cluster membership, and the wire distinguisher on every branch:
[`fingerprint-models-status.md`](fingerprint-models-status.md).

## `--fingerprinting` mode (core, PR 1)

All fingerprinting-specific behaviour in `puffin`/`tlspuffin` is guarded by a **single
`--fingerprinting` CLI flag** (global, off by default, threaded via `FuzzerConfig` so it reaches
fuzzer workers). Normal and differential fuzzing are unaffected unless the flag is set. It enables,
together:

1. **Corpus** (`CorpusOptions` → `tls::seeds::create_corpus`): client-attacker seeds only + the
   fingerprinting-only C1 probe seeds; drops MITM and server-attacker seeds.
2. **No PUT-config uniformisation**: each PUT is probed under its **real default config** (not the
   cross-implementation uniformised regime), so results match what a live stock server exposes.
3. **Wire-observable differential objectives**: status objectives are restricted to PUT-level
   outcomes, dropping non-deterministic tlspuffin-internal errors.

Two live-probe env-gates (used only by the `tcp` command; inert for in-process fuzzing):
`FP_EMIT_DISPOSITION` (emit terminal TCP disposition) and `PUFFIN_TCP_IO_SLEEP_MS` (I/O pacing so
slow live servers aren't truncated). Plus `tcp --sni`/`-g agent` for probing a live external target
by hostname. See the "Fingerprinting mode & controls" section of
[`README_fingerprinting.md`](../evaluation-ddyf/fingerprinting/README_fingerprinting.md).

The **RFC 7366 Encrypt-then-MAC** extension is modelled in the TLS message alphabet (a typed
Mapper, mirroring Extended-Master-Secret) — this is what enables the WolfSSL 5.1.1↔5.2.0
distinguisher (the 16th cluster) and lets the fuzzer rediscover it autonomously.

## Pipeline (evaluation, PR 2)

`evaluation-ddyf/fingerprinting/` — mine → matrix → tree → validate → report, plus a live-identify
driver. Reproduce the committed models:

```bash
# validate + report from the committed models (no campaigns needed)
PUFFIN_TCP_IO_SLEEP_MS=0   python3 run_fingerprint.py --put openssl --stages validate,report --timeout 12
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl --stages validate,report --timeout 15
# render either decision tree with live-TCP branch labels
python3 tree_report.py --put wolfssl --reference-dir "$(pwd)/reference"
```

How-to, internals, and the prober note: [`README_fingerprinting.md`](../evaluation-ddyf/fingerprinting/README_fingerprinting.md)
and [`DEVELOPER.md`](../evaluation-ddyf/fingerprinting/DEVELOPER.md).

**Committed vs excluded.** The models ship the decision `probes/` + `signatures.csv` + `tree.json`
+ `meta.json` + `report.md` (deployable & validatable, ~3.6 MB). The raw mined corpus
(`reference/*/probes_full/`, ~70 MB) and scratch (`reproduced*/`, `log/`, `experiments/`) are
git-ignored — `probes_full` is reproducible from the experiment archives.

## Analyses & findings

- [`fingerprint-models-status.md`](fingerprint-models-status.md) — model summary + both full
  decision trees (each branch labelled with its live-TCP wire distinguisher).
- [`wolfssl-cluster-merge-analysis.md`](wolfssl-cluster-merge-analysis.md) — why WolfSSL versions
  merge into shared clusters; the **TCP-DIST vs PUFFIN-DIST** distinction (theoretical wire
  distinguishability vs what our system/live model achieves).
- [`wolfssl-c1-split-analysis.md`](wolfssl-c1-split-analysis.md) — exhaustive source-diff proof
  that C1 {5.7.6, 5.8.0, 5.8.2} is a genuine merge on default config (splittable only against a
  TLS-1.3-only server).
- [`openssl-cluster-shatter-survey.md`](openssl-cluster-shatter-survey.md) — OpenSSL clusters are
  release-wave epochs (same-day cross-branch security releases); the observable dimension is the
  default group list + server alert codes.
- [`relaxed-replace-match-mutation.md`](relaxed-replace-match-mutation.md) — design note (not
  implemented) for a sub-signature replacement mutator.

## Key caveats

- **`wolfssl521` is mislabelled**: the vendored directory contains wolfSSL **5.0.1**, not 5.2.1
  (verified via `version.h` + code markers). The cluster the model prints as `{5.0.0, 5.2.1}` is
  really `{5.0.0, 5.0.1}` — adjacent patches.
- **16 / 11 clusters is the honest ceiling for the stock default-config live model.** Several
  merges are genuine (internal-crypto / client-side / DTLS / config-gated differences a passive
  remote observer cannot see); a few are TCP-DIST at the FFI level but not reproducible against a
  stock server (see the C1 analysis).
