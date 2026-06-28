# DDYF Version-Fingerprinting — Report (audited)

This document records the **verified** state of the DDYF version-fingerprinting pipeline for WolfSSL
and OpenSSL. Every number below was produced by re-running the committed pipeline live; figures that
could not be reproduced have been removed. See "Audit trail" for what changed and why.

> Status: WolfSSL model improved from 12 → **15** robustly-distinguishable clusters (live-validated
> 24/24). OpenSSL unchanged from the prior model (60/61, coarse). The previously-claimed "22
> clusters / 100% / production-ready" figure was **not reproducible** and has been retracted.

---

## Executive summary (verified)

| Metric | Prior model (`reference/`) | New model (`reproduced_strict/`) | How verified |
| :--- | :--- | :--- | :--- |
| **WolfSSL clusters** | 12 | **15** | full strict rebuild, all 806 probes |
| **WolfSSL live validation** | 24/24 consistent | **24/24 consistent** (≤4 traces) | `validate.py`, 5 walks/server |
| **OpenSSL clusters** | 11 | 11 (unchanged) | tree identical to prior |
| **OpenSSL live validation** | 60/61 | 60/61 consistent | `validate.py`, 5 walks/server |
| **Probing filter** | N_POOL=10/DOM=7 | **N_POOL=30, DOM=21, timeout=8s, retry=3** | recorded in `meta.json`/`validation.json` |

The WolfSSL gain (12 → 15) is real and deployment-validated. It is **+3**, not +10: the full strict
rebuild over the entire mined probe set yields exactly 15 clusters — the same 15 found by an
independent targeted re-measurement.

---

## Method (reproducible)

LLM-free. Differential-fuzzing campaigns mine candidate probe traces; each probe is replayed over a
real TCP socket against every vendored server; the **reproducibility filter** keeps only a server's
dominant signature (modal max-depth response recurring ≥ DOM of N_POOL connections, with `retry`
re-pools), and an ID3-style tree is induced over the resulting matrix. A server is identified by
walking the tree and replaying ≤ depth probes.

**Probing parameters are now first-class** (previously hardcoded constants that the docs misreported):

* Settable on every stage via `--n-pool / --dom / --retry / --timeout` (CLI > env
  `FP_N_POOL/FP_DOM/FP_RETRY/TIMEOUT` > default 10/7/3/12).
* **Recorded with the model** in `meta.json` and with the result in `validation.json`, and printed in
  `report.md`.
* A committed model **self-describes** its filter: `validate.py` / `fingerprint_probe.py` adopt the
  model's recorded params automatically (an explicit CLI/env value still wins). So a 30/21 model is
  reproduced at 30/21 without anyone having to know that out-of-band.

Reproduce the WolfSSL model:

```
run_fingerprint.py --put wolfssl --reference-dir <dir> --stages validate,report
# validate adopts N_POOL=30, DOM=21, timeout=8s, retry=3 from the model's meta.json
```

---

## Results

### WolfSSL — 15 clusters, 24/24 live (`reproduced_strict/wolfssl/`)
24 releases (5.0.0–5.9.1; 5.5.0/5.5.1 excluded — example server does not build). 15
distinguishability clusters, tree depth 4, 7 decision probes. Live validation: **24/24 recognised,
24/24 consistent across 5 walks, ≤4 traces each.** Multi-version clusters (genuinely
indistinguishable over the current probe set + canon): {5.1.0, 5.1.1, 5.2.0}, {5.6.0, 5.6.2, 5.6.3},
{5.7.6, 5.8.0, 5.8.2}, {5.0.0, 5.2.1}, {5.5.2, 5.5.3}, {5.9.0, 5.9.1}.

### OpenSSL — 11 clusters, 60/61 live (unchanged)
61 releases (3.0.0–3.6.2) collapse to 11 clusters; 787 of 1830 pairs are indistinguishable, so
"60/61 recognised" is mostly correct-bucket placement, not version-level identification. This model
is byte-identical to the prior session's; the recent work did not change it.

---

## Audit trail — what was corrected

1. **"100% (24/24) / 22 clusters / production-ready" was retracted.** The committed 22-cluster
   WolfSSL model live-validates at **14–16/24** (≈58–67%), and the number is not stable run-to-run.
   The full strict rebuild lands on **15** clusters at 24/24.
2. **Root cause of the phantom 7 clusters.** The 15→22 splits depended on two probes
   (`...074317586...`, `...074407644...`) that are **MitM/puppet traces**: replayed against a single
   live server they abort at term-evaluation (`Unable to find variable .../TranscriptServerFinished`)
   *before observing the server*, so the canon records `EMPTY`. The signatures that created those
   splits were partial-execution noise (0/60 reproduced on fresh measurement).
3. **Params now recorded.** The pipeline previously hardcoded N_POOL/DOM in `probe.py`; the docs
   claimed 30/21 + "100ms pacing" that the code could not actually set (pacing is still not
   implemented). Params are now configurable and stamped into every model/result/report.
4. **Internet-scan claim removed.** `scan_internet.py` runs but produced no captured, reproducible
   output; "matched lab signatures with high confidence" was unsubstantiated.

### Shared-code caveats — addressed
The recent infra work includes genuine fixes (TCP `bind` error handling; multi-agent "puppet"
routing via `--agent`/`is_server()`; real `shutdown()`/`version()` instead of `todo!()`). The
fingerprinting-specific changes that had been hardcoded into **shared** harness/PUT code have now
been gated or reverted so the fuzzer's default behavior is restored:
* `tlspuffin/src/put.rs`: hardcoded cipher suites **reverted** to the config-driven strings
  (removes the `into_raw()` leak and the dead-parameter warnings; rebuilt).
* `tlspuffin/harness/{openssl,wolfssl}/src/put.c`: the `if (false && …)` peer-verification disable
  is now **gated behind `FP_NO_PEER_VERIFY`** — unset (default) restores descriptor-driven
  verification for the fuzzer; fingerprinting can opt out. *Takes effect after re-vendoring the
  C-PUTs* (not done here — it does not affect live TCP probing, which never uses the C-PUT cert path).
* `puffin-build/cmake/harness/run.cmake`: `-Wl,--allow-multiple-definition` is **left in place**
  (removing it breaks the multi-PUT link) but now carries a prominent warning comment; the proper
  fix is to namespace the colliding symbols so the flag is unnecessary. Still open.

---

## Behavioral signature taxonomy — implemented, and what it showed

The terminal-TCP-behavior signal is now captured instead of being flattened to `EMPTY`:

* `tlspuffin/src/tcp/mod.rs`: the previously-discarded `read_to_end` result is classified into
  `TCP_CLOSE` (clean FIN) / `TCP_WAIT` (idle, connection still open) / `TCP_RST` / `TCP_ERR`, emitted
  on stderr **gated by `FP_EMIT_DISPOSITION`** (the fuzzer is unaffected). Alert level/description is
  already in the parsed flight, so the canon captures `ALERT(...)` when one is sent.
* `_canon.py`: folds the disposition into the signature (`disp=<token>`), so servers that all
  collapsed to EMPTY are now distinguished by *why* (close vs reset vs wait). Backward-compatible
  (absent → signature unchanged, old models still match).
* `probe.py`: enables the gate and injects the terminal disposition into the canon input.
  Verified working live (e.g. probe 803 → `TCP_CLOSE`, signature changes accordingly).

**Empirical result: on the current mined probe set, the taxonomy does not add granularity.** Strict
re-clustering with disposition still yields **15** (identical groups), and a single-shot screen of
**all 806 probes** finds **no** probe — even with `TCP_CLOSE/WAIT/RST` — that distinguishes any of
the 6 merged groups. The previously-"EMPTY" splitter probes (804/805) are MitM/puppet traces that
abort *before any read*, so no disposition is ever observed for them.

**Re-mine test (the unbiased check).** Screening the already-selected probes is biased — they were
chosen for signal under the *old* canon. So the raw objective traces were re-mined directly: for the
one merged pair with raw traces still in the repo (5.0.0/5.2.1, 430 objective traces; the other
pairs' `hunt-*` dirs are empty), all 430 were screened with disposition on. Result: **3 single-shot
candidates, 0 strict-confirmed** — the candidates were transient noise, no robust distinguisher.

**Conclusion: the bottleneck is the *fuzzing objective*, not the probe set or the observation layer.**
The differential fuzzer's objective is **internal in-process divergence** (that is what makes a
trace an "objective"), but the canon only sees **wire** behavior. 5.0.0/5.2.1 genuinely diverge
internally (hence the objectives exist) yet emit identical messages *and* identical TCP disposition
on the wire for every input we have. So the state-machine difference is real but not externally
observable over TCP for these inputs.

**Real next step:** drive the campaigns with a **wire-observable (disposition-aware) differential
objective** — reward inputs that make two versions differ in `MSG/ALERT/TCP_CLOSE/WAIT/RST`, not in
internal state — and re-run the dedicated `hunt-*` campaigns for the merged pairs (their raw traces
are not in this repo). The disposition machinery is now in place for that signal to count. A full
strict rebuild over the existing 806 probes with disposition would just reconfirm 15, so it was not
run.

## Root cause of probe non-reproducibility: attacker-side RNG (ring), not the PUT

Investigating why 5.0.0/5.2.1's objectives are nondeterministic produced the session's deepest
finding — and it is **not** PUT-side. Traced via `display-execute`:

* The input ClientHello term *should* be deterministic — every randomized DY function is pinned
  (`fn_new_random=[1;32]`, `fn_random_ec_key`=const, crypto uses `FixedByteRandom{42/43}`).
* Yet term evaluation fails ~50% of the time with
  `[Crypto] error in fn from rustls: Failed to shared secrets for TLS 1.2` → no ClientHello is sent
  → the canon records EMPTY. The failure rate is **PUT- and version-independent** (5.0.0: 9/20,
  5.2.1: 12/20), and it is **not ASLR** (`setarch -R` stays flaky) — but the binary draws from
  `/dev/urandom`.
* Mechanism: the trace's term reinterprets an ECDSA signature as an ECDH key share
  (`fn_decode_server_ecdh_pubkey(fn_ecdsa_sign_server(...))`). `ring 0.16.20` blinds its P-curve
  scalar ops with **system entropy regardless of the `FixedByteRandom` passed in**, so the signature
  bytes — and the key decoded from them — vary every run; the shared-secret computation then
  succeeds or fails ~50/50. The "no-rand" deterministic build neutralizes the **PUT's** RNG
  (wolfSSL/OpenSSL), but **not ring**, the fuzzer's own crypto for computing attacker terms.
* So this whole class of objectives is intrinsically a coin flip on the **attacker** side, identical
  for all versions — it can never fingerprint, and it injects EMPTY-vs-response noise into the
  matrix. (Stable decision probes like 803 carry no such construct: 0/10 term-eval failures.)

### Fix shipped: K-replay self-consistency screen (mining)
`probe.self_consistent(cfg, trace, port, k)` replays a probe K independent times against one server
and keeps it only if all K pooled measurements agree (incl. EMPTY); a flipper is rejected. Wired
into `mine_probes.py` stage A2 (`--consistency-k`, default 3) so non-reproducible probes never enter
the matrix, and exposed as a standalone auditor `check_consistency.py`.

**Quantified on the committed set:** **691 / 806 (86%) of the existing WolfSSL probes are
non-self-consistent** on a single reference server (5.4.0, K=3, 30/21) — i.e. attacker-side noise.
Calibration check: all **7** decision probes of the deployed 15-cluster model pass cleanly (3/3
identical), so the model already routes only on the reproducible ~14%; the screen would have pruned
the 86% up front, yielding a far cleaner matrix and removing the source of the earlier "mirage"
splits.

---

## Artifacts
* `evaluation-ddyf/fingerprinting/reference/wolfssl/` — **the canonical WolfSSL model, now the
  audited 15-cluster one** (promoted; params stamped). This is what `run_fingerprint.py` /
  `fingerprint_probe.py` use by default. (Prior 12-cluster version is in git history.)
* `evaluation-ddyf/fingerprinting/reference/openssl/` — OpenSSL 11-cluster, 60/61 (unchanged).
* `evaluation-ddyf/fingerprinting/reproduced_strict/wolfssl/` — the strict-rebuild source of the
  promoted model (kept for provenance).
* `evaluation-ddyf/fingerprinting/reproduced/wolfssl/` — the unreproducible 22-cluster model;
  retained only for the audit record. **Do not deploy.**
</content>
</invoke>
