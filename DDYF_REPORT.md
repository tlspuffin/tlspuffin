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

### Open shared-code caveats (flagged, not yet resolved)
The recent infra work includes genuine fixes (TCP `bind` error handling; multi-agent "puppet"
routing via `--agent`/`is_server()`; real `shutdown()`/`version()` instead of `todo!()`). It also
contains fingerprinting-specific changes hardcoded into **shared** harness/PUT code that affect all
users of the fuzzer and should be gated (behind an env var, like `FP_V13_ONLY`) or reverted:
* `tlspuffin/harness/{openssl,wolfssl}/src/put.c`: certificate/peer verification disabled via
  `if (false && ...)`.
* `tlspuffin/src/put.rs`: cipher suites hardcoded (configured cipher strings ignored; `into_raw()`
  leak).
* `puffin-build/cmake/harness/run.cmake`: `-Wl,--allow-multiple-definition` silently resolves symbol
  clashes — risky for a tool whose correctness depends on running the right version's code.

---

## Next step — behavioral signature taxonomy (the route past 15)

The remaining merged WolfSSL versions *do* differ (confirmed by dedicated campaigns that found
distinguishing objectives). The signal is lost because the current canon flattens the **terminal TCP
behavior** into a single `EMPTY` token. The fix is to capture and encode that behavior as distinct
signature tokens, with a **long timeout** so "waits for more" is separable from "closed":

Target token set (per connection, possibly combined with parsed messages):
`MSG(<which>)` · `ALERT(<level,description>)` · `TCP_CLOSE` (clean FIN) · `TCP_RST` ·
`WAIT` (peer holds the connection open past a grace period) · `EMPTY` (truly nothing).

Where the signal is dropped today, and the scoped change:

1. **Prober — `tlspuffin/src/tcp/mod.rs` + the `tcp` PUT's `--json` execution record.**
   The read loop uses a fixed idle timeout and does not surface TCP disposition. Add to the JSON
   output: bytes-received count, whether a TLS Alert was received (level + description), and how the
   connection ended — clean EOF (FIN), `ECONNRESET` (RST), or idle-timeout-with-connection-open
   (WAIT). This is the core change (Rust, moderate).
2. **Canon — `evaluation-ddyf/fingerprinting/_canon.py`.**
   When no full message is parsed, stop collapsing to `EMPTY(sha256(""))`. Instead emit the
   structured terminal token from the disposition above (and append it to any partial messages, e.g.
   `ServerHello → TCP_RST`). Low effort once the prober exposes the fields.
3. **Pooling already supports it.** `probe.py` already maps a hard timeout to a `TIMEOUT` token; the
   above generalises that to the full taxonomy. Keep the long timeout (≥ a few seconds) so `WAIT`
   vs `TCP_CLOSE` is reliably separable; then re-mine / `build_matrix → build_tree → validate`.

This is the principled way to recover the granularity that the puppet-trace shortcut only faked, and
it is exactly the "Signature Adapters (`ALERT / TIMEOUT / TCP_RST`)" idea sketched as future work.

---

## Artifacts
* `evaluation-ddyf/fingerprinting/reproduced_strict/wolfssl/` — the audited 15-cluster model
  (tree/meta/validation/report, params stamped). **Recommended WolfSSL model.**
* `evaluation-ddyf/fingerprinting/reference/{wolfssl,openssl}/` — prior validated models
  (WolfSSL 12-cluster; OpenSSL 11-cluster, still current).
* `evaluation-ddyf/fingerprinting/reproduced/wolfssl/` — the unreproducible 22-cluster model;
  retained only for the audit record. **Do not deploy.**
</content>
</invoke>
