# Explore: can we make OpenSSL fingerprintable over TCP by selecting deterministic traces?

## Start here
Read `evaluation-ddyf/fingerprinting/FINDINGS_2026-06-05.md` in full first. It has the
verified state, the methodology, and the audit trail. Don't re-derive what's there.

## Verified facts (do NOT re-litigate)
- **WolfSSL is robustly fingerprintable over real TCP: 24/24 (100%), every re-probe at
  Hamming dist=0.** It responds deterministically.
- **OpenSSL is NOT, at every setting tried (≤2/12).** Cause is verified-intrinsic: a
  stock, out-of-the-box `openssl s_server` (non-sancov) answers a *given* malformed probe
  only ~45% of the time (e.g. trace `…211608806…` vs openssl362: ServerHello 9/12, silence
  3/12). It is NOT a sancov / vendored-build / repeat-count / harness artifact. The
  500 ms→200 ms tcp read race exists but is handled by most-complete+majority capture.
- Per-cell re-probe noise for OpenSSL is ~5% (≈20/442 cells) and ≈ the inter-cluster
  separation, so identification collapses.

## The hypothesis to test (the likely real lever)
**We may be selecting the wrong trace candidates.** Triage ran `REPEATS=1` — no
determinism filter — so the matrix/tree mix *deterministic* traces with *marginal-response*
(flaky ~50/50) traces. But not all traces flake: some are 12/12 stable
(`…231528150…`, `…005427368…`, `…185049664…`) while others are ~50/50. If we keep **only
the traces whose live-TCP response is deterministic across all 61 versions** and cluster on
those, OpenSSL might become robustly fingerprintable like WolfSSL — *if* enough stable
traces still separate the versions.

## Concrete, LLM-free plan
The trace selection MUST be a deterministic script (no LLM hand-picking) — see the
constraint in FINDINGS and `mine_traces.py` for the existing style.
1. **Determinism filter (new script).** For each candidate (start from the 55,718-trace
   pool via `mine_traces.py`, or the 442 in `candidates_ossl_mined*/manifest.csv`), probe
   every version K≥15 times with `/tmp/tlspuffin_fast200 tcp`, pinned (`taskset`, cores
   0-25 are free, 30+ loaded). Classify each (trace,version) cell as **stable** (the
   max-`executed_until` capture's signature dominates, e.g. ≥0.8 of captures agree at the
   modal depth) or **flaky** (response/no-response or sig flips). Keep traces that are
   stable for (almost) all versions. This is a deterministic, reproducible algorithm.
2. **Rebuild + validate.** Feed the kept traces to `build_live_matrix.py`
   (`--server-cmd openssl`, `--repeat 11`), then `build_tree.py`, then
   `robust_validate.py --candidates <dir> --server-cmd openssl --repeat 11`. Success =
   the deterministic-trace matrix has cluster separation >> per-cell noise and
   `robust_validate` gives a high X/61.
3. **Measure the trade-off.** Key question: after dropping flaky traces, do enough
   *stable* traces remain to separate the versions? Report (a) #stable traces, (b) cluster
   count, (c) min inter-cluster separation, (d) end-to-end accuracy. The version signal may
   partly LIVE in the flaky cells — if so, the stable subset under-separates and the answer
   is "OpenSSL is genuinely wire-noisy." Either outcome is a clean result.

## Other things worth exploring
- **Tree/probe selection criterion**: `build_tree.py` picks probes by info-gain only.
  Add a *determinism weight* so the tree/min-separating-set prefer stable, high-separation
  probes (a robust min-cover, like the WolfSSL K-redundant cover in `mine_traces.py`).
- **Is some flakiness still truncation?** Rebuild `/tmp/tlspuffin_fast200` from
  `tlspuffin/src/tcp/mod.rs` with a longer read timeout (e.g. 1-2 s) and re-check whether
  the ~50/50 traces become stable (genuine server non-determinism) or stabilise (we were
  truncating). The stock-openssl control suggests genuine, but confirm.
- **Add the determinism filter to `triage.py`** (`REPEATS>1` + stability) so the pipeline
  produces stable candidates by construction, for both vendors.

## Tools / environment
- Prober: `/tmp/tlspuffin_fast200` (ASAN-free, 200 ms read, identical sigs, ~1000× faster).
- Servers: `vendor/openssl3XX/bin/openssl s_server -accept P -cert lab_validation/server.crt
  -key lab_validation/server.key -quiet` with `OPENSSL_CONF=/dev/null`. (Stock
  `/usr/bin/openssl` for control.) 61 versions vendored.
- Scripts: `mine_traces.py`, `build_live_matrix.py`, `build_tree.py`, `robust_validate.py`,
  `_canon.py`, `diag_node.py`. Bash gotcha: shell has `set -e`; guard `pkill` with
  `|| true`/`set +e`; killing a matrix run orphans its `s_server`s (kill them by PID).
- Keep the runtime pipeline **LLM-free**: selection is a script, never the LLM choosing traces.
