# Auditor Q&A — OpenSSL 61-cluster Fingerprinting

_Answers based on hands-on session data, June 2026._

---

## A. Trace Pool

### A1. Pool size and untapped potential

The **129 traces in the matrix are not the full triaged set** — they are a small sample.

- OpenSSL adjacent-version campaigns produced **111,436 objective traces** in `experiments/` (pre-triage).
- The AGY triage script sampled up to 100 traces per experiment with diversity-based selection (1 per diff-kind, then fill to 100).
- Pool evolution: original triage → 87 traces; AGY triage → 129 traces.
- Untapped: ~111,000 traces not yet in any matrix.

**This is the single biggest lever.** Selecting from the full pool by maximising non-EMPTY pair separation (≥2 distinct real-TLS signatures across as many version pairs as possible) would likely find more robust discriminating traces.

### A2. REPEATS and the determinism filter

Both our triage and AGY's triage use `REPEATS = 1` — the determinism filter was effectively **off**. No traces were dropped for non-determinism. The 3-run majority vote at matrix build time was the only protection against per-cell noise. We have no count of how many raw traces are non-deterministic.

---

## B. How "61" Was Built and Validated

### B3. Matrix provenance: `signatures_tcp.csv`

`candidates_openssl3x_live/signatures_tcp.csv` was built by **live TCP**:
- Client: `tlspuffin tcp` (ASAN binary `/tmp/tlspuffin_o3x`)
- Server: local `vendor/<version>/bin/openssl s_server`
- **3-run majority vote** per (trace, version) cell
- Not display-execute

Statistics: 129 traces × 61 versions = 7,869 cells; **22% EMPTY** (1,803 cells — truncation/non-response from the 500ms read timeout); **0 ERROR** (majority always resolvable).

`signatures_live.csv` (same directory, older) is the first-pass matrix from a single run per cell, before the majority-vote rebuild.

### B4. End-to-end validation: NOT performed

The 61-cluster model was **never validated end-to-end.** Specifically:
- `lab_validate.py` exists at `evaluation-ddyf/fingerprinting/lab_validate.py` for exactly this purpose (start `openssl s_server` per version, run `fingerprint_probe.py` over a real socket, check the cluster). **It was never executed.**
- The only validation performed was matrix-level self-consistency: `build_tree.py` checks that every version's signature vector is unique and walks to the correct leaf using stored matrix signatures.
- Three-version spot checks (`openssl302`, `openssl330`, `openssl362`) against live `openssl s_server` all **failed** (0/3 correct) due to non-determinism in the server's TLS responses to aggressive probes.

### B5. Inter-cluster separation: thin for most pairs

Measured on `signatures_tcp.csv` (non-EMPTY traces distinguishing each pair):

| Separation | Pairs |
|-----------|-------|
| 0 non-EMPTY traces (EMPTY-pattern only) | **3 pairs** |
| Exactly 1 non-EMPTY trace | 13 pairs |
| ≤2 non-EMPTY traces | 56 pairs |
| ≤5 non-EMPTY traces | 617 pairs |
| Maximum separation | 33 traces |
| Total pairs | 1,830 |

**3 pairs with zero real-TLS separation** (only EMPTY vs non-EMPTY):
- `openssl300` ↔ `openssl3015` (27 EMPTY-pattern traces)
- `openssl301` ↔ `openssl315` (31 EMPTY-pattern traces)
- `openssl331` ↔ `openssl340` (29 EMPTY-pattern traces)

These are entirely invisible to a robust live prober. The 13 single-trace pairs are fragile under any non-determinism.

This was **not measured or discussed** until the auditor raised it. No step in the pipeline measured inter-cluster separation/robustness — only distinctness (is each cluster unique?).

---

## C. Display-Execute and the 40% ERROR

### C6. ERROR rate and treatment

- AGY offline matrix (display-execute): **40% ERROR rate** (3,188 / 7,869 cells).
- This improved from ~50% after AGY's `cli.rs` fix (print JSON before `exit(1)`).
- Errors are from the tlspuffin PUT state machine aborting cleanly — **not ASAN memory bugs**. Verified: zero non-leak ASAN errors (`ERROR: AddressSanitizer`) across all 23 AGY model probes × 12 recent versions (3.2.0–3.6.2).
- ERROR was treated as a valid discriminating signal in the AGY model (a version that crashes on a probe is distinct from one that doesn't).
- **The ERROR pattern was NOT verified to reproduce across independent matrix builds.** The matrix was built once.
- Older versions (3.0.x) were not tested for ASAN behaviour; only recent versions (3.2.x–3.6.x) were checked.

### C7. AGY's extra ~42 traces: mostly fragile

The `execution.rs` StatusDiff expansion (same-step, different-error-string) grew the corpus 87→129. These extra traces tend to have high EMPTY rates (some versions crash/close, others respond). They contribute primarily to thin 1–2-trace separations rather than robust multi-trace discriminations. The top-10 most discriminating probes (by non-EMPTY pair separation) include late June-2nd traces from the expanded campaigns, but most provide thin coverage.

---

## D. The Core Question

### D8. Probe characterisation

OpenSSL 3.x versions respond **nearly identically** to most probes over the wire. The main variation axes:

**Strongest discriminators** (top probes by non-EMPTY pair separation from `signatures_tcp.csv`):

| Probe | Pairs separated | Type |
|-------|----------------|------|
| `20260602-145038121-7d08309aeee1b774` | 1,017 | ServerHello content (3.0.x gets EMPTY, newer get ServerHello) |
| `20260602-180300980-1fa6dbade9bc18b2` | 992 | ServerHello content |
| `20260601-231528150-913d8eebff5c4bb6` | 930 | Alert type |
| `20260601-234117494-13a061bfd277e363` | 930 | Alert type |
| `20260602-034522560-469cadc87ce9f005` | 928 | Alert type |

The ServerHello-content probes are the most powerful but depend on whether a handshake completes at all. Alert-based probes trigger `HandshakeFailure`, `IllegalParameter`, `DecodeError` — these are version-specific TLS state-machine behaviours.

**One confirmed robust signal**: probe `20260530-200327676` (HelloRetryRequest probe) splits 3.1.x from 3.3.x:
- 3.1.x: sends HelloRetryRequest only
- 3.3.x: sends HelloRetryRequest + `Alert(IllegalParameter)`

This is a real OpenSSL library-level change between 3.1 and 3.3, confirmed against live production servers (`vote.belenios.org` correctly identified as having two backends running different version families).

### D9. Binary and ASAN status

- Matrix build binary: `/tmp/tlspuffin_o3x` — **ASAN-linked** (`libclang_rt.asan-x86_64.so` confirmed).
- `openssl s_server` binaries at `vendor/<version>/bin/openssl` — ASAN status **unknown** (not checked).
- The 500ms read timeout in `tlspuffin/src/tcp/mod.rs:151` causes truncation on loaded machines; combined with ASAN overhead (~3.5s per probe), this is the primary performance and reliability bottleneck.
- `ASAN_OPTIONS=detect_leaks=0` was used as a workaround for display-execute; leak reports were suppressing JSON output. No non-leak ASAN errors were found on modern versions.

---

## E. Summary of What Was NOT Done (Critical Gaps)

1. **No end-to-end TCP accuracy measurement**: `lab_validate.py` was written but never run.
2. **Inter-cluster separation was never measured** during model building — only distinctness.
3. **REPEATS=1 in triage**: non-deterministic traces were not filtered.
4. **The full 111,436-trace pool** was never systematically mined for high-separation probes.
5. **Vendor binary ASAN status** unknown — may affect whether ERROR signals reproduce with a non-ASAN prober.
6. **No non-ASAN tlspuffin binary** was built or tested; the 500ms timeout and ASAN overhead were never addressed.

