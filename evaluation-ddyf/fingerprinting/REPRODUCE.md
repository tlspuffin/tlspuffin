# Reproducing the DDYF TLS-version fingerprinting results

This document reproduces, end to end, the RQ5 fingerprinting results: given the
objective traces of DDYF differential-fuzzing campaigns, build a
configuration-agnostic decision tree of probe traces that identifies which
version of a TLS stack a server runs, and validate it against real servers over
TCP in a controlled lab.

Everything lives in `evaluation-ddyf/fingerprinting/`. Two stacks are covered:
**OpenSSL 3.x** (3.0.0–3.6.2, 61 versions) and **WolfSSL 5.x** (5.0.0–5.9.1, 26
versions).

> TL;DR of the method choice (see "Why live-TCP" below): signatures are taken
> from **real servers over a TCP socket**, not from in-process `display-execute`.
> For OpenSSL the in-process PUTs are ASAN-instrumented and abort
> non-deterministically on the malformed probes, so display-execute is unusable
> (~93 % of its discrimination is crash-noise). The vendored `bin/openssl`
> servers are normal non-ASAN builds, so probing them over TCP yields the real,
> wire-observable behaviour.

---

## 0. Prerequisites

* The repo built once so that `vendor/<version>/` exists for every version
  (each contains a normal, non-ASAN `bin/openssl` for OpenSSL; for WolfSSL the
  example server is built by `build_wolfssl_servers.sh`, see §4).
* A **fast prober binary** — an ASAN-free, `tcp`-only `tlspuffin`. The default
  1.8 GB ASAN binary loads in ~3.5 s per probe (≈19 h for a full matrix); the
  fast one loads in ~0.003 s and produces **byte-identical signatures**. Build it:

  ```bash
  cd <repo root>
  nix-shell shell.nix --run \
    "LIBAFL_EDGES_MAP_DEFAULT_SIZE=65536 cargo build --release --bin tlspuffin"
  cp target/release/tlspuffin /tmp/tlspuffin_fast
  ```

  It is ASAN-free because no openssl/wolfssl PUT feature is enabled (the `tcp`
  PUT is core puffin); ASAN only comes from the vendored TLS libs.

* A throw-away server cert/key (the signature ignores cert bytes):

  ```bash
  cd evaluation-ddyf/fingerprinting/lab_validation
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=lab.local \
    -keyout server.key -out server.crt
  ```

---

## 1. Pipeline overview

```
 fuzzer objective traces
        │
        ▼
   triage.py            keep benign, TCP-observable, deterministic diffs → manifest.csv
        │
        ▼
   build_live_matrix.py  for every (trace, version): start the real server,
        │                replay the trace over TCP, capture the wire response
        │                (most-complete + majority over N repeats) → signatures_tcp.csv
        ▼
   build_tree.py         greedy info-gain decision tree + min separating set
        │
        ▼
   fingerprint_probe.py  live prober: walk the tree against a host:port
   lab_validate.py       end-to-end check: probe each version's own server,
                         confirm it routes to the cluster containing that version
```

Shared canonicalisation lives in `_canon.py`. The same scripts and the same
capture rule are used for both OpenSSL and WolfSSL (the only per-stack
difference is the server command, passed via `--server-cmd`).

### The capture rule (the crux)

`tlspuffin tcp` reads the server's response under a fixed 500 ms idle timeout
(`tcp/mod.rs`), so a slow/bursty flight is sometimes **truncated** — the engine
records fewer steps (`executed_until`) than the server actually sent; the extreme
case is an empty capture. Truncation only ever *drops* trailing flights, never
invents them. So across `--repeat` probes we keep the capture with the **largest
`executed_until`** and, among those, the **modal** signature. This cancels both
the truncation race and genuine same-depth response jitter, and reproduces the
matrix value the prober will see. Probes are pinned to dedicated cores
(`taskset`) so a busy host cannot starve the read window. A genuine "server
stopped responding" (a real, wire-observable behaviour) survives as a stable
empty signature; only truncation artifacts are filtered.

---

## 2. Reproduce OpenSSL (live-TCP)

```bash
cd evaluation-ddyf/fingerprinting

# (a) triage the campaign objective traces → candidates_ossl_live/manifest.csv
#     (already produced; see candidates_ossl_disp/manifest.csv for the 129-trace set)

# (b) build the live-TCP signature matrix against the real vendored servers
PUFFIN_BIN=/tmp/tlspuffin_fast200 python3 build_live_matrix.py \
    --manifest candidates_ossl_disp/manifest.csv \
    --out      candidates_ossl_live \
    --binary   /tmp/tlspuffin_fast200 \
    --repeat 11 --jobs 12 --first-core 0 --cpus-per-job 2 --base-port 20100

# (c) synthesise the decision tree
python3 build_tree.py --in-dir candidates_ossl_live --out-dir model_ossl_live --tcp-mode

# (d) end-to-end validation. Two flavours:
#   - lab_validate.py walks the decision tree (few probes). Its decision probes
#     are the most-discriminating ones, which jitter most over the wire, so a
#     single ~3% per-connection cell flip on a decision node cascades to a wrong
#     leaf. Demonstrates the tree, but is noise-sensitive.
#   - robust_validate.py re-probes ALL traces and assigns each version to the
#     nearest matrix cluster (Hamming). Tolerates a few flips; measures whether
#     the *clustering* reproduces live -- the defensible end-to-end test.
PUFFIN_BIN=/tmp/tlspuffin_fast200 python3 robust_validate.py \
    --candidates candidates_ossl_live --server-cmd openssl \
    --repeat 5 --jobs 12 --first-core 0 --cpus-per-job 2
```

> **Reproducibility note.** The clustering reproduces at the cell level:
> re-probing a version's full column matches the matrix to within ~1/30 cells
> (verified on several versions, both 200 ms and 500 ms read timeouts, two
> independent runs). The 53-cluster result is stable; only the few-probe
> decision-tree *walk* is fragile, hence nearest-cluster matching for robust ID.

**Result (2026-06-05) — ⚠️ SUPERSEDED, see §2b.** The first live matrix gave 61
OpenSSL versions → **53 distinguishable clusters**. We later showed this number is
**not robust**: 45/53 of those clusters are separated by only 1–2 traces, which is
*at the per-connection live-jitter floor*, so the separations do not reproduce
across independent connection batches. The honest, deployment-validated OpenSSL
result is in **§2b** (10 clusters, depth-3 tree, 61/61 servers recognised). Keep
this number only as the raw, unverified matrix distinctness.

## 2b. OpenSSL — corrected oracle + strict live verification (the honest result)

The §2 matrix has two problems that §2b fixes, giving the result reported in the
paper (`appendix_fingerprinting.tex`, `\subsection{OpenSSL 3.x ...}`).

### Problem 1 — the differential objective oracle was not wire-observable

On this branch, `DifferentialRunner::execute_config` (`puffin/src/execution.rs`)
had been broadened to flag *any* divergence between the two PUTs, including
tlspuffin-internal `Fn`/`Crypto` errors. A fuzzer-mutated `fn_decode_*` parses the
server's fresh per-connection random bytes as a length-prefixed field and fails
~50 % of the time → `FnError::Codec` → a *non-deterministic* "objective". With this
oracle an adjacent OpenSSL pair produces **~hundreds of thousands** of objectives
per campaign, almost all client-side artifacts.

**Fix (committed `6351b46b6`, refined to the `(Put,Ok)` form):** a status objective
is recorded **only** for wire-observable outcomes — both sides a PUT error at a
*different* step, or exactly one side a clean PUT error while the other cleanly
succeeds. Internal `Fn`/`Crypto`/`Term`/`IO`/… errors never create an objective
(their error *string* is internal state a remote client never sees). Security-claim
and content/flight diffs are unchanged. After the fix, adjacent pairs yield **0–3**
objectives and a far-apart pair (3.2.6↔3.6.2) yields thousands — signal preserved,
noise gone.

To regenerate the corrected campaigns (one differential campaign per adjacent
pair, with the fixed-oracle binary):

```bash
# build a fixed-oracle binary (must contain 6351b46b6) WITHOUT clobbering a binary
# that another run is using; one per-pair binary keeps each campaign small:
cargo build --release -p tlspuffin --features "<the openssl-3x PUT features>"
cp target/release/tlspuffin /tmp/bin_openssl300_openssl301   # etc., one per pair
# launch (one core per pair):
timeout 12h /tmp/bin_openssl300_openssl301 -p 3000 --cores 0 \
    differential-experiment openssl300 openssl301 -t fpp-3.0.0-3.0.1
# objectives land in experiments/<date>--openssl-*fpp-<a>-<b>--*/objective/
```

### Problem 2 — an in-process objective is NOT a wire difference

A campaign's objectives come from the *in-process* PUT. Most do **not** reproduce
against a real `s_server` over TCP: replayed live, the two versions return the
*same* canonical signature (or no parseable response), because OpenSSL's example
server answers a given fuzzer probe only *intermittently*. A single replay can thus
spuriously "distinguish" two wire-identical versions, and single-shot verdicts flip
run to run. The verification scripts make this rigorous; run them in order:

```bash
cd evaluation-ddyf/fingerprinting          # all use /tmp/tlspuffin_fast200 + vendored s_servers

# (1) per-pair, single batch: for every pair with objectives, replay each objective
#     live against BOTH versions (K=7) and report which pairs LOOK distinguishable.
python3 repro_fullcheck.py                 # NOTE: its verdicts FLIP run-to-run (jitter floor)

# (2) strict filter: a trace counts only if, in ALL 3 independent K=11 batches, BOTH
#     servers respond >=9/11 AND give distinct canonical sigs. Kills the jitter flips.
python3 confirm_final.py                   # over the union of all pairs ever flagged
#     -> DEFINITIVE: robustly-distinguishable ADJACENT pairs (by own objectives) = 0;
#        far-apart control 3.2.6-3.6.2 passes decisively (method works).

# (3) mine + confirm + cross-apply, then build a CLEAN matrix and DEPLOYMENT-VALIDATE.
#     mine_exhaustive.py screens every fixed-oracle objective on its OWN pair, confirms
#     survivors with the strict 10x / >=7-of-10 filter, and cross-applies the confirmed
#     probes to all 61 versions (writes /tmp/ossl_confirmed_reps.txt).
python3 mine_exhaustive.py
#     rebuild the cross-apply matrix under CONTROLLED load: each server probed
#     SEQUENTIALLY (one connection at a time) so it answers within the socket-read
#     window. Heavy parallel load truncates captures and corrupts cells (~6% reproduce);
#     sequential probing gives 0 unstable cells. Writes candidates_clean/.
CORES="0,2,4,6,8,10,12,14,16,18,20,22,24,26,28" JOBS_VERS=15 python3 rebuild_matrix.py
#     induce the wildcard-aware decision tree from the clean matrix:
python3 build_tree_wildcard.py candidates_clean   # -> 10 leaves, depth 3, 3 probes

# (4) DEPLOYMENT VALIDATION (train/test split): walk the tree against each of the 61
#     live servers, 5x, replaying only each node's probe (<= depth traces). Recognises a
#     server iff it lands in a leaf containing its true version.
CAND=candidates_clean python3 validate_tree_walk.py
#     -> 61/61 recognised, 61/61 CONSISTENTLY over 5 walks, <=3 traces each.
#     run_clean_rebuild.sh chains (3)+(4) and regenerates FINAL_REPORT.md.
```

### Result (2026-06-08): 10 deployment-validated clusters, 61/61 recognised

From 24,235 fixed-oracle objectives → 2,110 live-screen survivors → **275 confirmed
probes** (strict 10×/≥7) cross-applied to all 61 versions. The clean matrix induces a
wildcard decision tree of **depth 3** using **3 probes**, partitioning the 61 releases
into **10 distinguishable clusters**. Walking that tree against the live servers
(train/test split, 5 walks each) recognises **61/61** servers — consistently, in ≤3
traces. This is the honest, deployment-validated number (not the construction count).

| cluster | OpenSSL 3.x releases |
| --- | --- |
| `C0` (24) | 3.0.0–3.0.15, 3.1.0–3.1.7 |
| `C1` (6)  | 3.0.16–3.0.20, 3.1.8 |
| `C2` (8)  | 3.2.0–3.2.3, 3.3.0–3.3.2, 3.4.0 |
| `C3` (3)  | 3.2.4, 3.3.3, 3.4.1 |
| `C4` (8)  | 3.2.5, 3.2.6, 3.3.4, 3.4.2–3.4.4 |
| `C5` (2)  | 3.3.7, 3.4.5 |
| `C6` (6)  | 3.5.0–3.5.5 |
| `C7` (1)  | 3.5.6 |
| `C8` (2)  | 3.6.0, 3.6.1 |
| `C9` (1)  | 3.6.2 |

The cluster boundaries are dominated by OpenSSL's coordinated upstream releases:
**`C3` = {3.2.4, 3.3.3, 3.4.1}** is *exactly* the 3.2/3.3/3.4 members of the
February-2025 backport wave (its 3.0/3.1 members {3.0.16–3.0.20, 3.1.8} form `C1`,
split from the large pre-wave block `C0`); the pre-wave 3.2/3.3/3.4 releases form `C2`
and the post-wave ones `C4`/`C5`. So the wire-visible signal of a coordinated release
is still the strongest separator, but controlled-load probing additionally resolves
finer within-branch structure (the 3.5.x and 3.6.x lines). 10 is a lower bound; deeper
fuzzing could only refine it. Full funnel/heatmap in `FINAL_REPORT.md`.

> **Methodological note (why §2's 53 and the earlier 3-group numbers were wrong).**
> §2's 53-cluster matrix was built under heavy parallel load → socket-read truncation
> corrupted the cells, so a tree induced from it mis-routed 42/61 live servers — which
> *looks* like cross-session version drift but is a load artifact (only ~6% of cells
> reproduced clean). The strict-confirm cross-apply (`robust_partition*.py`,
> `confirm_*.py`) gave a defensible but coarse lower bound of 3 groups. Rebuilding the
> matrix under controlled load (`rebuild_matrix.py`, per-server sequential) removes the
> corruption (0 unstable cells) and lifts the result to the validated 10 clusters above.
> Lesson: a fingerprinting classifier must be deployment-validated against freshly-probed
> servers, and the construction matrix must be built under controlled load.

**Why this differs from WolfSSL:** OpenSSL's finer changes are mostly internal
(crypto payloads, memory-safety fixes, refactors) or masked by the server's
intermittent response; WolfSSL's example server responds deterministically, so its
partition is finer (21 clusters / near-per-version). DDYF reports each faithfully,
always validated against live servers, never the in-process harness.

## 3. (reference only) OpenSSL in-process display-execute — NOT used

`signatures.py --tcp-mode --vendor openssl` builds the deterministic in-process
matrix. It yields 61 singleton clusters but **only 4 survive once the `ERROR`
(ASAN crash non-determinism) cells are treated as a wildcard** — i.e. its
discrimination is almost entirely an instrumentation artifact, not
wire-observable. Kept only to document why live-TCP is required for OpenSSL.

## 4. Reproduce WolfSSL (same pipeline, new folders)

```bash
# (a) build the wolfssl example server for each vendored version
./build_wolfssl_servers.sh           # writes vendor/wolfssl<ver>/bin/server

# (b)-(d) identical to OpenSSL but with the wolfssl server command and new dirs
PUFFIN_BIN=/tmp/tlspuffin_fast python3 build_live_matrix.py \
    --manifest <wolfssl manifest> --out candidates_wolfssl_live \
    --binary /tmp/tlspuffin_fast --server-cmd wolfssl \
    --repeat 11 --jobs 12 --first-core 0 --cpus-per-job 2 --base-port 21000
python3 build_tree.py --in-dir candidates_wolfssl_live --out-dir model_wolfssl_live --tcp-mode
PUFFIN_BIN=/tmp/tlspuffin_fast python3 lab_validate.py --model model_wolfssl_live ...
```

**Result:** _TBD — WolfSSL: N clusters from 26 versions; tree depth D, P probes;
lab-TCP end-to-end accuracy X/26._

---

## 5. Files in the final artifact

| file | role |
| --- | --- |
| `_canon.py` | shared signature canonicalisation (volatile-field stripping, hashing) |
| `triage.py` | filter fuzzer traces → manifest of benign/TCP-observable/deterministic diffs |
| `build_live_matrix.py` | **live-TCP** signature matrix vs real servers (most-complete+majority capture) |
| `build_tree.py` | greedy info-gain decision tree + greedy min separating set |
| `fingerprint_probe.py` | deterministic live prober (walk the tree against host:port) |
| `lab_validate.py` | end-to-end ground-truth validation against controlled servers |
| `build_wolfssl_servers.sh` | compile the wolfssl example server per vendored version |
| `signatures.py` | (reference) in-process display-execute matrix; not used for OpenSSL |
| `diag_node.py` | debugging aid: per-node capture distribution for one version |
| `robust_validate.py` | end-to-end nearest-cluster ID: re-probe all versions live, assign to closest matrix cluster (Hamming) |
| `repro_fullcheck.py` | OpenSSL live reproducibility, per pair, single K=7 batch (verdicts flip — shows the jitter) |
| `confirm_final.py` | **strict** filter: a trace counts only if distinct + both respond ≥9/11 in **all 3** independent K=11 batches |
| `confirm_boundaries.py` | strict 3-batch confirmation of specific release-wave boundary pairs + a same-wave negative control |
| `robust_partition.py` | replay verified-robust probes vs all 61 versions → reliable group partition (lower bound, 6 probes) |
| `robust_partition_full.py` | richer mined probe set → refined reliable cluster count; writes `/tmp/ossl_reliable_partition.json` |

Result directories: `candidates_ossl_live/` + `model_ossl_live/` (OpenSSL),
`candidates_wolfssl_live/` + `model_wolfssl_live/` (WolfSSL). Earlier
`model_*`/`candidates_*` directories are superseded and not part of the artifact.
