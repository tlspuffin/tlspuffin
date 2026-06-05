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

**Result (2026-06-05):** 61 OpenSSL versions → **53 distinguishable clusters**
(50 singletons + 3 merged groups) over real TCP. Only **1.0 % EMPTY** cells (vs
22.9 % in the old, truncation-contaminated matrix). Discrimination is genuinely
wire-observable: treating EMPTY ("server stopped responding") as a wildcard still
gives **50** clusters, so 50 come from non-empty responses and 3 from real
stops-responding behaviour. Decision tree: **depth 8, 16 probes** (minimal
separating set 12). The 3 indistinguishable groups are
`{3.0.0,3.0.2,3.0.5,3.0.9,3.1.1,3.1.4,3.1.7}`, `{3.2.3,3.3.2}`, `{3.3.4,3.4.3}`.

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

Result directories: `candidates_ossl_live/` + `model_ossl_live/` (OpenSSL),
`candidates_wolfssl_live/` + `model_wolfssl_live/` (WolfSSL). Earlier
`model_*`/`candidates_*` directories are superseded and not part of the artifact.
