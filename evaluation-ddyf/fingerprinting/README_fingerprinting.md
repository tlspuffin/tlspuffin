# DDYF version fingerprinting of TLS libraries

Automatically learn, from differential fuzzing, a deterministic decision tree that tells **which
version (cluster) of a TLS library** a remote server runs — by replaying a handful of short,
fuzzer-discovered probe traces over a plain TCP socket and reading only the **wire-observable**
response. No machine learning, no fuzzing at deployment time, no decryption: the prober is a fixed
tree of fixed traces.

The same pipeline runs on any supported PUT (Program-Under-Test). Today: **OpenSSL 3.x** and
**WolfSSL 5.x**.

## Result (live-TCP, this artifact)

| PUT | versions | clusters | tree depth | probes used | live deployment validation |
|---|---:|---:|---:|---:|---|
| OpenSSL 3.x (3.0.0–3.6.2) | 61 | **10** | 3 | 3 | **61/61** recognised, consistently, ≤3 traces |
| WolfSSL 5.x (5.0.0–5.9.1) | 24 | **14** | 4 | 8 | **23/24** recognised (5.3.0 misroutes), ≤4 traces |

“Cluster” = a group of versions no probe can tell apart over the wire. The OpenSSL boundaries are
dominated by upstream’s coordinated release waves (e.g. cluster {3.2.4, 3.3.3, 3.4.1} is exactly the
Feb-2025 backport set); see `reference/openssl/report.md`.

> **Scope note.** These are the **live-TCP** numbers (a remote observer who never decrypts). An
> offline regime that *does* decrypt (display-execute / FFI signatures) resolves WolfSSL more
> finely (26 versions → 21 clusters), because some WolfSSL changes are only visible in decrypted
> content; live-TCP cannot see those and merges them. The artifact ships the honest live-TCP models.

## Layout

```
puts.py              PUT registry + path/runtime resolver (one place for all config)
probe.py             shared live-probing primitives (the 10×/≥7 reproducibility filter)
_canon.py            wire-response canonicalisation (volatile fields stripped)
build_live_matrix.py server_argv(): how to launch each stack's stock server

run_fingerprint.py   the driver (construction + identification)
  mine_probes.py     stage 1  objectives -> confirmed probes
  build_matrix.py    stage 2  cross-apply matrix (controlled load)
  build_tree.py      stage 3  wildcard decision tree (the model)
  validate.py        stage 4  deployment validation (walk fresh live servers)
  report.py          stage 5  report.md + heatmap.csv
fingerprint_probe.py identify a live host:port across one or more PUT models

reference/<put>/     committed canonical model + results (see "What is committed")
build_openssl3x.sh   vendor the OpenSSL servers
build_wolfssl_servers.sh  vendor the WolfSSL example servers
```

## Prerequisites

1. **Enter the dev shell** (from the repo root) so `cargo`, `taskset`, OpenSSL headers etc. are on
   PATH:
   ```
   nix-shell ./shell.nix
   ```
2. **Build the prober binary** — a release `tlspuffin` with the PUTs compiled in. Its `tcp`
   subcommand replays a trace against any host:port and prints the canonical capture as JSON:
   ```
   cargo build --release -p tlspuffin --features cputs
   # -> target/release/tlspuffin   (the default prober path)
   ```
   Point the pipeline at any binary with `--prober PATH` or `PUFFIN_BIN=PATH`.
3. **Vendor the per-version servers** (only needed to *re-probe*; not needed to inspect the
   committed models):
   ```
   ./build_openssl3x.sh         # -> vendor/openssl3XX/bin/openssl
   ./build_wolfssl_servers.sh   # -> vendor/wolfssl5XX/bin/server
   ```

All paths follow **CLI flag → environment variable → derived default**, so nothing is hardcoded.
Run `python3 puts.py --put openssl wolfssl` to print the resolved configuration.

## Reproduce

Rebuild the matrix, tree, validation and report for both PUTs from the committed probe set, then
print a combined summary:

```
python3 run_fingerprint.py --put openssl wolfssl
```

PUTs run **sequentially** (never two matrices in parallel) — this controlled-load discipline is what
keeps the matrix uncorrupted (see DEVELOPER.md). Pin to a spread, lightly-loaded core set:

```
python3 run_fingerprint.py --put openssl \
    --prober /path/to/tlspuffin --cores 0,2,4,6,8,10,12,14,16,18,20,22,24,26,28 --jobs 15
```

Run a subset of stages with `--stages` (default `matrix,tree,validate,report`; `mine` is off by
default because it needs fresh differential campaigns):

```
python3 run_fingerprint.py --put openssl --stages tree,validate,report   # from the committed matrix
```

Outputs land in `reference/<put>/`. Expected: OpenSSL → 10 clusters, depth 3, 61/61; WolfSSL → 14
clusters, depth 4, 24/24.

### Mining probes from scratch (optional)

`mine_probes.py` turns differential-campaign objective traces into a confirmed probe set. Point it
at the campaigns with `--experiments-glob` (or `FP_EXPERIMENTS_GLOB`):

```
python3 run_fingerprint.py --put openssl --stages mine,matrix,tree,validate,report \
    --experiments-glob '/path/to/experiments/*openssl*fpp*/objective/*.trace'
```

## Identify a live target

Point the prober at a host:port. With a **list of PUTs** it determines *which library* and *which
version-cluster*, abstaining cleanly if neither model matches:

```
python3 fingerprint_probe.py --host 127.0.0.1 --port 4433 --put openssl wolfssl --json
# or via the driver:
python3 run_fingerprint.py identify --host example.com --port 443 --put openssl wolfssl
```

A model only *claims* a target when every decision probe’s live response matches a real branch
(no forced default, no missing response), so an unrelated stack returns `unknown` rather than a
false positive.

## What is committed

Per PUT, `reference/<put>/` holds the inspectable canonical result:

- `signatures.csv` — the cross-apply matrix (probe × version → signature key)
- `clusters.json` — the wildcard compatibility clusters
- `tree.json` + `meta.json` — the deployment model the prober walks
- `probes/` — **only** the decision-node probe traces the tree replays (+ `manifest.csv`)
- `validation.json`, `report.md`, `heatmap.csv` — the deployment number and human report

The **full** confirmed-probe set (hundreds of traces) needed to rebuild the matrix from scratch is
bulky and regenerable, so it is **not** committed — `mine_probes.py` recreates it under
`reference/<put>/probes_full/` (gitignored). Superseded scripts and exploratory data live in
`archive/` (gitignored).

For the methodology, the three hard-won correctness invariants, and how to add a new PUT, see
**DEVELOPER.md**. For the OpenSSL fixed-oracle story and exact campaign numbers, see **REPRODUCE.md**.
