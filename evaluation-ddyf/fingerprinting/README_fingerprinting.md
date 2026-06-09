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

run_campaigns.py     stage 0  launch the differential-fuzzing campaigns -> experiments/
run_fingerprint.py   the driver (construction + identification)
  mine_probes.py     stage 1  objectives -> confirmed probes (-> probes_full/)
  build_matrix.py    stage 2  cross-apply matrix (controlled load)
  build_tree.py      stage 3  wildcard decision tree (the model)
  validate.py        stage 4  deployment validation (walk fresh live servers)
  report.py          stage 5  report.md + heatmap.csv
fingerprint_probe.py identify a live host:port across one or more PUT models

reference/<put>/     committed canonical model + results (see "What is committed")
setup.sh             one-shot bootstrap: build prober + all vendored servers + cert
  build_all.sh       vendor any PUT's versions (mk_vendor) + build the harness
  build_openssl3x.sh vendor the OpenSSL servers
  build_wolfssl_servers.sh + sancov_stub.c   compile the WolfSSL example servers
```

## From a fresh clone

```
git clone <repo> && cd <repo>
nix-shell ./shell.nix --run ./evaluation-ddyf/fingerprinting/setup.sh
```

`setup.sh` is the one-shot bootstrap: it builds everything the pipeline expects **at its default
paths** —

1. every vendored per-version library + server (`vendor/openssl3XX/bin/openssl`,
   `vendor/wolfssl5XX/bin/server`) via `tools/mk_vendor` + the version presets,
2. the `tlspuffin` prober/fuzzer at `target/release/tlspuffin` (the default `--prober`),
3. the WolfSSL example servers (`build_wolfssl_servers.sh`), and
4. a throwaway localhost cert the OpenSSL `s_server` needs.

It is **long** (≈90 version builds + the harness) but idempotent (re-running skips what exists).
Build a subset with e.g. `PUTS=openssl` or `VERSIONS_OPENSSL="3.6.2" VERSIONS_WOLFSSL="5.9.1"`.
Then `python3 puts.py --put openssl wolfssl` prints the resolved configuration. After bootstrap:

```
python3 run_fingerprint.py --put openssl wolfssl     # live-test the committed models
```

All paths follow **CLI flag → environment variable → derived default**, so nothing is hardcoded;
override the prober with `--prober PATH` / `PUFFIN_BIN`, the vendored servers with `--vendor-dir`,
etc. Inspecting the committed `reference/<put>/report.md` needs none of the above.

> Prober note: `target/release/tlspuffin` uses a 2000 ms TCP read window (`tlspuffin/src/tcp/mod.rs`)
> — robust against truncation. A shorter window probes faster but can truncate slower WolfSSL flights
> (see DEVELOPER.md); tune it there if you re-probe at scale.

## Reproduce

### Live-test the committed models (default)

Walk each committed decision tree against freshly-launched live servers for every version, R=5
times, and print a combined summary. This is the default and the headline reproduction:

```
python3 run_fingerprint.py --put openssl wolfssl \
    --prober /path/to/tlspuffin --cores 0,2,4,6,8,10,12,14,16,18,20,22,24,26,28 --jobs 12
```

PUTs run **sequentially** (never two in parallel) — this controlled-load discipline keeps live
captures from truncating (see DEVELOPER.md). Expected combined summary (≈3–4 min):

```
  openssl : 10 clusters, depth 3, recognised 61/61 consistently (<= 3 traces)
  wolfssl : 14 clusters, depth 4, recognised 23/24 consistently (<= 4 traces)
```

(The default `--stages` is `validate,report`. WolfSSL 5.3.0 is the one miss under the strict
tree-walk; see the result note above.)

### Rebuild the tree from scratch (OpenSSL)

`build_matrix`/`build_tree` re-probe and re-induce the tree, so they need the **full** confirmed
probe set, which `mine_probes` regenerates from the differential campaigns (it is gitignored, not
committed). OpenSSL ships its full probe list (`reference/openssl/probes_full/reps.txt`), so its tree
is fully rebuildable from the committed matrix:

```
python3 run_fingerprint.py --put openssl --stages tree,validate,report   # -> 10 clusters, 61/61
```

The WolfSSL tree is a **pre-built, validated model** carried over from the earlier pipeline; the
full WolfSSL probe set is not committed, so `build_tree.py --put wolfssl` deliberately **refuses**
to rebuild (it would otherwise replace a 23/24 model with a weaker one). Reproduce WolfSSL with
`--stages validate,report` (the default), or mine a fresh WolfSSL probe set first.

### Full rebuild from the fuzzing campaigns (both PUTs)

The whole pipeline is reproducible end to end — launch the campaigns, mine, then rebuild:

```
# stage 0: run one differential campaign per adjacent version pair -> experiments/
python3 run_campaigns.py --put openssl --timeout 1h --jobs 20 --cores 0-19
# stages 1-5: mine the objectives -> matrix -> tree -> validate -> report
python3 run_fingerprint.py --put openssl --stages mine,matrix,tree,validate,report \
    --cores 0,2,4,6,8,10,12,14,16,18,20,22,24,26,28 --jobs 15
```

`mine_probes.py` reads the campaigns via `--experiments-glob` (default
`<repo>/experiments/*<put>*fpp*/objective/*.trace`) and writes the confirmed probe set into
`reference/<put>/probes_full/` (committed — see below), so `build_matrix`/`build_tree` find it by
default. Override `--experiments-glob` / `--reference-dir` / `--probes` to point at a fresh run.
The same two commands with `--put wolfssl` rebuild WolfSSL from its campaigns.

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
- `probes/` — the decision-node probe traces the tree replays (+ `manifest.csv`)
- `probes_full/` — the **full** confirmed-probe set (`*.trace` + `reps.txt`) so `build_matrix`/
  `build_tree` rebuild from the repo **without** needing the raw `experiments/`
- `validation.json`, `report.md`, `heatmap.csv` — the deployment number and human report

`reps.txt` lists bare filenames resolved against `probes_full/` (the committed default); point
`--reference-dir`/`--experiments-glob` elsewhere to run on a fresh campaign. The raw fuzzing output
(`experiments/`) and superseded scripts/data (`archive/`) are gitignored.

For the methodology, the three hard-won correctness invariants, and how to add a new PUT, see
**DEVELOPER.md**. For the OpenSSL fixed-oracle story and exact campaign numbers, see **REPRODUCE.md**.
