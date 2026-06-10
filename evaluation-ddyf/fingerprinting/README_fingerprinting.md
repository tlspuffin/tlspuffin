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
| WolfSSL 5.x (5.0.0–5.9.1) | 26 | **14** | 4 | 6 | **26/26** recognised, consistently, ≤4 traces |

“Cluster” = a group of versions no probe can tell apart over the wire. The OpenSSL boundaries are
dominated by upstream’s coordinated release waves (e.g. cluster {3.2.4, 3.3.3, 3.4.1} is exactly the
Feb-2025 backport set); see `reference/openssl/report.md`.

> **Scope note.** These are the **live-TCP** numbers (a remote observer who never decrypts). An
> offline regime that *does* decrypt (display-execute / FFI signatures) resolves WolfSSL more
> finely (26 versions → 21 clusters), because some WolfSSL changes are only visible in decrypted
> content; live-TCP cannot see those and merges them. The artifact ships the honest live-TCP models.
> Caveat on the WolfSSL 26/26: 5.5.0 and 5.5.1 have no working vendored example server (their build
> is incomplete), so they emit no wire response and `validate.py` flags them explicitly; with all
> cells UNSTABLE they follow the tree's default branch into cluster C0 — which does contain them — so
> they count as recognised, but on default routing, not on observed behaviour. The other 24 are
> recognised on their live responses.

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
tree_report.py       inspect a model: ASCII tree + per-branch wire-observable flight labels
                     (e.g. "0: HRR | 4: Alert(HandshakeFailure) | 5: (Terminated)"). Needs a
                     PUT-linked tlspuffin (display-execute), not the tcp-only prober.

reference/<put>/     committed canonical model + results (see "What is committed")
setup.sh             one-shot bootstrap: build prober + all vendored servers + cert
  build_all.sh       vendor any PUT's versions (mk_vendor) + build the harness
  build_openssl3x.sh vendor the OpenSSL servers
  build_wolfssl_servers.sh + sancov_stub.c   compile the WolfSSL example servers
```

## From a fresh clone

Enter the dev shell **first**, then run the bootstrap *inside* it (the `nix-shell ... --run` one-liner
does not work for this build):

```
git clone <repo> && cd <repo>
nix-shell ./shell.nix                       # drops you into the dev shell
# If your NIX_PATH is empty / nix-shell warns about <nixpkgs>, pin nixpkgs explicitly:
#   nix-shell -I nixpkgs=https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz ./shell.nix
./evaluation-ddyf/fingerprinting/setup.sh   # run this INSIDE the nix-shell
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

> Prober note (read DEVELOPER.md): WolfSSL's example server is RST-killed by the rapid TCP teardown
> unless the prober pauses ~100 ms around each socket I/O; without it the server crashes mid-handshake
> and the 10×/≥7 confirm flaps UNSTABLE. That pause is **implemented** in `tlspuffin/src/tcp/mod.rs`
> as an env-gate **`PUFFIN_TCP_IO_SLEEP_MS`** (default **100 ms**; `0` disables), applied *before each
> read* (so the full flight buffers) and *after each write*. It is **universal, not per-PUT** — a
> remote prober cannot know whether the target is OpenSSL or WolfSSL, so one setting must serve both;
> 100 ms is what lets WolfSSL respond reproducibly, while only slightly perturbing OpenSSL (≈61/61 →
> 59/61). A freshly-built `tlspuffin` therefore sleeps by default; to reproduce the original OpenSSL
> **61/61** exactly, run its prober with `PUFFIN_TCP_IO_SLEEP_MS=0`. *(Open optimisation: make the
> pause adaptive — return early on a response/FIN — to recover the speed the fixed sleep costs.)*

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
  wolfssl : 14 clusters, depth 4, recognised 26/26 consistently (<= 4 traces)
```

(The default `--stages` is `validate,report`.)

### Rebuild the tree (both PUTs)

Both PUTs ship their **full** confirmed probe set under `reference/<put>/probes_full/` (committed),
so the tree is re-inducible from the committed matrix without re-running campaigns:

```
python3 run_fingerprint.py --put openssl wolfssl --stages tree,validate,report
#   openssl -> 10 clusters, 61/61      wolfssl -> 14 clusters, 26/26
```

A *full* rebuild that also re-probes the matrix (`--stages matrix,tree,validate,report`) re-reads
`probes_full/`; it is fast for OpenSSL but slow for WolfSSL, because the prober's 100 ms inter-action
pause (which is what makes the WolfSSL example server respond reproducibly — see DEVELOPER.md) makes
the 77×26 re-probe take a while. `build_tree.py` refuses to run only if `probes_full/` is **absent**
(so a model is never silently replaced by one whose probe traces aren't available).

### Full rebuild from the fuzzing campaigns (both PUTs)

The whole pipeline is reproducible end to end — launch the campaigns, mine, then rebuild:

```
# stage 0: run one differential campaign per adjacent version pair -> experiments/
python3 run_campaigns.py --put openssl --timeout 1h --jobs 20 --cores 0-19
# stages 1-5: mine the objectives -> matrix -> tree -> validate -> report
python3 run_fingerprint.py --put openssl --stages mine,matrix,tree,validate,report \
    --cores 0,2,4,6,8,10,12,14,16,18,20,22,24,26,28 --jobs 15
```

`mine_probes.py` reads the campaigns and writes the confirmed probe set into
`reference/<put>/probes_full/` (committed — see below), so `build_matrix`/`build_tree` find it by
default. **Where it looks for the campaigns** follows CLI → env → derived default, so it works out of
the box yet can be pinned anywhere:

- **`--experiments-dir DIR`** / `FP_EXPERIMENTS_DIR` — just the experiments *folder*; the per-PUT
  layout `*<put>*fpp*/objective/*.trace` is appended automatically. Use this to point at campaigns
  living outside the repo (e.g. `--experiments-dir /data/ddyf/experiments`).
- **`--experiments-glob GLOB`** / `FP_EXPERIMENTS_GLOB` — a full explicit glob; overrides
  `--experiments-dir`. Use it to mine a single batch or one pair, e.g.
  `--experiments-glob '<repo>/experiments/2026-06-10--wolfssl-*-1cfpp-*/objective/*.trace'`.
- **default** (neither given): `<repo>/experiments/*<put>*fpp*/objective/*.trace`.

The same two commands with `--put wolfssl` rebuild WolfSSL from its campaigns. Override
`--reference-dir` to write the rebuilt model somewhere other than the committed `reference/`.

### Reproduce from published experiment archives (no campaigns needed)

The differential-fuzzing campaigns are the slow part (hours). For **full reproducibility without
re-running them**, the campaigns' *objective traces* are published as archives; the pipeline then
runs `mine → matrix → tree → validate → report` straight from them (only the live re-probing,
minutes, is recomputed):

| archive | contents | raw / compressed | sha256 |
|---|---|---|---|
| `wolfssl_lastnight_objectives.tar.gz` | WolfSSL 5.x campaigns, one focused 2-PUT run per adjacent pair (the clean last-night batch) | 4.6 GB / **256 MB** | `dbf1c9710a7ef6b239f40b3e2e75a81990569bcb5c21b48254065e87002fa47e` |
| `wolfssl_all_objectives.tar.gz` | WolfSSL 5.x **all** campaigns (last-night + earlier batches) — more objectives for the older pairs, for a denser re-mine | 5.5 GB / **306 MB** | `d7b01db702243fb2a65a8c3defc350d2c59e42f0279dbbdae4c6cf2e61422558` |
| `openssl_objectives.tar.gz` | OpenSSL 3.x adjacent-pair campaigns (objective traces) | 18 GB / **920 MB** | `b04d322ea48dc0364fc88f77f1d1cef8d6015b965ff1d45082eaa1929764cc49` |

Download: **`<FILL IN URL AFTER UPLOAD>`** (e.g. Zenodo / GitHub release); verify against the sha256
above. Each archive unpacks to `<campaign-dir>/objective/*.trace` — the layout the mine globs — so you
point the pipeline at the extraction dir with `--experiments-dir`:

```
# 1. download + extract (preserves the <campaign>/objective/ layout)
mkdir -p ~/ddyf_experiments
tar -xf wolfssl_lastnight_objectives.tar.gz -C ~/ddyf_experiments

# 2. mine the objectives (cap per-pair for speed; omit --a1-cap to use every objective)
python3 mine_probes.py --put wolfssl --experiments-dir ~/ddyf_experiments \
    --reference-dir ./reproduced --prober /path/to/tlspuffin --jobs 24 --a1-cap 400

# 3. matrix -> tree -> validate -> report from the mined probe set
python3 run_fingerprint.py --put wolfssl --stages matrix,tree,validate,report \
    --reference-dir ./reproduced --prober /path/to/tlspuffin --jobs 24
```

(Same prober note as above: a freshly-built `tlspuffin` paces with `PUFFIN_TCP_IO_SLEEP_MS=100` by
default, which WolfSSL needs.) Swap `--put openssl` + `openssl_objectives.tar.gz` for OpenSSL.

## Identify a live target

Point the prober at a `host:port`. With a **list of PUTs** it determines *which library* and *which
version-cluster*, abstaining cleanly if neither model matches.

`fingerprint_probe.py` needs something listening on the target port — against a closed port it just
blocks/retries. To try it locally, start a vendored version as a TCP target with `serve.py` in one
terminal, then probe it from another:

```
# terminal 1 — start a live target (a vendored stock server on :4433)
python3 serve.py --put openssl --version 3.6.2 --port 4433

# terminal 2 — identify it across both PUT models
python3 fingerprint_probe.py --host 127.0.0.1 --port 4433 --put openssl wolfssl --json
# or via the driver, against any real endpoint:
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

### OpenSSL campaign funnel (provenance)

The committed OpenSSL model came from: **24,235** fixed-oracle differential objectives →
**2,110** that survive a first live screen → **275** confirmed probes (the strict 10×/≥7 filter),
cross-applied to all 61 versions → a clean signature matrix → a wildcard tree of **depth 3 / 3
probes** → **10 clusters** → **61/61** recognised on the train/test live walk. (WolfSSL: the
2026-05-29 campaigns → 77 confirmed probes → 14 clusters → 26/26.)

For the methodology, the three hard-won correctness invariants (wire-observable oracle, 10×/≥7
confirmation, controlled-load + deployment-validate), and how to add a new PUT, see **DEVELOPER.md**.
