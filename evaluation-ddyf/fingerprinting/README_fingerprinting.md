# DDYF version fingerprinting of TLS libraries

Automatically learn, from differential fuzzing, a deterministic decision tree that tells **which
version (cluster) of a TLS library** a remote server runs — by replaying a handful of short,
fuzzer-discovered probe traces over a plain TCP socket and reading only the **wire-observable**
response. No machine learning, no fuzzing at deployment time, no decryption: the prober is a fixed
tree of fixed traces.

The same pipeline runs on any supported PUT (Program-Under-Test). Today: **OpenSSL 3.x** and
**WolfSSL 5.x**.

## Result (live-TCP, this artifact)

| PUT | versions | clusters | tree depth | probes used | live deployment validation | prober params |
|---|---:|---:|---:|---:|---|---|
| OpenSSL 3.x (3.0.0–3.6.2) | 61 | **11** | 4 | 4 | **60/61** recognised consistently, ≤4 traces | `PUFFIN_TCP_IO_SLEEP_MS=0` |
| WolfSSL 5.x (5.0.0–5.9.1) | 26 | **12** | 3 | 8 | **26/26** recognised consistently, ≤3 traces | `PUFFIN_TCP_IO_SLEEP_MS=150 --timeout 15` |

“Cluster” = a group of versions no probe can tell apart over the wire. The OpenSSL boundaries are
dominated by upstream’s coordinated release waves; see `reference/openssl/report.md`. The committed
numbers were rebuilt with exactly the per-PUT prober params in the table.

> **Prober params are per-PUT (model-build time).** OpenSSL needs **no** pause (`=0`) — it answers
> immediately and a pause only perturbs it (the smaller-probe-set alternative is 10 clusters / 61-61,
> fully robust; the committed 11/60-61 uses the larger 639-probe run, trading one fragile
> single-version split). WolfSSL needs the pause + longer timeout (`150 ms` / `15 s`) to capture its
> slower distinguishing flights.

> **WolfSSL 12 vs 14 — it's server/data-bound, not method-bound.** This artifact's campaigns yield
> **12** clusters (reproduced 3× here): a few sparse adjacent pairs — notably **5.3.0/5.4.0** — are
> wire-identical on *these* vendored servers, so no probe separates them, even with the denser
> combined campaigns (5.3.0-5.4.0 has 367 objectives yet 0 confirmed distinguishers). On a second
> machine whose vendored 5.3.0/5.4.0 servers *do* differ on the wire, the same pipeline (150/15)
> reaches **14** (5.3.0 and 5.4.0 become singletons). So **12 is the honest reproducible number for
> this repo's data**; 14 is achievable with servers/objectives that split those pairs.

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
Then `python3 puts.py --put openssl wolfssl` prints the resolved configuration. After bootstrap,
live-test the committed models — **per-PUT prober env** (see Reproduce for the expected numbers):

```
PUFFIN_TCP_IO_SLEEP_MS=0   python3 run_fingerprint.py --put openssl --stages validate,report --timeout 12
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl --stages validate,report --timeout 15
```

All paths follow **CLI flag → environment variable → derived default**, so nothing is hardcoded;
override the prober with `--prober PATH` / `PUFFIN_BIN`, the vendored servers with `--vendor-dir`,
etc. Inspecting the committed `reference/<put>/report.md` needs none of the above.

> Prober note (read DEVELOPER.md): WolfSSL's example server is RST-killed by the rapid TCP teardown
> unless the prober pauses around each socket I/O; without it the server crashes mid-handshake and the
> 10×/≥7 confirm flaps UNSTABLE. That pause is an env-gate **`PUFFIN_TCP_IO_SLEEP_MS`** in
> `tlspuffin/src/tcp/mod.rs` (default 100 ms; `0` disables), applied before each read and after each
> write. **The value is set per PUT at model-build time** (one binary, env per run):
> **OpenSSL `=0`** (it answers immediately; a pause only perturbs it) and **WolfSSL `=150` with
> `--timeout 15`** (its distinguishing flights are slower; 100/12 undersamples). A genuinely universal
> deployment prober that doesn't know the target's library is the open problem — the adaptive-pause
> idea (return early on a response/FIN) would let one fixed setting fit both.

## Reproduce

### Live-test the committed models (default)

Walk each committed decision tree against freshly-launched live servers for every version, R=5 times.
**The prober pause differs per PUT** (see the params table), so run them **separately** with the right
env each — one binary, value set per run:

```
# OpenSSL — NO pause:
PUFFIN_TCP_IO_SLEEP_MS=0   python3 run_fingerprint.py --put openssl --stages validate,report \
    --prober target/release/tlspuffin --timeout 12 --jobs 12
#   -> openssl : 11 clusters, depth 4, recognised 60/61 consistently (<= 4 traces)

# WolfSSL — 150 ms pause + 15 s timeout:
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl --stages validate,report \
    --prober target/release/tlspuffin --timeout 15 --jobs 12
#   -> wolfssl : 12 clusters, depth 3, recognised 26/26 consistently (<= 3 traces)
```

Each PUT probes its servers one at a time (controlled load) so live captures don't truncate (see
DEVELOPER.md). The default `--stages` is `validate,report`. (`target/release/tlspuffin` is what
`setup.sh` builds; it carries the `io_pacing_sleep` gate, so the same binary serves both via the env.)

### Rebuild the tree (both PUTs)

Both PUTs ship their **full** confirmed probe set under `reference/<put>/probes_full/` (committed),
so the tree is re-inducible from the committed matrix without re-running campaigns (same per-PUT env):

```
PUFFIN_TCP_IO_SLEEP_MS=0   python3 run_fingerprint.py --put openssl --stages tree,validate,report --timeout 12
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl --stages tree,validate,report --timeout 15
#   openssl -> 11 clusters, 60/61      wolfssl -> 12 clusters, 26/26
```

A *full* rebuild that also re-probes the matrix (`--stages matrix,tree,validate,report`) re-reads
`probes_full/`; it is fast for OpenSSL (no pause) but slow for WolfSSL, because the 150 ms inter-action
pause (which is what makes the WolfSSL example server respond reproducibly — see DEVELOPER.md) makes
the re-probe take a while. `build_tree.py` refuses to run only if `probes_full/` is **absent**
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

(Set the per-PUT prober env: WolfSSL `PUFFIN_TCP_IO_SLEEP_MS=150 --timeout 15`, OpenSSL
`PUFFIN_TCP_IO_SLEEP_MS=0`.) Swap `--put openssl` + `openssl_objectives.tar.gz` for OpenSSL.

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

The committed OpenSSL model (sleep=0) came from: **722,103** fixed-oracle differential objectives →
**639** confirmed probes (the strict 10×/≥7 filter), cross-applied to all 61 versions → a clean
signature matrix (0 UNSTABLE) → a wildcard tree of **depth 4 / 4 probes** → **11 clusters** →
**60/61** recognised on the train/test live walk (one version routes inconsistently — the trade for
the extra split; a smaller probe set gives the all-robust 10 / 61-61). WolfSSL (sleep=150, timeout=15)
came from the 2026-06-10 last-night campaigns → confirmed probes → **12 clusters / 26-26** (depth 3,
8 probes); see the WolfSSL 12-vs-14 note above.

For the methodology, the three hard-won correctness invariants (wire-observable oracle, 10×/≥7
confirmation, controlled-load + deployment-validate), and how to add a new PUT, see **DEVELOPER.md**.
