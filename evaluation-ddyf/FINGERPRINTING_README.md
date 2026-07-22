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
| WolfSSL 5.x (5.0.0–5.9.1) | 24 | **16** | 4 | 8 | **24/24** recognised consistently, ≤4 traces | `--n-pool 30 --dom 21 --timeout 8` |

> **Current model = 16 WolfSSL clusters, depth 4, 8 probes, 24/24 (24 versions).** The committed
> numbers live in `reference/wolfssl/{meta.json,validation.json}` and are auto-adopted by
> `validate.py`/`fingerprint_probe.py`. History: an early 12-cluster model → a strict 806-probe
> rebuild at `N_POOL=30, DOM=21, timeout=8` → **15** clusters, then the RFC 7366 Encrypt-then-MAC
> probe split cluster {5.1.0, 5.1.1, 5.2.0} → **16** (adding the 8th decision probe). The remaining
> merged groups are indistinguishable over the current probe set (see the paper's fingerprinting
> appendix for the per-cluster source-diff analysis).
> (WolfSSL 5.5.0/5.5.1 are excluded — their vendored example server does not build; the model
> covers 24 versions. The vendored `wolfssl521` dir actually contains 5.0.1, so the `{5.0.0, 5.2.1}`
> cluster is really {5.0.0, 5.0.1}.)

“Cluster” = a group of versions no probe can tell apart over the wire. The OpenSSL boundaries are
dominated by upstream’s coordinated release waves; see `reference/openssl/report.md`. The committed
numbers were rebuilt with exactly the per-PUT prober params in the table.

> **Prober params are per-PUT (model-build time).** OpenSSL needs **no** pause (`=0`) — it answers
> immediately and a pause only perturbs it (the smaller-probe-set alternative is 10 clusters / 61-61,
> fully robust; the committed 11/60-61 uses the larger 639-probe run, trading one fragile
> single-version split). WolfSSL needs the pause + longer timeout (`150 ms` / `15 s`) to capture its
> slower distinguishing flights.

> **Merged groups are data/server-bound, not method-bound.** A few adjacent WolfSSL versions are
> wire-identical on *these* vendored default servers, so no probe separates them (see the paper's
> fingerprinting appendix). On servers/objectives that split those pairs the
> count can rise; 16 is the honest reproducible number for this repo's data + stock example servers.

> **Scope note.** These are the **live-TCP** numbers (a remote observer who never decrypts). An
> offline regime that *does* decrypt (display-execute / FFI signatures) resolves WolfSSL more
> finely (~21 clusters), because some WolfSSL changes are only visible in decrypted content;
> live-TCP cannot see those and merges them. The artifact ships the honest live-TCP models.
> Caveat on the WolfSSL 24/24: 5.5.0 and 5.5.1 have no working vendored example server (their build
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

## Fingerprinting mode & controls (all off by default — normal fuzzing is never affected)

Every fingerprinting-specific behaviour in `puffin`/`tlspuffin` is guarded so that normal and
differential fuzzing keep their baseline semantics unless explicitly requested. There is **one
primary switch** plus **two live-probe env-gates**:

| Control | Where | Effect (only when enabled) |
|---|---|---|
| **`--fingerprinting`** (CLI flag) | `puffin` root + `seed` subcommand | The single fingerprinting switch. Threaded via `FuzzerConfig` so it reaches fuzzer workers. Enables three things together: (1) **corpus** = client-attacker seeds only + the fingerprinting-only probe seeds (`tls::seeds::create_corpus` via `CorpusOptions`); (2) **no PUT-config uniformisation** — each PUT is probed under its real default config (`ProtocolTypes::differential_fuzzing_uniformise_put_config`); (3) **wire-observable differential objectives** — status objectives are restricted to PUT-level outcomes, dropping non-deterministic internal Fn/Crypto errors (`DifferentialRunner`). `run_campaigns.py --client-attacker-only` passes this flag. |
| **`FP_EMIT_DISPOSITION`** (env) | `tlspuffin/src/tcp/mod.rs` | Live-`tcp`-PUT only. Emits the terminal TCP disposition (`TCP_CLOSE`/`TCP_WAIT`/`TCP_RST`/`TCP_ERR`) on stderr so the prober can fold FIN/RST/WAIT into the signature. Set by the pipeline when the model's `disposition` param is on. Off ⇒ legacy signatures unchanged. |
| **`PUFFIN_TCP_IO_SLEEP_MS`** (env) | `tlspuffin/src/tcp/mod.rs` | Live-`tcp`-PUT only (see the prober note above). Paces socket I/O so slow servers aren't truncated. Default 100 ms; `0` disables. Never runs under in-process (FFI) fuzzing, so it cannot affect fuzzing throughput. |

Rule of thumb: **nothing here changes what a normal `experiment` / `differential-experiment`
campaign does unless you pass `--fingerprinting`** (or set the two `tcp`-PUT env-gates, which only
matter to the live prober).

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
#   -> wolfssl : 16 clusters, depth 4, recognised 24/24 consistently (<= 4 traces)
```

Each PUT probes its servers one at a time (controlled load) so live captures don't truncate (see
DEVELOPER.md). The default `--stages` is `validate,report`. (`target/release/tlspuffin` is what
`setup.sh` builds; it carries the `io_pacing_sleep` gate, so the same binary serves both via the env.)

### Rebuild the tree (both PUTs) — needs the mined corpus, which is NOT committed

> **The committed models do NOT ship `reference/<put>/probes_full/`** (the raw mined probe set,
> ~70 MB): it is git-ignored (`.gitignore`) to keep the repo small, and is reproducible from the
> published experiment archives (below) or by re-mining. What IS committed is enough to **use and
> validate** the models — the decision `probes/`, the `signatures.csv` matrix, `tree.json`,
> `meta.json`, `report.md`. So the default `--stages validate,report` works from a fresh checkout,
> but `--stages tree,...` (which needs `probes_full/reps.txt`) does **not** until you restore
> `probes_full/` from the archives or re-mine. `build_tree.py` refuses to run when `probes_full/` is
> absent, so a model is never silently replaced.

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
`reference/<put>/probes_full/` (git-ignored; restore from archives or re-mine), so `build_matrix`/`build_tree` find it by
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

**Download:** a single ZIP —
**<https://members.loria.fr/LHirschi/data/fingerprinting_traces.zip>** — containing two
gzip-tarballs of the campaigns' objective traces:

| archive (inside the zip) | contents |
|---|---|
| `openssl_objectives.tar.gz` | all OpenSSL 3.x adjacent-pair campaign objective traces |
| `wolfssl_all_objectives.tar.gz` | all WolfSSL 5.x campaign objective traces |

Each tarball unpacks to `<campaign-dir>/objective/*.trace` — the layout the mine globs — so you point
the pipeline at the extraction dir with `--experiments-dir`:

```
# 1. download + unzip, then extract the tarball(s) (preserves the <campaign>/objective/ layout)
wget https://members.loria.fr/LHirschi/data/fingerprinting_traces.zip
unzip fingerprinting_traces.zip
mkdir -p ~/ddyf_experiments
tar -xf wolfssl_all_objectives.tar.gz -C ~/ddyf_experiments      # or openssl_objectives.tar.gz

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

Each PUT model walks the target and reports how many decision nodes it *matched* vs had to *default*;
the verdict is the model with the most matched nodes (and fewest forced defaults), with `confidence`
from the margin. The right library wins because an unrelated model matches little and defaults a lot —
e.g. probing a live OpenSSL 3.6.2 server with `--put openssl wolfssl` returns `openssl → {3.6.2}` at
high confidence (openssl matched 2 / defaulted 0; wolfssl matched 1 / defaulted 2 and loses). (A model
*can* soft-claim with forced defaults, so the cross-model ranking — not a single model's walk — is
what makes the verdict robust; if no model matches anything it returns `unknown`.)

## What is committed

Per PUT, `reference/<put>/` holds the inspectable canonical result:

- `signatures.csv` — the cross-apply matrix (probe × version → signature key)
- `clusters.json` — the wildcard compatibility clusters
- `tree.json` + `meta.json` — the deployment model the prober walks
- `probes/` — the decision-node probe traces the tree replays (+ `manifest.csv`)
- `probes_full/` — the **full** confirmed-probe set (`*.trace` + `reps.txt`) so `build_matrix`/
  `build_tree` rebuild from the repo **without** needing the raw `experiments/`
- `validation.json`, `report.md`, `heatmap.csv` — the deployment number and human report

`reps.txt` lists bare filenames resolved against `probes_full/` (git-ignored — restore from archives or re-mine); point
`--reference-dir`/`--experiments-glob` elsewhere to run on a fresh campaign. The raw fuzzing output
(`experiments/`) and superseded scripts/data (`archive/`) are gitignored.

### OpenSSL campaign funnel (provenance)

The committed OpenSSL model (sleep=0) came from: **722,103** fixed-oracle differential objectives →
**639** confirmed probes (the strict 10×/≥7 filter), cross-applied to all 61 versions → a clean
signature matrix (0 UNSTABLE) → a wildcard tree of **depth 4 / 4 probes** → **11 clusters** →
**60/61** recognised on the train/test live walk (one version routes inconsistently — the trade for
the extra split; a smaller probe set gives the all-robust 10 / 61-61). WolfSSL (sleep=150, timeout=15)
came from the differential campaigns → confirmed probes → **16 clusters / 24-24** (depth 4,
8 probes), including the RFC 7366 EtM probe that splits {5.1.0, 5.1.1, 5.2.0}.

For the methodology, the three hard-won correctness invariants (wire-observable oracle, 10×/≥7
confirmation, controlled-load + deployment-validate), and how to add a new PUT, see **DEVELOPER.md**.
