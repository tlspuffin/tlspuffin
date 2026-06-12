# Developer guide — DDYF version fingerprinting

How the pipeline is built, the invariants that make it correct, and how to extend it. For *using*
it (reproduce, identify a target), see `README_fingerprinting.md`.

## Big picture

Differential fuzzing of two PUT versions produces *objective* traces: client-driven traces on which
the two versions diverged. Most divergences are in-process artifacts that are invisible to a remote
observer. The pipeline distills the few traces that produce a **robust, wire-observable** difference
into a deterministic decision tree, then *validates that tree against freshly-probed live servers*.

```
run_campaigns ──▶ mine_probes ──▶ build_matrix ──▶ build_tree ──▶ validate ──▶ report
 differential      confirmed        signature        wildcard      walk live     report.md
 campaigns         probes           matrix           tree (model)  servers       + heatmap
 (experiments/)    (probes_full/)
```

Both the confirmed probe set (`probes_full/`) and the deployment model (`tree.json` + `probes/`) are
committed, so steps 2-5 reproduce from the repo alone; step 0 (`run_campaigns`) + step 1 regenerate
`probes_full/` from scratch when you want to re-mine.

Everything is parametrised by PUT; one driver (`run_fingerprint.py`) runs any list of PUTs.

## Components & data contracts

| file | role | reads | writes |
|---|---|---|---|
| `puts.py` | PUT registry + path/runtime resolver (CLI→env→derived) | — | — |
| `probe.py` | live-probing primitives: `pooled_sig` (10×/≥7), `batch`, `launch`, `sigkey` | — | — |
| `_canon.py` | canonicalise a capture to a wire signature (strip volatile fields) | — | — |
| `build_live_matrix.py` | `server_argv()` = how to launch each stack's stock server | — | — |
| `run_campaigns.py` | stage 0: launch `differential-experiment` per adjacent pair | vendored servers | `experiments/*<put>*fpp*/objective/*.trace` |
| `mine_probes.py` | screen→dedup→confirm objectives | `experiments_glob` | `reference/<put>/probes_full/{*.trace,reps.txt}` |
| `build_matrix.py` | cross-apply probes × versions (controlled load) | `probes_full/reps.txt` | `reference/<put>/{signatures.csv,clusters.json}` |
| `build_tree.py` | wildcard decision-tree induction | `signatures.csv` | `reference/<put>/{tree.json,meta.json,probes/}` |
| `validate.py` | deployment validation (walk fresh live servers, R×) | model | `reference/<put>/validation.json` |
| `report.py` | human report + heatmap | model + matrix + validation | `reference/<put>/{report.md,heatmap.csv}` |
| `fingerprint_probe.py` | identify a live host:port across PUT models | `reference/<put>/` | stdout |
| `run_fingerprint.py` | driver (construction + `identify`) | — | — |

### The model (what the prober walks)

`reference/<put>/tree.json` is a node tree:

```jsonc
{"type":"node","trace":"probes/<file>.trace","probe":<col>,"default":<sig>,
 "children": { "<sig>": <node-or-leaf>, ... }}
{"type":"leaf","clusters": [ ["<ver>", ...] ]}     // one cluster of indistinguishable versions
```

`reference/<put>/meta.json` = `{canon:"tcp_mode", vendor:<put>, sig_len:<int>, clusters:[[...]]}`.

**`sig_len`** is the only subtlety: a live probe always yields the full 64-hex canonical signature,
but a model may key its branches on a *prefix*. The committed OpenSSL model uses `sig_len=10`
(`build_matrix` stored `sig[:10]`); the WolfSSL model uses `sig_len=0` (full sigs). The walk
truncates the live sig with `probe.sigkey(full, sig_len)` before matching. New PUTs: pick a length
in the `PUTS` registry and stay consistent between `build_matrix` and the walk (both read it).

## The three correctness invariants

These are not optional — each fixes a failure that *looked* like signal but was an artifact.

1. **The differential oracle must be wire-observable.**
   In `puffin/src/execution.rs`, `DifferentialRunner::execute_config` records a status objective
   only for wire-observable outcomes — a PUT-level error at a *different* step, or one side a clean
   PUT error while the other cleanly succeeds — never for internal `Fn`/`Crypto`/codec errors (whose
   error *string* is internal state a remote client never sees). With the broad oracle, a fuzzed
   decoder reading the server's fresh random bytes as a length prefix fails ~50% of the time and
   floods each adjacent pair with ~10⁵ non-deterministic "objectives". With the fixed oracle: 0–few
   per adjacent pair. (Do not widen this oracle.)

2. **An in-process objective is not a wire difference — confirm with 10×/≥7.**
   Replayed against a real server, most objectives give the *same* canonical response on both
   versions, and the server answers a given probe only intermittently (per-connection jitter), so
   single-shot verdicts flip run to run. `probe.pooled_sig` runs each probe `N_POOL=10` times and
   accepts the modal max-depth signature only if it recurs `DOM=7` times; otherwise the cell is
   `UNSTABLE` and treated as **missing** (never forces a tree split).

3. **Build the matrix under controlled load, and deployment-validate.**
   The TCP read uses a fixed idle timeout; under heavy parallel load a server's flight is
   *truncated* and the captured signature is corrupted. A matrix built under ~90 parallel probe
   threads once made a tree mis-route **42/61** live servers — which mimics "cross-session version
   drift" but is purely a load artifact (only ~6% of those cells reproduced on clean re-probing).
   `build_matrix.py` therefore probes **each server sequentially** (one connection at a time, ≤
   `--jobs` servers in parallel), retries `UNSTABLE`, and re-checks stragglers single-threaded.
   Then `validate.py` does a **train/test split**: it walks the tree against *freshly-probed* live
   servers (R independent walks each). The honest robustness number is the validation count
   (OpenSSL 60/61, WolfSSL 26/26), never the construction count. Always run on a quiet machine and,
   when others share it, pin to a spread idle core set via `--cores`.

## Canonicalisation (`_canon.py`)

`canonicalize_execution(data, tcp_mode=True, live_mode=True)` reduces a capture to the
wire-observable response: alert behaviour, message-flight sequence, encrypted-record structure
(type/count/coarse size bucket). `_VOLATILE` always strips fields a remote client cannot pin or an
operator may reconfigure: randoms, session IDs, key-share, certificate chains, **and currently the
offered cipher suites** (`cipher_suite`/`cipher_suites`). `_VOLATILE_AGGRESSIVE` (off) would also
strip extensions/sig-algs/groups/versions. Changing what is stripped changes cluster resolution, so
treat it as a deliberate experiment. (Keeping `cipher_suite` as a real difference is a known,
currently-deferred option.)

## Adding a new PUT

1. **Registry** — add an entry to `PUTS` in `puts.py`: `server_cmd`, `vendor_glob`, `ver_re`
   (captures the two version components), `line`, `base_port`, `drop`, `features`, `sig_len`.
2. **Server launch** — add a branch to `server_argv()` in `build_live_matrix.py` returning
   `(argv, env, cwd)` for the stack's stock example server (it must accept many connections and not
   exit on a malformed probe).
3. **Vendor servers** — a build script (à la `build_openssl3x.sh` / `build_wolfssl_servers.sh`) that
   produces `vendor/<ver>/bin/<server>` for each version.
4. **Run** — `run_fingerprint.py --put <new> --stages mine,matrix,tree,validate,report
   --experiments-glob '<this PUT's objective traces>'`.

No stage script needs editing — they all read the registry and the resolver.

## Runtime knobs

All via CLI flag → env var → derived default (see `puts.add_common_args`):
`--prober`/`PUFFIN_BIN`, `--vendor-dir`/`VENDOR_DIR`, `--reference-dir`/`FP_REFERENCE`,
`--repo-root`/`DDYF_ROOT`, `--experiments-dir`/`FP_EXPERIMENTS_DIR`,
`--experiments-glob`/`FP_EXPERIMENTS_GLOB`, `--cores`/`CORES`, `--jobs`/`JOBS`,
`--base-port`/`BASE_PORT`, `--timeout`/`TIMEOUT`. `python3 puts.py --put …` prints the resolved set.

**Locating the campaigns (mine stage).** `Config.experiments_glob(put)` resolves in three tiers:
`--experiments-glob`/`FP_EXPERIMENTS_GLOB` (a full glob, most precise) > `--experiments-dir`/
`FP_EXPERIMENTS_DIR` (just the folder; the `*<put>*fpp*/objective/*.trace` layout is appended) >
the derived default `<repo>/experiments/...`. So the default works out of the box, a relocated
experiments folder needs only `--experiments-dir`, and a single batch/pair is selectable with a
precise `--experiments-glob`.

**Prober I/O pause — `PUFFIN_TCP_IO_SLEEP_MS` (+ `--timeout`).** A single env-gate read in
`tcp/mod.rs` (`io_pacing_sleep()`), default **100 ms**, `0` disables; it sleeps before each
`read_to_end` and after each write on both TCP puts. **The right value is PUT-specific at
model-build time:**
- **OpenSSL: `=0`** (no pause) + `--timeout 12`. OpenSSL answers immediately; a pause only perturbs it.
- **WolfSSL: `=150` + `--timeout 15`.** WolfSSL's distinguishing flights on several adjacent pairs are
  slow; at 100 ms / 12 s the prober *undersamples* them — cells go UNSTABLE and adjacent versions
  merge — so always probe WolfSSL at **150 ms / 15 s** for stable capture. *Given* stable capture, the
  cluster **count** is then set by probe-set density: the committed dense **77-probe** set splits
  5.3.0/5.4.0 and 5.7.2/5.7.4 (→ **14** clusters, depth 4); a sparser set lacks those discriminators
  and merges both pairs (→ 12). So the WolfSSL number is both parameter-bound (150/15 for stability)
  *and* probe-set-bound (the 77 probes carry the two extra splits).

The env-gate is what lets one binary serve both (set the value per run). A genuinely *universal*
deployment prober that doesn't know the target's library is the open problem — the adaptive-pause idea
(return early on response/FIN) would shrink the OpenSSL perturbation and let one setting fit both.