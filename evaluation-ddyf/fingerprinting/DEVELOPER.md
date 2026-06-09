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
   (OpenSSL 61/61, WolfSSL 24/24), never the construction count. Always run on a quiet machine and,
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
`--repo-root`/`DDYF_ROOT`, `--experiments-glob`/`FP_EXPERIMENTS_GLOB`, `--cores`/`CORES`,
`--jobs`/`JOBS`, `--base-port`/`BASE_PORT`, `--timeout`/`TIMEOUT`. `python3 puts.py --put …`
prints the resolved set.

## Gotchas

- **WolfSSL live (14) vs offline (21).** The live-TCP method merges versions whose only differences
  are in *decrypted* content. The offline decryption-enabled regime resolves 26 versions → 21
  clusters; live-TCP resolves 24 → 14. This artifact ships the live models for both PUTs.
- **Old vs new tree format.** The WolfSSL model predates the `probe`/`default` node fields; `report.py`
  and `validate.py` tolerate their absence (probe index is recovered from the trace basename; an
  unseen sig with no `default` falls back gracefully). New trees from `build_tree.py` include both.
- **Don't rebuild a shipped tree without its full probe set.** `build_tree.py` refuses to run when
  `reference/<put>/probes_full/reps.txt` is absent — otherwise it would induce a tree from the partial
  committed matrix and overwrite a validated model with a weaker one (a wildcard rebuild of the
  WolfSSL tree from only its 8 committed traces drops live recognition from 23/24 to 3/24). OpenSSL
  ships `probes_full/` (gitignored) so it rebuilds faithfully; the WolfSSL tree is reproduced by
  re-walking it (`--stages validate,report`), not rebuilding. Hence the driver default is
  `validate,report`, not a full rebuild.
- **WolfSSL has intrinsic per-probe jitter; OpenSSL does not.** Measured at ZERO contention
  (single server, fully sequential): OpenSSL gives 0 UNSTABLE cells (its matrix is fully
  reproducible at a 200 ms read window → `build_matrix` rebuilds it end to end, 10 clusters, 61/61).
  WolfSSL's example server, in contrast, returns genuinely non-reproducible responses to ~24/77 of
  the probes — and this is **neither load nor read-window**: it persists at 200 ms *and* 2000 ms
  (re-probing the 200 ms-UNSTABLE cells at 2000 ms stabilises 0 of them), and is unchanged by lowering
  load. So a wider read window buys WolfSSL nothing (just slower probing); 200 ms is the right window
  for both. The ~53 stable WolfSSL probes carry the signal (→ 14 clusters); the jittery 24 are
  correctly treated as wildcards. Because that intrinsic jitter makes a greedy wildcard rebuild pick
  flaky split probes (→ poor live walk), the committed WolfSSL tree is the earlier ID3/modal model
  (`build_live_matrix.py` + the original `build_tree`, validated 23/24), whose probe set
  (`reference/wolfssl/probes_full/`, from the same campaigns) is committed for reproducibility. A
  future unified WolfSSL rebuild should bias `build_tree` toward low-jitter (low-UNSTABLE) probes.
- **`experiments/` is gitignored** and large; the committed `probes/` holds only the decision-node
  traces. Rebuilding the matrix needs the full set (`mine_probes.py` regenerates it).
- **Provenance.** Superseded scripts, exploratory dirs, and prior reports are in `archive/`
  (gitignored) — including the older strict-three-batch OpenSSL analysis (`confirm_*`,
  `robust_partition*`) that produced the coarse 3-group lower bound before the controlled-load
  rebuild lifted it to the validated 10 clusters.
