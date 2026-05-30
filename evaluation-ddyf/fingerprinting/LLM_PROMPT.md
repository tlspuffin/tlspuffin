# Executor prompt — Automated TLS-stack version fingerprinting with DDYF

> Paste this whole file as the task for an autonomous coding agent (e.g. Claude Code)
> working **inside the `DDYF-fingerprinting` repository**. It is written to be run
> phase-by-phase with explicit STOP-and-report checkpoints so a human can correct
> course. Companion design doc: `evaluation-ddyf/fingerprinting/PLAN.md`.

## Role & mission

You are extending an academic differential cryptographic-protocol fuzzer ("DDYF",
a differential variant of the published fuzzer *puffin*). DDYF compares the outputs
of two Programs Under Test (PUTs) to surface behavioral differences. Benign
differences between *versions of the same TLS stack* are excellent for
**fingerprinting**: deciding which version a remote server runs.

Your mission: build an **automated pipeline** that fingerprints WolfSSL versions and
produce a rigorous **evaluation** plus **paper text**. Today the paper only has a
manual proof-of-concept (paper §RQ5 "Fingerprinting different versions of a PUT" in
`papier-diff-fuzzing/implem_and_eval.tex` around line 416, and
`papier-diff-fuzzing/appendix_fingerprinting.tex`). Automate and strengthen it.

## The method must be AI-free at runtime (core constraint)

AI (you) is used **only once, at authoring time, to write these scripts**. The
delivered fingerprinting method must contain **no AI/LLM call and no fuzzer** at
deploy time. There are two distinct stages — keep them separate:

- **Build-time (once):** you write the scripts; the *fuzzer* discovers candidate
  traces; deterministic scripts triage → cluster → build the decision tree.
- **Deploy-time (every fingerprint):** replay a small fixed set of `.trace` probes
  against the target, hash the TCP responses, and walk the static `tree.json`.
  This stage is pure, deterministic, dependency-light, and reproducible — **no LLM,
  no fuzzer, no learning, no randomness in classification.**

Do not introduce any model inference, ML classifier, or LLM call into the
classification path. The final artifact is: probe trace files + `tree.json` + a tiny
replay-and-classify routine that a third party can run with no AI dependencies.

## Absolute rules (do not violate)

1. **Always build and run inside the nix shell**: `nix-shell ./shell.nix`. Before any
   fuzzing, `export LIBAFL_EDGES_MAP_SIZE=262144`.
2. **Do NOT modify the harness / Rust code to make a new version build.** Adding PUT
   versions to `puffin-build/vendors/wolfssl/presets.toml` is allowed; if the *PUT*
   builds but the *tlspuffin harness* fails to compile against that version (API
   drift), record it, **exclude that version**, and **STOP and ask the human**
   before attempting any Rust change.
3. **Never fabricate, round-up, or extrapolate data.** Report only measured numbers.
   If a step is skipped or a version excluded, say so explicitly.
4. **Stay inside this repository.** Anything outside requires asking the human first.
5. **Stop at every CHECKPOINT below**, print the requested summary, and wait for the
   human to confirm or correct before continuing. Do not silently barrel through.
6. Long campaigns: launch in the background and poll; never block forever. Make every
   script **resumable/idempotent** (re-running must not duplicate work or corrupt data).

## Ground truth you must rely on (verify, don't assume)

- Discovery campaign:
  `./target/release/tlspuffin -p <PORT> --cores <CORES> differential-experiment <A> <B> -t <title>`
  → objective traces under `experiments/<dated-dir>/objective/*.trace`.
- Pairwise differential execution (the comparison oracle):
  `./target/release/tlspuffin differential-execute --json <A> <B> <trace>`
  → JSON array of `TraceDifference`. Variants (see `puffin/src/differential.rs`):
  `Status` (different execution status / executed steps),
  `Knowledges` (`DifferentTypes` | `InnerDifference`) — on-the-wire message knowledge,
  `Claims` (`DifferentTypes` | `InnerDifference`) — internal claims,
  `SecurityClaim` (`Different` | `BothError`).
- Single-PUT observable execution:
  `./target/release/tlspuffin --put <V> display-execute --json -t -k -c -p <trace>`
  → `execution.steps[*].{action,knowledges,claims}`, `execution.executed_until`,
  `error`, `execution.agents[*].protocol_config`, `execution.extra_knowledges`.
- Reusable triage library: `evaluation-ddyf/diff_analyzer.py` — reuse `get_diff`,
  `get_status`, and the `BucketCondition` classes (`NoDiffC`, `StatusC`,
  `InnerKnowledgeC`, `KnowledgeContainsC`, `AllC`/`AnyC`/`NotC`, …). Read it first.
- Existing manual example for sanity: the appendix found 2 traces distinguishing
  clusters A0=5.0.0, A1={5.1.0,5.1.1}, B=5.2.0. Your automated pipeline must at least
  reproduce this 3-cluster result on those 4 versions (a built-in regression check).

Before writing code, **read** `puffin/src/differential.rs`,
`evaluation-ddyf/diff_analyzer.py`, `evaluation-ddyf/fingerprinting_exp.sh`,
`DDYF_README.md`, and the two paper locations above. Confirm the JSON shapes by
running the binary on one existing objective trace (a build already exists under
`experiments/`), not by guessing.

---

## Phase 0 — Environment & sanity (CHECKPOINT 0)

1. Enter `nix-shell ./shell.nix`; confirm `cargo`, `just`, `cmake`, `clang`, `python3`.
2. There is already a build and sample objectives under `experiments/` for
   500/510/520. Use one of those `.trace` files to **verify the JSON schemas** of
   `differential-execute --json` and `display-execute --json` match what this prompt
   and `diff_analyzer.py` assume. Print one example of each.
3. Print the full target version list and confirm it matches PLAN.md (26 tags).

**STOP — CHECKPOINT 0.** Report: nix OK?, the two example JSON outputs, the version
list. Wait for confirmation.

## Phase 1 — Presets & builds (CHECKPOINT 1)

1. Write `evaluation-ddyf/fingerprinting/presets_gen.py` that appends idempotent
   `[wolfsslXYZ-asan]` blocks for every target tag to
   `puffin-build/vendors/wolfssl/presets.toml`, mirroring the existing block style
   (`sources.repo`, `branch = "vX.Y.Z-stable"`, `version`, `builder builtin wolfssl`,
   `asan = true`, `sancov = true`, `fix = ["AllowClaim"]`). Do not duplicate existing
   blocks. Show the diff; do not run it until the human confirms the block format.
2. Write `evaluation-ddyf/fingerprinting/build_all.sh`:
   - for each version: `./tools/mk_vendor make wolfssl:wolfsslXYZ-asan`
   - once all PUTs built: `cargo build --release --bin tlspuffin --features cputs,asan`
   - run `cargo clean` only if switching PUT sets (per DDYF_README).
   - capture per-version PUT build success/failure; capture harness build result.
3. Build incrementally from oldest to newest. On the **first** harness compile error
   attributable to a version's API, STOP (rule 2).

**STOP — CHECKPOINT 1.** Report a table: version | PUT build | harness build | included?.
Propose the buildable contiguous set to evaluate. Wait for confirmation.

## Phase 2 — Discovery campaigns (CHECKPOINT 2)

1. `./target/release/tlspuffin seed --fingerprinting` (like `--differential` but drops
   server-attacker seeds — see `prompts/CHANGELOG_seed_fingerprinting.md`).
2. Write `evaluation-ddyf/fingerprinting/discover.sh`: for each **adjacent** buildable
   pair (Vi, Vi+1), run a 1h / 10-core `differential-experiment` (configurable
   `TIMEOUT`, `CORES`, `PORT`; one unique PORT per concurrent campaign). Tag titles
   `fpp-<Vi>-<Vi+1>`. Make it resumable (skip pairs whose experiment dir exists and
   is non-empty).
3. Run them (background + poll). Collect objective counts per pair.

**STOP — CHECKPOINT 2.** Report objectives found per pair and total. If many pairs
have ~0 objectives, propose adding selected long-range pairs or increasing TIMEOUT.
Wait for confirmation.

## Develop Phases 3–5 on EXISTING data first (do this before/while campaigns run)

The repo already contains a build and sample objectives for 5.0.0/5.1.0/5.2.0 under
`experiments/` (counts are uneven: 500vs510 ~174 objectives, 510vs520 ~32, but
**500vs520 only ~6 — that pair barely ran**, and **5.1.1 is not built**).

Use this data in **two distinct ways**:

1. **Bootstrap (immediately):** author and debug `triage.py`, `signatures.py`,
   `build_tree.py` against the existing objectives. There are enough traces to exercise
   every code path (JSON parsing, filters, canonicalization, clustering, tree) without
   waiting for any campaign.
2. **Regression validation (do NOT trust the existing data for this):** the existing
   data is too thin/uneven to confirm correctness — after the benign+observable+
   deterministic filter the counts shrink, 500vs520 is unreliable, and 5.1.1 is absent
   so the A1={5.1.0,5.1.1} cluster cannot be tested. Therefore validate on a **fresh
   short campaign**: build 5.1.1 too, then run all pairs among
   {5.0.0, 5.1.0, 5.1.1, 5.2.0} for ~30–60 min each (the server is free).
   Success criterion: the pipeline reproduces the appendix result — clusters
   A0=5.0.0, A1={5.1.0,5.1.1}, B=5.2.0 — including the two named distinguishing traces
   (TLS1.2 session-ticket request separating 5.2.0; certificate-request →
   `UnexpectedMessage` `Alert` separating 5.0.0). Only after this passes, scale to 26.

## Phase 3 — Fingerprint triage (CHECKPOINT 3)

Write `evaluation-ddyf/fingerprinting/triage.py` on top of `diff_analyzer.py`:

1. **Keep only benign, remotely-observable** candidates. For a trace, run
   `differential-execute --json` on its discovery pair and keep it iff every reported
   difference is observable over TCP and benign:
   - KEEP `Knowledges` differences (server output messages differ).
   - KEEP `Status` differences **only** when the difference is an on-the-wire
     observable (e.g. one side sends an `Alert`/closes, visible to a remote client);
     classify using the status string and executed-steps, reusing `StatusC`.
   - DROP anything with a crash / ASAN / memory error / `SecurityClaim`, and DROP
     `Claims`-only differences (internal, not remotely observable).
2. **Determinism filter.** Re-execute each surviving trace **R times** (default R=10)
   and discard any whose observable outcome is not identical every time (handles
   nondeterminism). Keep R configurable.
3. **Deduplicate** traces with identical observable effect (same canonical signature,
   see Phase 4); prefer the shortest trace.
4. Output kept candidates to `evaluation-ddyf/fingerprinting/candidates/` with a
   manifest CSV (trace path, discovery pair, difference kind, summary).

**Self-check:** on versions {5.0.0,5.1.0,5.1.1,5.2.0}, the surviving candidates must
include traces matching the appendix description (a TLS1.2 ClientHello with session
ticket request distinguishing 5.2.0; a certificate-request → `UnexpectedMessage`
`Alert` distinguishing 5.0.0). If not, your filter is too aggressive — report and stop.

**STOP — CHECKPOINT 3.** Report: #candidates before/after benign filter, after
determinism filter, after dedup; and the regression self-check result.

## Phase 4 — Signatures & clustering (CHECKPOINT 4)

Write `evaluation-ddyf/fingerprinting/signatures.py`:

1. For every kept candidate trace `t` and every included version `v`, run
   `display-execute --json --put v -t -k -c -p t` and build a **canonical structural
   signature** of the TCP-observable response:
   - include: sequence/types of server output messages, present extensions, alert
     presence+code, content-type structure, whether/where execution stopped.
   - **normalize away volatile values**: random bytes, session IDs, timestamps, key
     shares, and any length that only reflects random material. (TLS responses embed
     server-random etc.; failing to strip these makes every run look different.)
   - signature = stable hash of the normalized structure.
2. Emit `signatures.csv` (rows = traces, cols = versions, cell = signature hash).
3. **Cross-validate**: for a sample of version pairs, confirm "signatures differ on t"
   agrees with `differential-execute --json v1 v2 t` reporting a benign diff. Report
   disagreements (they indicate a signature-canonicalization bug).
4. **Cluster**: group versions whose entire signature column vector is identical
   ("indistinguishable"). Emit `clusters.json`.

**STOP — CHECKPOINT 4.** Report: #clusters, cluster membership, the
signature-vs-differential cross-validation agreement rate, and any volatile-field
normalization you had to add. Wait for confirmation.

## Phase 5 — Optimization & decision tree (CHECKPOINT 5)

Write `evaluation-ddyf/fingerprinting/build_tree.py`:

1. **Decision tree**: greedy information-gain (ID3-style) over candidate traces; each
   trace multi-way-splits the current version set by signature value; recurse to
   singleton clusters. Emit `tree.json` and `tree.dot` (Graphviz).
2. **Minimal separating set**: greedy minimum test cover — fewest traces such that
   every distinguishable cluster pair is separated by ≥1 trace. Emit the set.
3. Emit `report.md`: #clusters, #distinct probes in the tree, #probes in the minimal
   set, the lower bound ⌈log₂(#clusters)⌉, tree depth, and the per-pair
   distinguishability heatmap (versions × versions).

**STOP — CHECKPOINT 5.** Report the tree (ASCII), the minimal set, and the metrics
table. Wait for confirmation.

## Phase 6 — Evaluation hardening (CHECKPOINT 6)

1. **Leave-one-pair-out**: for a few indistinguishable-looking and a few
   easily-distinguished pairs, rebuild the tree with that pair's discovery objectives
   excluded and confirm the remaining probes still classify both versions correctly.
2. **Stability**: re-run `signatures.py` after a fresh `cargo clean` + rebuild; confirm
   identical clusters/tree.
3. **Stealth assertion**: verify every probe in the final tree is benign on all
   versions (no crash/ASAN). Fail loudly if not.
4. **Indistinguishable pairs**: for each, fetch the upstream git diff between the two
   tags (`git ls-remote`/`git log` on the wolfssl repo, read-only) and summarize why
   they are behaviorally identical over TLS (mirror the 5.1.0/5.1.1 = 3 LoC memory
   example already in the appendix).

**STOP — CHECKPOINT 6.** Report all four results. Wait for confirmation.

## Phase 7 — Paper write-up (CHECKPOINT 7)

1. Rewrite the RQ5 subsection (`implem_and_eval.tex` ~line 416) to describe the
   **automated** pipeline and the headline numbers: N versions → K clusters, tree of
   D probes (vs ⌈log₂K⌉ lower bound), all stealthy, vs Atluri et al.'s 2 clusters.
   Keep the existing macros (`\gls{PUT}`, `\wolfssl`, `\tlsTerm{...}`, `\fuzzTerm{...}`,
   `\Cref`, `\ie`). Resolve/remove the `\luccaM{...}` margin notes appropriately.
2. Update `appendix_fingerprinting.tex` with the full method, the cluster table, the
   decision tree figure (from `tree.dot`), and the honest list of indistinguishable
   pairs with git-diff explanations.
3. Add a results table/figure to `assets/` if needed; do not break the LaTeX build
   (`latexmk`/`pdflatex` as the repo already uses). Build the PDF to confirm.
4. Match the surrounding writing style; do not overclaim (note the existing
   `\luccaM` hedge about the Atluri comparison and keep claims defensible).

**STOP — CHECKPOINT 7.** Show the diff of the `.tex` files and confirm the PDF builds.

---

## How the human can correct you (use these signals)

- At each CHECKPOINT, present a concise table/summary and **explicitly wait**.
- If a result contradicts the appendix regression (Phase 3 self-check) or the
  cross-validation (Phase 4) disagrees a lot, **stop and surface it** rather than
  tuning thresholds until it "looks right".
- Surface every excluded version, every dropped trace category with counts, and every
  normalization rule you added — these are exactly what the human needs to audit.
- Keep all randomness/thresholds (R, TIMEOUT, CORES, info-gain tie-breaks) as named,
  documented constants at the top of each script so the human can adjust and re-run.

## Definition of done

- `evaluation-ddyf/fingerprinting/` contains: `presets_gen.py`, `build_all.sh`,
  `discover.sh`, `triage.py`, `signatures.py`, `build_tree.py`, `run_all.sh`, plus
  outputs `signatures.csv`, `clusters.json`, `tree.{json,dot}`, `report.md`.
- The pipeline reproduces the appendix 3-cluster result on {5.0.0,5.1.0,5.1.1,5.2.0}.
- The paper RQ5 + appendix are updated and the PDF builds.
- A short `RESULTS.md` summarizing measured numbers and any caveats.
