# Automated TLS-stack version fingerprinting with DDYF — Plan of action

Goal: turn the *manual* RQ5 proof-of-concept (paper §"Fingerprinting different
versions of a PUT", `papier-diff-fuzzing/implem_and_eval.tex:416` and
`appendix_fingerprinting.tex`) into an **automated pipeline** that:

1. discovers behavioral differences between WolfSSL versions with DDYF,
2. triages them down to **benign, remotely-observable, deterministic** ones,
3. reconciles them into per-version **signatures** and **distinguishability clusters**,
4. optimizes a **minimal decision tree** of probe traces to identify the running version,
5. is **evaluated** rigorously, and
6. is **written up** in the paper.

## Core constraint: the method is AI-free at runtime

AI is used **only once, to author the scripts**. The delivered fingerprinting method
contains no AI/LLM call and no fuzzer at deploy time:
- **Build-time (once):** AI writes scripts; the fuzzer discovers candidate traces;
  deterministic scripts triage → cluster → build the decision tree.
- **Deploy-time (every fingerprint):** replay a fixed small set of `.trace` probes,
  hash the TCP responses, walk the static `tree.json`. Deterministic, reproducible,
  dependency-light, human-auditable — a selling point vs. ML/state-machine-learning
  fingerprinting (e.g. Atluri et al.).

## Decisions taken (2026-05-29)

- **Version universe**: the full *contiguous* WolfSSL 5.x stable line, **26 versions**
  `5.0.0, 5.1.0, 5.1.1, 5.2.0, 5.2.1, 5.3.0, 5.4.0, 5.5.0, 5.5.1, 5.5.2, 5.5.3,
  5.5.4, 5.6.0, 5.6.2, 5.6.3, 5.6.4, 5.6.6, 5.7.0, 5.7.2, 5.7.4, 5.7.6, 5.8.0,
  5.8.2, 5.8.4, 5.9.0, 5.9.1`
  (obtained via `git ls-remote --tags https://github.com/wolfSSL/wolfssl.git`; the
  missing patch numbers never existed, so this is the complete sequence).
  The evaluation runs on the largest contiguous prefix that **builds successfully**
  (PUT + harness); excluded versions are reported with the reason.
- **Discovery budget**: 1 h, 10 cores per campaign. Discovery on **adjacent pairs**
  (N−1 campaigns) is the default; global reconciliation (Phase 3) does the rest.
  Optionally add a few long-range pairs if adjacent discovery yields too few candidates.
- **Observation model**: **TCP-observable only (stealth)** — a signature is what a
  remote black-box client can see (server output messages, their types/extensions,
  alert behavior), with volatile fields (randoms, session IDs, timestamps, lengths
  of random material) normalized away. No crashes, no ASAN, no internal-only claims.
- **Execution**: this repo currently contains only the **plan + LLM prompt**
  (`LLM_PROMPT.md`). The pipeline scripts are to be implemented by the executor LLM.

## Key primitives (already in the repo)

- Campaign:    `tlspuffin -p <PORT> --cores <C> differential-experiment <A> <B> -t <title>`
               → objectives in `experiments/<dated-dir>/objective/*.trace`.
- Pairwise diff: `tlspuffin differential-execute --json <A> <B> <trace>`
               → JSON list of `TraceDifference` =
               `Status{first/second_executed_steps,first/second_status,total_step}`
               | `Knowledges(DifferentTypes|InnerDifference)`
               | `Claims(DifferentTypes|InnerDifference)`
               | `SecurityClaim(Different|BothError)`  (schema: `puffin/src/differential.rs`).
- Per-version: `tlspuffin --put <V> display-execute --json -t -k -c -p <trace>`
               → steps, knowledges, claims, error  (consumed by `diff_analyzer.py`).
- Reusable triage library: `evaluation-ddyf/diff_analyzer.py` (`get_diff`, `get_status`,
  `BucketCondition` family, `run_triaging`). Reuse it; do not reinvent.

## Pipeline (scripts to build under `evaluation-ddyf/fingerprinting/`)

- `presets_gen.py`     — emit `[wolfsslXYZ-asan]` blocks for all 26 tags into
                         `puffin-build/vendors/wolfssl/presets.toml` (idempotent).
- `build_all.sh`       — in nix-shell: `mk_vendor make` each `-asan` PUT, then
                         `cargo build --release --features cputs,asan`. On a harness
                         build failure for a version: record it, drop that version,
                         and **STOP to ask the user** before touching harness code.
- `discover.sh`        — adjacent-pair `differential-experiment` campaigns (1h/10c),
                         tagged dirs under `experiments/`.
- `triage.py`          — fingerprint filter built on `diff_analyzer.py`: keep
                         `Knowledges` diffs + observable alert `Status` diffs; drop
                         crashes/ASAN/`SecurityClaim`/internal-only `Claims`;
                         then re-execute R times and keep only deterministic traces.
- `signatures.py`      — run each surviving candidate on **every** version with
                         `display-execute --json`; canonicalize to a structural,
                         volatility-stripped signature; emit `signatures.csv`
                         (rows=traces, cols=versions, cells=signature hash) and
                         cross-check against pairwise `differential-execute`.
- `build_tree.py`      — cluster versions by identical signature column; greedy
                         info-gain decision tree + greedy minimal separating set;
                         emit `clusters.json`, `tree.json`, `tree.dot`, `report.md`.
- `run_all.sh`         — orchestrates the above end-to-end; resumable.

## Evaluation methodology

- **Distinguishing power**: number of clusters among the buildable versions;
  per-pair distinguishability heatmap; comparison to Atluri et al. (2 clusters for
  their overlapping WolfSSL range).
- **Efficiency**: #distinct probes in the optimized tree and in the minimal
  separating set, vs the lower bound ⌈log₂(#clusters)⌉; total round-trips/bytes.
- **Robustness / honesty**: leave-one-pair-out check (discover excluding a pair,
  confirm the chosen probes still classify it); explicitly list indistinguishable
  pairs together with their upstream git diff (as already done for 5.1.0/5.1.1).
- **Stealth**: assert 100% of selected probes are benign (no crash, no ASAN, no
  alert storm) — this is the core advantage over crash-based or SM-learning methods.
- **Stability**: re-run signatures across R repetitions and across a fresh build to
  confirm the tree is reproducible.

## Deliverables

- The scripts above + `signatures.csv`, `clusters.json`, `tree.{json,dot}`, `report.md`.
- Rewritten RQ5 subsection + `appendix_fingerprinting.tex` with the automated
  results, a results table/figure, and an honest limitations paragraph.

## Guardrails

- Always run builds/campaigns inside `nix-shell ./shell.nix`.
- `export LIBAFL_EDGES_MAP_SIZE=262144` before fuzzing.
- Never patch the harness to fix a version build without asking the user first.
- Never fabricate or extrapolate numbers; report only measured data and say so when
  a step was skipped or a version excluded.
