# Step-locked mutation stacking — design & evaluation methodology

## 1. What this feature does

A mutational **stage** may stack several mutations (see `GeometricStackMutator`). With step-locking
**enabled (default)**, all mutations stacked within one stage confine their **anchor selection** to a
**single step chosen at random once per stage**. Scope still governs how far the *effect* spreads:

- **Individual** → the one locked-step occurrence,
- **Step** → all occurrences within the locked step,
- **Global** → all occurrences across the whole trace (its *effect* reaches other steps, but its
  *anchor* was chosen inside the locked step).

Disable with the CLI flag **`--no-step-lock`**.

### Rationale (data-backed)
Replaying finished corpora showed **~51% of saved traces are broken on replay**, with breaks
clustered a few steps *after* the handshake. Cause: heavy stacking lets one stage anchor mutations
on **different** steps — an early edit gains coverage while a later edit breaks executability, yet
the whole broken-tailed trace is still saved because coverage improved (the **coverage-hitchhiker**
effect). Locking every anchor of a stage to one step makes the coverage gain and any executability
break attributable to the **same** step.

### Implementation map
- `puffin/src/fuzzer/utils.rs` — process-local `STEP_LOCK` + `set_step_lock`/`step_lock`; the skip
  in `reservoir_sample` (the single anchor chokepoint every `choose*` routes through). Fan-out via
  `find_all_*` deliberately ignores the lock, so Global stays trace-wide.
- `puffin/src/fuzzer/stages.rs` — `StepLockedStackMutator<PT, M>` wraps the stacking mutator; picks
  one step per stage, sets the lock around the inner stacking loop, restores it after.
- `puffin/src/fuzzer/config.rs` — `MutationStageConfig.step_locked_stacking` (default `true`).
- `puffin/src/cli.rs` — `--no-step-lock`; `puffin/src/fuzzer/libafl_setup.rs` — wiring;
  `puffin/src/experiment.rs` — `_nolock` run-dir suffix when disabled.
- Test: `utils::tests::test_step_lock_confines_anchors_to_locked_step`.

### Scope of v1 (deliberate)
The lock applies to **term-anchor** mutations (Swap, RemoveAndLift, ReplaceMatch, ReplaceReuse,
Generate — all route through `reservoir_sample`). Whole-step **structural** mutations (Skip, Repeat)
pick a step directly via `rand.choose(steps)` and are left unlocked in v1; they change trace length
(a different failure mode) and can be brought under the lock later if warranted.

---

## 2. Evaluation methodology

### 2.1 Hypotheses
- **H1 (executability):** step-lock lowers corpus broken-rate.
- **H2 (reachability):** step-lock improves **bad-switch reachability from legit seeds** (the open
  milestone) — hit-rate and time/execs-to-first.
- **H3 (no-harm):** throughput (exec/s) and edge coverage are not materially reduced.

### 2.2 Arms (isolate the one variable — same binary, toggled only by the flag)
| Arm | Config |
|-----|--------|
| **LOCK** | default (geometric stacking + scope weights + step-lock ON) |
| **BASE** | `--no-step-lock` (geometric + scope weights, lock OFF) |
| **AFL-ref** *(optional)* | historical heavy AFL stacking, no scope, no lock — the broken-corpus reference |

### 2.3 Design & controls
- **Seeds:** primary `OPCUA_SEEDS=legit` (the milestone); positive control `OPCUA_SEEDS=bug`
  (must still crash bad-switch quickly → proves build validity).
- **Bit:** no-bit primary; with-bit secondary.
- **PUT:** open62541 with the bad-switch OOB reachable, `-DNDEBUG` (no teardown-assert deaths) and
  the CLO/UAF resilience patches (campaign survives crashes).
- **Replication:** **N = 5 independent runs/arm** (distinct RNG). Fuzzing is high-variance; report
  **median + [min,max]**, never a single run.
- **Budget:** fixed wall-clock (24 h) and fixed cores/run, identical across arms; stagger to avoid
  CPU contention.

### 2.4 Metrics
**Primary**
- **Bad-switch reachability (legit):** hit-rate (k of N runs that crash within budget); **TTF**
  (time-to-first) and **ETF** (execs-to-first).
- **Corpus broken-rate:** `fuzz_campaigns/measure_hitchhiker.sh <dir> <bin> <sample>` — replays a
  campaign's own corpus with its own binary and classifies COMPLETE vs BROKEN; also the
  break-step-vs-switch-step histogram.
- **Exec-completion %:** `all_exec_success/all_exec` and term-eval break-rate from `log/stats.json`.

**Secondary / diagnostic**
- Edge coverage, exec/s (H3), corpus size & max trace size (caps holding), near-miss density
  (identity rejections, channel switches).

### 2.5 Analysis pipeline (harness already exists in `fuzz_campaigns/`)
- `measure_hitchhiker.sh` → broken-rate + histograms.
- `monitor_hitchhiker.sh` → periodic trend of the above as a campaign matures.
- stats.json parser → exec-completion %, term-err rate.
- objective-signature extractor → bad-switch counts + TTF/ETF from `RESULT.txt`.
- One summary table per arm (median/range of each primary metric); append to
  `fuzz_campaigns/DECISIVE_RESULT.md`.

### 2.6 Sanity gates before the big run
- Positive control (bug seed) crashes bad-switch < 15 min in **both** LOCK and BASE.
- LOCK's break-step histogram is **single-peaked at the locked step** (mechanism check, complements
  the unit test).

### 2.7 Decision criteria
- **Adopt step-lock as default** iff broken-rate drops materially (target ≈ 50% → < 25%) **AND**
  (legit bad-switch hit-rate improves **or** is unchanged) **AND** no > ~15% throughput/coverage
  regression (H3).
- If H1 holds but H2 does not: keep the lock (corpus-quality win) and pursue the next reachability
  lever (e.g. an identity-swap mutation).
- If throughput regresses badly: fall back to locking only the DY stage, or lock with probability p.
