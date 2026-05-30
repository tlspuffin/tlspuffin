# Pipeline Handoff Status: Phases 1 & 2 Completed

This document provides context for the LLM session taking over the downstream algorithmic phases (Phase 3: Triage, Phase 4: Signatures, and Phase 5: Build Tree) of the DDYF fingerprinting pipeline.

## 1. Current State & Infrastructure
The mechanical boilerplate scripts (`presets_gen.py`, `build_all.sh`, `discover.sh`, `run_all.sh`) have been fully implemented, validated, and executed. 

**Build Status:**
- The `presets.toml` configuration was successfully updated to include idempotent `[wolfsslXYZ-asan]` blocks for the full stable 5.x tag line (26 versions).
- `mk_vendor` and `cargo build --release --bin tlspuffin --features cputs,asan` were executed against all versions.
- **25 out of 26 versions compiled successfully** and are statically linked into the `tlspuffin` binary. 
- *Exception*: Version `5.2.1` failed to compile at the C (`mk_vendor`) level and is cleanly excluded from the pipeline. There were zero Rust API drift / harness compilation errors.

**Running Fuzzing Campaigns:**
- A robust parallel orchestrator (`launch_parallel_campaigns.sh`) is currently executing in a detached background shell.
- It is running 1-hour `differential-experiment` campaigns for all **24 adjacent pairs** among the 25 working versions.
- It cleanly allocates 5 dedicated cores per campaign (`--cores 0-4`, `--cores 5-9`, etc.) running in concurrent batches of 7 campaigns (using 35 cores max, safe for the 48-core system).
- *Completion ETA*: 4 hours.

## 2. Expected Results & Data Availability
When the background task completes, the following data will be available for your scripts to consume:

1. **Objective Traces**: 
   The campaigns will populate the `experiments/` directory. For each adjacent version pair (e.g., `5.0.0` vs `5.1.0`), there will be a tagged output directory containing raw candidate traces:
   `experiments/<timestamp-dir-with-fpp-5.0.0-5.1.0>/objective/*.trace`

2. **Validation Data**:
   A 15-second smoke test was conducted on the `{5.0.0, 5.1.0}` pair which successfully generated 43 objective traces. The pipeline is fully proven to generate the required `.trace` payload.

## 3. Your Task (Phases 3–5)
You are now cleared to build the algorithmic core:
* **`triage.py`**: Iterate over all discovered `.trace` files in the `experiments/` objectives directories. Re-execute them with `tlspuffin differential-execute --json` to enforce the TCP-observable/stealth constraint and filter out nondeterministic traces.
* **`signatures.py`**: Run surviving candidates across *all 25* built versions using `display-execute --json`. Canonicalize the JSON (stripping volatile session IDs/random bytes) to build deterministic structural signatures, cross-validate with diffs, and define indistinguishability clusters.
* **`build_tree.py`**: Run greedy information-gain splitting over the signatures to produce the optimal ID3 decision tree (`tree.json`, `tree.dot`) and the minimal separating probe set. 

You can bootstrap and test your scripts immediately using the existing sample objectives from the smoke test or earlier manual runs, then run them across the full dataset once the 4-hour batch completes.
