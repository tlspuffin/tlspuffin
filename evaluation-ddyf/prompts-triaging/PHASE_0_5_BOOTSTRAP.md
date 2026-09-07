# Phase 0.5 — Empty-criteria triaging bootstrap

**Role:** Orchestrator (Sonnet-class is fine; this phase is cheap).
**Position:** Between Phase 0 (metadata production) and Phase 1 (global survey).
**Goal:** Produce a token-cheap, mechanical first cut of the bucket set BEFORE any metadata is read by an LLM.

---

## Why this phase exists

Phase 1 (global survey) is where the LLM starts reading `metadata_*.log` files in bulk. That is the most token-expensive phase of the campaign. If Phase 1 starts with no bucket scaffolding at all, the LLM has to:
- Discover the population of difference patterns from scratch.
- Re-derive the same clustering the triaging script already implements internally.
- Read many metadata files just to learn what the symptoms ARE.

The triaging script can do the clustering work mechanically and for free. When run with an **empty** (or near-empty) bucket set, it aggregates every observed difference pattern across the corpus and prints a frequency table. That table is the right starting point for Phase 1 — it converts "20,000 traces, no idea what's in them" into "~30 difference patterns, ranked by frequency."

The buckets created in this phase are **deliberately loose** — they encode "I see this difference pattern N times" not "I have validated the root cause." Phase 1 + Phase 2 + Phase 2.5 will tighten each one to meet `BUCKET_GRANULARITY.md` Criteria 1–4. The bootstrap pass exists to save tokens, not to produce ship-ready buckets.

---

## Protocol

### Step 1 — Save the current bucket set if any

If you are running this on a campaign that already has a bucket set in `evaluation-ddyf/sort_objectives_ossl_libre.py` (resumed campaign, or incremental re-run — see §"Incremental re-runs" below), back up the current script first:

```bash
cp evaluation-ddyf/sort_objectives_ossl_libre.py \
   ${CAMPAIGN}/phase_0_5_bootstrap/sort_objectives_ossl_libre.before_bootstrap.py
```

For a brand-new campaign, the script ships with only one housekeeping bucket (`no_errors`) — no backup needed.

### Step 2 — Create the bootstrap output directory

```bash
mkdir -p ${CAMPAIGN}/phase_0_5_bootstrap/
```

### Step 3 — Run the triaging script with empty buckets

If the script has any `[RFC]` / `[VULN]` / `[BENIGN]` buckets, **temporarily neuter them** (keep `no_errors` and `non_triaged`, comment out everything else with a `# BOOTSTRAP: temporarily disabled` marker). Then run:

```bash
python -m evaluation-ddyf.sort_objectives_ossl_libre \
    2>&1 | tee ${CAMPAIGN}/phase_0_5_bootstrap/empty_buckets_run.log
```

The script writes one `Trace : <file>` line per trace plus an aggregate "error string : count" table at the end. The aggregate table is the bucket-pattern seed.

### Step 4 — Extract the difference patterns

**Always filter out the per-trace lines** when reading the run log — they dominate the file (~20,000 lines for our reference campaign) and carry no clustering information:

```bash
grep -v "^Trace : " ${CAMPAIGN}/phase_0_5_bootstrap/empty_buckets_run.log \
    > ${CAMPAIGN}/phase_0_5_bootstrap/difference_summary.txt
wc -l ${CAMPAIGN}/phase_0_5_bootstrap/difference_summary.txt
```

The result should be ~30–60 lines for a typical campaign (one per distinct difference pattern), each formatted as:

```
<error-string-cluster> :  <count>
```

If the file is very small (< 10 lines): the script's `ExecutionStatus.errors` aggregation may be too coarse — fall back to clustering across `metadata_diff_*.log` files manually as described in Phase 1.

If the file is very large (> 200 lines): the corpus has very fine-grained errors — group lines by the leading common prefix before writing initial buckets.

### Step 5 — Write LOOSE initial bucket criteria

For each non-trivial cluster (>5 traces, roughly), write a **loose** bucket criterion in the triaging script. Loose means: it uses the simplest possible primitive (typically `StatusC(<PUT>, "<error fragment>", ...)` or `KnowledgeDiffC(...)`), and intentionally does NOT yet meet `BUCKET_GRANULARITY.md` Criteria 1–4.

Tag each new bucket with:

```python
# BOOTSTRAP: loose criterion from Phase 0.5; tighten in Phase 2.
# Pattern: <copy the difference_summary.txt line>
# Approx count: <N>
# PENDING REVIEW
"bootstrap_<short_descriptor>/": <BucketCondition>,
```

Aim for ~20-30 bootstrap buckets covering the top-frequency clusters. Don't bother with clusters of <5 traces — they are noise at this stage.

### Step 6 — Re-run the triaging script with the bootstrap buckets

```bash
python -m evaluation-ddyf.sort_objectives_ossl_libre \
    2>&1 | tee ${CAMPAIGN}/phase_0_5_bootstrap/with_bootstrap_buckets_run.log
```

This run **moves** traces into the new `bootstrap_*` subdirectories under `objective/`. Each bucket directory now contains the trace files + `metadata_*.log` files for that pattern, ready for Phase 1 inspection.

Check the residual catch-all:

```bash
ls objective/*.trace 2>/dev/null | wc -l
# count of traces NOT captured by any bootstrap bucket
```

If this number is large (>20% of total), iterate Step 5 — add more bootstrap buckets for the remaining patterns. Get the catch-all below ~5% before declaring Phase 0.5 done.

### Step 7 — Save the bootstrap state for later reference

```bash
cp evaluation-ddyf/sort_objectives_ossl_libre.py \
   ${CAMPAIGN}/phase_0_5_bootstrap/sort_objectives_ossl_libre.after_bootstrap.py

# Final diff-pattern catalog
grep -v "^Trace : " ${CAMPAIGN}/phase_0_5_bootstrap/with_bootstrap_buckets_run.log \
    > ${CAMPAIGN}/phase_0_5_bootstrap/residual_differences.txt
```

`residual_differences.txt` lists the difference patterns that are NOT captured by any bootstrap bucket. This is the input to Phase 1 (which buckets need tightening, what's still uncaptured).

---

## What you have at the end of Phase 0.5

| Artifact | Purpose |
|---|---|
| `${CAMPAIGN}/phase_0_5_bootstrap/empty_buckets_run.log` | Full script output with empty buckets (mostly per-trace lines, plus aggregate). Keep for audit trail. |
| `${CAMPAIGN}/phase_0_5_bootstrap/difference_summary.txt` | The grepped-clean aggregate. THIS is the bucket-pattern seed. |
| `${CAMPAIGN}/phase_0_5_bootstrap/sort_objectives_ossl_libre.before_bootstrap.py` | Backup of pre-bootstrap script (only for resumed campaigns). |
| `${CAMPAIGN}/phase_0_5_bootstrap/sort_objectives_ossl_libre.after_bootstrap.py` | Snapshot of script with loose bootstrap buckets. |
| `${CAMPAIGN}/phase_0_5_bootstrap/with_bootstrap_buckets_run.log` | Run log after bootstrap buckets are applied. |
| `${CAMPAIGN}/phase_0_5_bootstrap/residual_differences.txt` | Difference patterns NOT captured by any bootstrap bucket. Phase 1 / Phase 2 input. |
| `evaluation-ddyf/sort_objectives_ossl_libre.py` | Live script now contains the bootstrap buckets (tagged `# BOOTSTRAP: loose criterion`). |
| `objective/bootstrap_*/` | Trace files moved into per-bucket subdirectories with co-located metadata logs. |

Phase 1 now starts from a ~20-30 loose-bucket scaffold, not a blank slate. Most of the LLM's metadata reading in Phase 1 becomes per-bucket sampling (5-10 traces per bucket) rather than corpus-wide discovery.

---

## Important grep rule (applies everywhere downstream)

Any time a future phase reads `empty_buckets_run.log`, `with_bootstrap_buckets_run.log`, `residual_differences.txt`, or any other triaging-script output:

**Always filter the per-trace lines with `grep -v "^Trace : "`** (note the exact prefix: `^Trace ` then a literal space then `:` then space). The per-trace lines are one per trace in the corpus — for a 20k-trace campaign they dominate the file by ~200x and dilute the signal. The lines you care about are the aggregate "error pattern : count" lines and the `<file> checked <bucket> conditions` lines.

A robust filter that drops both per-trace lines and bucket-checked-confirmation lines is:

```bash
grep -vE "^(Trace |.*checked .* conditions)" <run_log>
```

When in doubt: `head -20 <file>` after the grep — if you see the same line pattern repeated more than 10 times, the grep needs to be tightened.

---

## Incremental re-runs (new objectives on an existing bucket set)

When new traces are added to an ongoing campaign — e.g., a fresh fuzzer batch produced additional objectives — re-run Phase 0.5 incrementally to find new difference patterns that the existing buckets don't capture:

1. Run Phase 0 (`./evaluation-ddyf/phase0_produce_metadata.sh`) on the new traces to produce their metadata logs.
2. Without neutering any buckets, run the triaging script again:
   ```bash
   python -m evaluation-ddyf.sort_objectives_ossl_libre \
       2>&1 | tee ${CAMPAIGN}/phase_0_5_bootstrap/incremental_$(date +%Y%m%d).log
   ```
3. Filter per-trace lines:
   ```bash
   grep -v "^Trace : " ${CAMPAIGN}/phase_0_5_bootstrap/incremental_$(date +%Y%m%d).log \
       > ${CAMPAIGN}/phase_0_5_bootstrap/incremental_$(date +%Y%m%d)_filtered.txt
   ```
4. Check the residual catch-all (`ls objective/*.trace`). Any trace not in a bucket is potentially a new pattern.
5. For each new high-frequency pattern: add a bootstrap bucket as in Step 5 above, then proceed to Phase 1 for tightening.

The incremental re-run preserves all prior bucket work — existing tightened buckets continue to capture their patterns; only the deltas need new attention. This is the supported workflow for ongoing campaigns where the trace corpus grows over time.

If the incremental re-run finds NO new patterns (residual catch-all is empty or contains only flaky traces), the existing bucket set is complete with respect to the new corpus. Record the date and the no-delta finding in `${CAMPAIGN}/phase_0_5_bootstrap/`.

---

## Anti-patterns

- **Reading metadata logs by hand in Phase 0.5.** This phase exists precisely to avoid that. The triaging script does the clustering for you, mechanically and for free. Save the LLM tokens for Phase 1.
- **Trying to write CRITERIA 1-4-compliant buckets in Phase 0.5.** The buckets here are loose by design. Tightening happens in Phase 2 with the metadata-grounded constraints.
- **Skipping Phase 0.5 on a fresh campaign because "I'll just read the metadata."** You'll spend 20x more tokens for the same scaffolding. Always run Phase 0.5 first.
- **Forgetting to filter `^Trace : `.** A 20k-trace campaign's run log has 20,000 of those lines. Read them once and your context is gone.
- **Naming the bootstrap buckets as if they were ship-ready.** Use the `bootstrap_<short_descriptor>` prefix so Phase 2 can rename them when it tightens the conditions. The renaming step also forces a re-read of the criteria, which catches sloppy bootstrap work.

---

## When this phase can be skipped

Phase 0.5 is mandatory for fresh campaigns. It can be skipped if:

- You are resuming a campaign that already has a tightened bucket set and you are not adding new objectives.
- The corpus is small (< 200 traces) and the LLM can do the whole survey + clustering itself in Phase 1 without exceeding its budget.

In all other cases, run Phase 0.5 first. The token savings compound through the rest of the campaign.
