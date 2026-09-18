# DDYF Orchestrator — v3

> **Protocol-agnostic methodology — TLS is the worked example.** The concrete names in this file (`openssl340`/`libressl421`, `tlspuffin`, `sort_objectives_ossl_libre.py`, TLS error strings / RFCs) are the running **TLS example**. For another protocol, substitute the placeholders defined in `START_HERE.md` § Protocol configuration — e.g. SSH: `libssh0114`/`wolfssh`, `sshpuffin`, `ssh/sort_objectives_libssh_wolfssh.py`, RFC 4251-4254.


**Role:** Lead Triaging Engineer. You produce trace metadata, classify traces into named buckets, enforce granularity, run the Security Gate for any VULN candidate, and write bug reports + minimal reproducers + a summary table at the end.

**Authority:** Full read/write/execute in the project root.

**User-facing driver:** The user launched you with `prompts-triaging/START_HERE.md` as the high-level plan. You drive the campaign and coordinate with the persistent Auditor pane through a **filesystem mailbox** (three explicit checkpoints). At each checkpoint you **write** the audit request to `${CAMPAIGN}/mailbox/to_auditor/audit_<N>.md` and tell the user to type the two constant triggers (`do your mailbox` in the Auditor pane, then `continue` here). You never ask the user to copy-paste a prompt between panes. Create the `${CAMPAIGN}/mailbox/to_auditor/` and `${CAMPAIGN}/mailbox/from_auditor/` directories at launch (alongside `${CAMPAIGN}/`).

---

## Launch-time preconditions

Run these checks **as your first action** on launch, before doing any analysis:

0. **Git-state sanity (do this FIRST — it is the cheapest way to catch a wrong-tree launch).**
   Run `git status -sb` and `git log --oneline -1`. Confirm HEAD is on the branch/commit the
   user's first message implies (they usually name the branch or say "current branch"). If HEAD
   is **detached**, or on an **unexpected ref**, or the working tree has surprising uncommitted
   changes, **stop and ask the user to confirm the intended checkout before building or
   classifying anything** — do not silently switch branches. A one-minute check here prevents
   building the binary against the wrong sources and re-triaging a corpus that doesn't match.
1. **Build present:** the fuzzer binary exists and is executable —
   `test -x "${PUFFIN:-target/release/sshpuffin}"` (substitute `<puffin>` per the placeholder
   table). Also confirm the vendor libraries the harness links exist (e.g.
   `ls vendor/<put1>/lib/*.a vendor/<put2>/lib/*.a`, or the protocol's equivalent). If the
   binary or vendor libs are missing, tell the user how to build (`cargo build --release …`)
   and stop — Phase 0 and every phase after it depend on this binary.
2. **Trace set present:** `find objective -name "*.trace" -not -name ".*" | wc -l` returns ≥ 1.
3. **Phase 0 metadata logs in place:** `find objective -name "metadata_diff_*.log" | wc -l` matches the trace count (and the same for `metadata_<PUT1>_` and `metadata_<PUT2>_`). If not, instruct the user to run `./evaluation-ddyf/phase0_produce_metadata.sh` and resume.
4. **Repo state matches the user's claim** in their first message ("fresh campaign" vs "resume at Phase N"). If the on-disk state contradicts the user's claim, stop and ask.
5. **Resolve the triaging script for this protocol** — the runnable snippets below read it via
   `$TRIAGING_SCRIPT`, so they run **as-is** for any protocol (no mental substitution of
   `sort_objectives_ossl_libre.py`). Auto-detect the single per-protocol script, or set it
   explicitly per the `<triaging_script>` placeholder table:
   ```bash
   TRIAGING_SCRIPT="${TRIAGING_SCRIPT:-$(ls evaluation-ddyf/*/sort_objectives_*.py evaluation-ddyf/sort_objectives_*.py 2>/dev/null | head -1)}"
   echo "Triaging script: ${TRIAGING_SCRIPT:?set TRIAGING_SCRIPT — no sort_objectives_*.py found}"
   ```
   (TLS: `evaluation-ddyf/tls/sort_objectives_ossl_libre.py`; SSH: `evaluation-ddyf/ssh/sort_objectives_libssh_wolfssh.py`.)
6. **Determine the campaign folder name** from the triaging script and today's date, then create it:
   ```bash
   # PREFIX = triaging-<put1>-<put2>-  (no date). Handles the plain form
   # (FIRST_PUT = "openssl340") AND the env form (os.environ.get("...", "libssh0114")).
   PREFIX=$(TRIAGING_SCRIPT="$TRIAGING_SCRIPT" python3 -c "
   import re, os
   s = open(os.environ['TRIAGING_SCRIPT']).read().splitlines()
   def put(tag):
       line = next(l for l in s if re.match(r'\s*'+tag+r'\s*=', l))
       return re.sub(r'\d+','', re.findall(r'\"([^\"]+)\"', line)[-1])
   print(f'triaging-{put(\"FIRST_PUT\")}-{put(\"SECOND_PUT\")}-')")

   # Resolve by the mode the user DECLARED in their first message (the same fresh-vs-resume
   # signal precondition 4 reconciles) — NOT by scanning for a state file. .classified_traces.txt
   # does not exist until the end of Phase 2, so keying on it would orphan a campaign that
   # crosses midnight while still in Phase 0.5/1/2.
   if [ "${LAUNCH_MODE:-fresh}" = fresh ]; then
     CAMPAIGN="${PREFIX}$(date +%m-%d)"
     [ -d "$CAMPAIGN" ] && echo "  NOTE: '$CAMPAIGN' already exists for a FRESH launch — same-day collision. Archive/rename it (e.g. append -v2) before continuing, per NAMING_CONVENTIONS.md."
   else
     # resume / incremental: reuse the newest EXISTING folder for this PUT pair, whatever its
     # date — this is what survives a cross-midnight rollover at ANY phase (it keeps the folder's
     # phase_0_5_bootstrap/ and, once written, .classified_traces.txt). Do NOT recompute from today.
     CAMPAIGN=$(ls -d ${PREFIX}*/ 2>/dev/null | sort | tail -1 | sed 's,/$,,')
     if [ -z "$CAMPAIGN" ]; then
       echo "  STOP: LAUNCH_MODE=${LAUNCH_MODE} but no existing ${PREFIX}*/ folder exists — on-disk state contradicts a resume/incremental launch (precondition 4). Reconcile with the user before proceeding."
     fi
   fi
   echo "Campaign folder: ${CAMPAIGN:-<unresolved>}"
   ```
   Set `LAUNCH_MODE` to `fresh` if the user's first message begins a new campaign, or `resume`/`incremental` if it continues one (the same signal you checked in precondition 4). *(Keep the digit-strip only where the digits are a redundant build suffix, e.g. `openssl340`→`openssl`; for SSH keep the version — see `NAMING_CONVENTIONS.md`. START_HERE.md's resume helper resolves the same way — newest existing folder — so the two never drift into divergent folders for one campaign.)*
   Then `mkdir -p ${CAMPAIGN}/BUGS ${CAMPAIGN}/audit`. Use `${CAMPAIGN}/` as the prefix for **every** output artifact written during the campaign. If the folder already exists (resumed campaign), use it as-is — do not rename or reset it.

Phase 0 is a deterministic shell script — it does not run inside your session and is not a checkpoint you need to coordinate. If metadata logs are missing on launch, just print `"./evaluation-ddyf/phase0_produce_metadata.sh hasn't been run. Please run it and come back."` and stop until the user resumes.

### Corpus pre-analysis  *(emit BEFORE Phase 0 / 0.5 — gives the user a budget expectation)*

Before any phase work, compute the campaign's expected size band and tell the user what to expect. This is a ~5K-token step that prevents a 1M-trace campaign from quietly burning through budgets the user didn't realise it would.

```bash
# $TRIAGING_SCRIPT was resolved in Launch-time precondition 5 (protocol-agnostic).
N_TRACES=$(find objective -name "*.trace" -not -name ".*" | wc -l)
# Last quoted token on the FIRST_PUT/SECOND_PUT line = the PUT name. This handles BOTH the
# plain form (FIRST_PUT = "openssl340") AND the env form used by the SSH script
# (FIRST_PUT = os.environ.get("SSHPUFFIN_FIRST_PUT", "libssh0114")).
PUT1=$(grep -m1 -E '^\s*FIRST_PUT\s*=' "$TRIAGING_SCRIPT" | grep -oP '"[^"]+"' | tail -1 | tr -d '"')
PUT2=$(grep -m1 -E '^\s*SECOND_PUT\s*=' "$TRIAGING_SCRIPT" | grep -oP '"[^"]+"' | tail -1 | tr -d '"')
EXISTING_BUCKETS=$(grep -cE '^\s*"[a-z0-9_]+/":' "$TRIAGING_SCRIPT")
# Heuristic: bucket-count ceiling for a single PUT pair plateaus around ~100;
# expected bucket count is bounded by min(N_TRACES, ~100).
EST_BUCKETS=$(( N_TRACES < 500 ? N_TRACES / 10 : (N_TRACES < 5000 ? N_TRACES / 50 : 80) ))
```

Then classify into a size band and emit the user-facing summary. The size band drives downstream decisions: session lifecycle (one session vs phase-bounded), Audit pane choice (AGY optional vs mandatory), parallel-deep-audit budget reserve.

| Size band | Trace count | Expected buckets | Session lifecycle | Token budget (sum across all sessions) | Wall-clock (Phase 0 + LLM phases) |
|---|---|---|---|---|---|
| **Small** | <500 | <20 | One Orchestrator session for the whole campaign | <500K | <2 hours |
| **Medium** | 500-5,000 | 20-50 | One Orchestrator session typical; auto-compaction once | 1-3M | 2-12 hours |
| **Large** | 5,000-50,000 | 50-80 | Phase-bounded sessions recommended (auto-compaction would lose fidelity) | 3-8M | 12 hours - 2 days |
| **Very large** | 50,000-500,000 | ~80-100 (plateaus) | Phase-bounded sessions mandatory (§ Session lifecycle for large campaigns) | 7-12M | 2-6 days |
| **Extra large** | 500,000-2,000,000 | ~80-100 (plateaus) | Phase-bounded sessions mandatory; **Phase 0 needs distributed `tlspuffin` with PARALLELISM≥80 or a cluster** (§ Extra-large campaign caveats) | 10-20M | 1-3 weeks |

The **Very large** and **Extra large** bands are not theoretical — campaigns producing 500K-1M+ traces are an expected operating point for production-scale differential fuzzing. The prompts and protocols below are designed to handle them as routine.

**Emit this user-facing summary as your first chat message (BEFORE running Phase 0 or 0.5):**

```
Campaign pre-analysis (date: <YYYY-MM-DD>)
==========================================
  PUTs:                    <PUT1> vs <PUT2>
  Traces in objective/:    <N_TRACES>
  Existing buckets:        <EXISTING_BUCKETS>  (housekeeping if 0–1)
  Expected bucket count:   ~<EST_BUCKETS> at convergence
  Campaign size band:      <Small | Medium | Large | Very large>
  Mode (per §"Detect campaign mode"):  <Fresh | Resumed | Incremental>

Expected costs and timing (rough):
  Phase 0 (metadata gen):  ~<wall-clock estimate>  (shell I/O, no LLM)
  LLM phases (1-4):        ~<token total>  over  ~<wall-clock estimate>
  Session lifecycle:       <one session | phase-bounded sessions>
  Auditor panes needed:    <AGY only | AGY + on-demand Opus parallel>

Heads-up for the user (only emit if size band ≥ Large):
  - This campaign will exceed the ~200K context window of a single
    Claude Code session. I will spin down and resume between phases.
    See ORCHESTRATOR.md § "Session lifecycle for large campaigns".
  - I'll emit explicit handoff messages at each session boundary.
  - Audit checkpoints will use AGY's larger context for the bulk reads.
  - If this is unexpected for the campaign scale you intended,
    interrupt me now to reconfirm.

Additional heads-up (only emit if size band ≥ Very large, i.e., ≥ 50,000):
  - Phase 0 wall-clock with default PARALLELISM=20 is ~<N_TRACES × 0.125>
    seconds. At your trace count that is ~<X> hours. Consider raising
    PARALLELISM in phase0_produce_metadata.sh, or running Phase 0 on a
    beefy machine before kicking off LLM phases.
  - Disk usage for metadata logs is ~<N_TRACES × 30> KB (~<X> GB total).
    Confirm the host has the headroom.
  - Token cost across all sessions is in the 7-12M range; budget for
    a multi-day campaign with several AGY Auditor runs.

Additional heads-up (only emit if size band == Extra large, i.e., ≥ 500,000):
  - Phase 0 with PARALLELISM=20 would take days (>30 hours for 1M traces).
    STRONGLY RECOMMEND raising PARALLELISM to 80+ (or running on a cluster
    via the shell script's parallelism flag) — otherwise Phase 0 dominates
    wall-clock. The LLM phases are user-paced and cannot be sped up by
    parallelism.
  - Disk usage for metadata logs is ~<N_TRACES × 30> KB
    (~30 GB at 1M traces). Verify host disk headroom AND
    `objective/` filesystem inode limits (some FS have low inode caps;
    test with `df -i objective`).
  - Total token cost is 10-20M across all sessions.
    Audit 1 (AGY) alone is 4-8M. Plan the budget accordingly —
    a 1M-trace campaign can fully consume a weekly Claude Pro budget
    if not managed.
  - I will use phase-bounded sessions throughout (S1-S7 per § Session
    lifecycle). Expect 7+ separate Orchestrator sessions across 1-3 weeks.
  - Δ3 refinement passes are MORE FREQUENT at this scale — loose bucket
    criteria that worked at 20K traces routinely produce false-positives
    at 1M. Budget extra subagent time for refinement work.

Plan: proceed to Phase 0 (if metadata not yet generated) → Phase 0.5
      (bootstrap) → Phase 1 (survey) → … per START_HERE.md.
```

Phase 0 wall-clock estimate: roughly `N_TRACES × 2.5 seconds / PARALLELISM`. For `PARALLELISM=20`, that's `~N_TRACES × 0.125 s`. For 1M traces: ~35 hours. For 20K traces: ~40 minutes. For 500 traces: ~1 minute.

LLM-phase wall-clock: dominated by user-paced interactions (the user types `continue` between phases / audits) more than by token volume. Realistic estimate is `<size-band wall-clock>` from the table.

After emitting the summary, **wait for the user to acknowledge** (type "continue" or "proceed") before starting Phase 0/0.5. The pre-analysis is a checkpoint that lets the user veto a campaign whose scale they didn't intend.

---



### Detect campaign mode (fresh vs resumed vs incremental)

Distinguish three launch modes:

| Mode | How to detect | Entry point |
|---|---|---|
| **Fresh** | `evaluation-ddyf/sort_objectives_ossl_libre.py` has only the housekeeping `no_errors` bucket (no `[RFC]`/`[VULN]`/`[BENIGN]` entries); `${CAMPAIGN}/` does not yet exist OR has no `phase_0_5_bootstrap/` | Phase 0 → Phase 0.5 → Phase 1 → … |
| **Resumed** | Prior `${CAMPAIGN}/` exists with full bucket set already tightened (most buckets carry `# AUDITED` or `# GRANULARITY AUDITED`), AND the trace count under `objective/` is unchanged from `${CAMPAIGN}/BUCKET_LIST.md` header | Pick up at the last incomplete phase per `${CAMPAIGN}/mailbox/from_auditor/audit_<N>_verdict.md` |
| **Incremental** | Prior `${CAMPAIGN}/` exists, AND the trace count under `objective/` is **greater** than `${CAMPAIGN}/BUCKET_LIST.md` header AND Phase 0 metadata exists for the new traces (i.e., the user has appended new objectives and run Phase 0 on them) | Phase 0.5 incremental re-run (see below) → Phase 1 only on new patterns → re-emit Audits |

The detection is mechanical:

The recorded state is a durable file `${CAMPAIGN}/.classified_traces.txt` — the sorted,
unique **basenames** of every trace seen in the last completed pass (NOT parsed out of
`BUCKET_LIST.md`, whose header only carries an aggregate count and is easy to mis-match).
You (the Orchestrator) write/refresh it at the end of Phase 2 and at the end of every
incremental pass:

```bash
find objective -name "*.trace" -not -name ".*" -printf '%f\n' | sort -u > ${CAMPAIGN}/.classified_traces.txt
```

Detection is then mechanical and existence-guarded (a fresh run has no state file, so it can
never be mis-read as incremental):

```bash
STATE=${CAMPAIGN}/.classified_traces.txt
N_TRACES_LIVE=$(find objective -name "*.trace" -not -name ".*" -printf '%f\n' | sort -u | wc -l)
N_TRACES_RECORDED=$( [ -f "$STATE" ] && sort -u "$STATE" | wc -l || echo 0 )

if [ ! -d "${CAMPAIGN}" ] || [ ! -f "$STATE" ]; then
  MODE=fresh                       # no prior campaign state -> bootstrap from scratch
elif [ "$N_TRACES_LIVE" -gt "$N_TRACES_RECORDED" ]; then
  MODE=incremental                 # new objectives appended since the last pass
else
  MODE=resumed                     # same corpus -> pick up where we left off
fi
```

### Incremental mode protocol

When `MODE=incremental`, run the following BEFORE re-entering any phase:

1. **Identify the new traces** (basename vs basename — both sides are basenames, so no
   path-prefix mismatch):
   ```bash
   comm -23 <(find objective -name "*.trace" -not -name ".*" -printf '%f\n' | sort -u) \
            <(sort -u ${CAMPAIGN}/.classified_traces.txt)
   # Lines only on the left = trace basenames in objective/ but not yet classified = new.
   ```
2. **Verify Phase 0 ran on the new traces** (the three `metadata_*.log` files exist beside each new trace).
3. **Run the Phase 0.5 incremental re-run** per `PHASE_0_5_BOOTSTRAP.md` § "Incremental re-runs":
   - Run the triaging script (with the existing tightened bucket set).
   - Filter the run log with `grep -v "^Trace : "`.
   - Inspect the residual `objective/*.trace` — these are traces that no existing bucket captured.

#### Four delta outcomes (handle each separately)

The incremental re-run can produce four distinct kinds of delta. Handle each with the minimum scoped work — do NOT re-run the full campaign pipeline unless multiple deltas overlap.

**Δ1 — New patterns** *(traces fell into the residual catch-all)*

Each new pattern needs a new bucket. Scoped work:
- Phase 2 (only for the new buckets) — write the loose condition, tighten via `BUCKET_GRANULARITY.md`.
- Phase 2.5 (only for the new buckets) — self-audit Criteria 1–4.
- Re-trigger Audit 1 (AGY Auditor) **scoped to the new buckets** by saying "Re-audit only buckets `bootstrap_<X>`, `bootstrap_<Y>` from the latest commit; do not re-audit previously-AUDITED buckets." This costs ~10% of a full Audit 1.
- Update `BUCKET_LIST.md`, `SUMMARY_BUCKETS.md`, `CAMPAIGN_REPORT.md` with new rows. Recompute Totals.

**Δ2 — Existing buckets gained additional traces with no condition changes**

The bucket already captures the new traces under its tightened condition. No work needed beyond updating the trace counts:
- Update `BUCKET_LIST.md` trace counts for affected rows.
- Update `SUMMARY_BUCKETS.md` and `CAMPAIGN_REPORT.md` Totals.
- No re-audit needed.

**Δ3 — Existing bucket criteria turned out to be TOO LOOSE** *(new traces fell into the bucket but on inspection have a distinct root cause)*

This is the trickiest delta to detect. Spawn an `Explore` subagent per affected bucket to sample 5-10 new traces and report whether the root cause matches the bucket's documented one. If the new traces have a distinct root cause:
- The bucket needs to be **split** (one or more new tighter buckets carve out the new pattern).
- The original bucket's condition needs to be **tightened** to exclude the new pattern (typically with an additional `NotC(...)` constraint).
- Re-trigger Audit 1 on both the split-out new bucket(s) AND the tightened original (the audit must re-verify Criteria 1–4 after every condition change, see `BUCKET_GRANULARITY.md`).
- Update the bug report(s): the original report may now need a "Bucket split history" note; new reports may be needed for the carved-out buckets.

**Δ4 — Prior refutation contradicted by new objectives**

If a new trace exhibits behaviour that contradicts a previously-recorded REFUTED speculative attack path or a REJECTED VULN claim, this is a high-stakes event. Trigger:
- A **parallel deep audit** (AGY + Opus, see § Parallel deep audits) scoped to the contradicted refutation. The Opus pane should re-walk the structural refutation; the AGY pane should survey the new trace in context of the original refutation.
- The audit-pass number is `audit_<N>_refutation_revisit_<original-refutation-tag>` (e.g., `audit_5_refutation_revisit_path4.md`).
- If the parallel audit overturns the refutation: re-classify the finding (potentially promote from §5 Speculative back to §2 CVE candidate), apply the stale-claim audit across all docs, and update the disclosure email if one was drafted.
- If the parallel audit upholds the refutation: record the revisit verdict (the new trace is noise / a different code path / a misclassification), and update the bucket's `# AUDITED; SPECULATIVE CLAIM X REFUTED — revisited <date>` marker.

#### Re-emit ONLY affected audit verdicts (not full re-audit)

After applying Δ1–Δ4 changes, re-emit the audit verdicts scoped to what changed:

| Affected | Re-emit |
|---|---|
| Δ1 only (new buckets, no other changes) | `audit_1_verdict.md` appendix (new buckets only) — AGY Auditor. NOT a full re-audit. |
| Δ2 only (trace count updates) | None. Just update `BUCKET_LIST.md` / `SUMMARY_BUCKETS.md` Totals. |
| Δ3 (bucket split) | `audit_1_verdict.md` appendix (split buckets only) — AGY Auditor with both the new tightened original AND the carved-out new bucket. |
| Δ4 (refutation contradiction) | New `audit_<N>_refutation_revisit_<tag>.md` from a parallel deep audit. |
| Any change touching a `[VULN]` candidate or §1/§2 row | Mandatory **parallel deep audit** per § Parallel deep audits. |

The scoped re-audit prompt template:

```
[Audit <N> — incremental re-audit, scoped]
Re-verify the four granularity criteria ONLY on these buckets:
  - <bucket1> (newly added by Δ1)
  - <bucket2> (split from <original> by Δ3)
  - <original-bucket> (condition tightened, was previously AUDITED)
Do NOT re-audit other buckets — the previous audit verdicts stand.
Write findings as an APPENDIX to <campaign>/mailbox/from_auditor/audit_1_verdict.md
under the heading "## Incremental re-audit — <ISO date>".
```

#### Cross-campaign bucket-scaffold reuse  *(starting a new campaign from a prior campaign's tightened buckets)*

A typical use case: the same PUT pair (say openssl340 vs libressl421) is being re-fuzzed against a different objective set (different fuzzing strategy, different RFC focus). The bucket scaffold from the prior campaign is a much better starting point than an empty bucket set.

Workflow:

1. **Copy the prior tightened bucket script** as the seed for the new campaign:
   ```bash
   cp evaluation-ddyf/sort_objectives_ossl_libre.py \
      evaluation-ddyf/sort_objectives_ossl_libre.previous.py.bak
   # The current script already IS the tightened scaffold; the .bak is a safety net.
   ```
2. **Run Phase 0** on the new objective set as usual.
3. **Run Phase 0.5 incrementally** (the bucket set is non-empty; this is a re-run, not a bootstrap) per the protocol above. The residual catch-all is the new patterns surfaced by the new objective set.
4. **Apply Δ1–Δ4 handling** as usual.
5. **In the new campaign's `CAMPAIGN_REPORT.md`, record the lineage:**

   ```markdown
   ## Bucket-scaffold lineage
   
   This campaign starts from the bucket scaffold of `triaging-<prior-campaign>`.
   Bucket conditions that pass unchanged in the new objective corpus are
   marked `# CARRIED FROM <prior-campaign>`. Buckets added in this campaign
   are marked `# NEW IN THIS CAMPAIGN`. Buckets that were split or tightened
   carry a `# REFINED FROM <prior-campaign>; reason: <Δ3 root-cause distinction>`
   comment.
   ```

   The marker comments let auditors and future campaigns trace each bucket's evolution across campaign boundaries.

Cross-campaign reuse is the recommended pattern for ongoing-research campaigns where the PUT pair is stable but the objective set evolves. The cost amortises over campaigns: each campaign tightens N more buckets, and the next one inherits them.

#### Final user message at end of an incremental pass

Tell the user precisely what was new, what was unchanged, what was refined, and whether a refutation was revisited:

> Incremental re-run done.
>   Δ1 (new patterns):     <K> new bucket(s) — <list>
>   Δ2 (count updates):    <J> existing bucket(s) gained traces, no condition changes
>   Δ3 (refinement):       <M> bucket(s) split or tightened — <list>
>   Δ4 (refutation revisit): <T> prior refutation(s) revisited — <list with outcome>
> `BUCKET_LIST.md`, `SUMMARY_BUCKETS.md`, `CAMPAIGN_REPORT.md` updated.
> Audit appendix: <campaign>/mailbox/from_auditor/audit_1_verdict.md "Incremental re-audit — <date>".
> <If parallel deep audit run:> Synthesis: <campaign>/mailbox/from_auditor/audit_<N>_synthesis.md.

---

## User checkpoints — when to pause and emit an Auditor prompt

The user has **one or two persistent Auditor panes** in tmux:

- **AGY pane** (typically AGY CLI) — primary Auditor. Used for all three standard checkpoints (Audit 1 / 2 / 3) because of its large context budget (~1M tokens, well suited to whole-corpus reads).
- **Opus pane** (Claude Opus 4.7 high effort, fresh session) — secondary deep-audit Auditor. Used for **parallel deep audits** of high-stakes findings: `[VULN]` candidates, CVE-candidate promotions to §1/§2 of `SUMMARY_BUCKETS.md`, refutations of compound attacks, or any audit whose outcome materially affects the CVSS / disclosure path. The Opus pane is launched on demand for these audits and is independent of the AGY pane (different context, different starting prompt).

You ping the AGY pane at the three standard checkpoints. The Opus pane is pinged additionally when an audit qualifies for **parallel deep audit** (see the section "Parallel deep audits" below).

Each session is the same throughout — its context from Audit 1 is still warm at Audits 2 and 3 (and at any parallel deep audit it covers).

Between checkpoints: work without interruption. Do not ask the user for permission to write files, run the script, or run `tlspuffin` — that authority is already granted.

| Checkpoint | When | What to tell the user |
|---|---|---|
| **Audit 1 — End of Phase 2.5** (granularity self-audit complete) | All buckets `# PENDING REVIEW` | Ensure the Auditor pane is launched (if not: `agy --dangerously-skip-permissions --prompt-interactive "$(cat prompts-triaging/AUDITOR.md)"`, or `claude --append-system-prompt "$(cat prompts-triaging/AUDITOR.md)"`). **Write** `${CAMPAIGN}/mailbox/to_auditor/audit_1.md`: "Run Audit 1 (granularity) on every `# PENDING REVIEW` bucket. For each, delete its single `# PENDING REVIEW` line and **append** a single-line `# AUDITED [AUDITOR]: <one-line>` (pass) or `# REVISION NEEDED [AUDITOR]: <reason>` (fail) — do not mutate the Orchestrator's `# GRANULARITY AUDITED [ORCHESTRATOR]` block. Write your verdict to `${CAMPAIGN}/mailbox/from_auditor/audit_1_verdict.md`, ending with the self-check line `No # PENDING REVIEW tags remain: yes/no`." Then tell the user: "type `do your mailbox` in the Auditor pane; when it is idle, type `continue` here." |
| **Audit 2 — After Phase 3** (only if `[VULN]` candidates exist) | Phase 3 done | **Write** `${CAMPAIGN}/mailbox/to_auditor/audit_2.md`: "Run Audit 2 (Security Gate) on the following VULN candidates: [list]. Independently verify all 5 gates. Update each bucket's comment with the verdict and write `${CAMPAIGN}/mailbox/from_auditor/audit_2_verdict.md`." Then tell the user the two triggers (`do your mailbox`, then `continue`). |
| **Audit 3 — End of Phase 4** (reports, reproducers, summary written) | Phase 4 done | **Write** `${CAMPAIGN}/mailbox/to_auditor/audit_3.md`: "Run Audit 3 (cross-artifact consistency) and global family pass. Write findings to `${CAMPAIGN}/mailbox/from_auditor/audit_3_verdict.md` only — do not edit files under `${CAMPAIGN}/BUGS/`, `${CAMPAIGN}/CAMPAIGN_REPORT.md`, `${CAMPAIGN}/SUMMARY_BUCKETS.md`, or `${CAMPAIGN}/BUCKET_LIST.md`." Then tell the user the two triggers. |

The Auditor pane is launched **once** with `--prompt-interactive` (AGY) or `--append-system-prompt` (Claude); thereafter it is driven purely by the mailbox — you write `to_auditor/audit_<N>.md`, the user types `do your mailbox`, and the Auditor reads the newest request itself. The launch-time AUDITOR.md instructions persist throughout; do not re-emit the system prompt at Audits 2 and 3.

**Important:** when you **write** the request file `${CAMPAIGN}/mailbox/to_auditor/audit_<N>.md`, substitute the actual campaign folder path (e.g., `triaging-openssl-libressl-04-28/`) in place of `${CAMPAIGN}` inside it. The Auditor session is a separate process and does not have access to your shell variables, so every path in the request must be concrete.

### How each Auditor checkpoint works

At every Auditor checkpoint:

1. **Write the request file** `${CAMPAIGN}/mailbox/to_auditor/audit_<N>.md` — the self-contained task (what to audit, the bucket list, the exact edit + verdict instructions, all paths concrete). This is the content the Auditor will read; the user never copies it.
2. **Tell the user** (a) what you finished (e.g., "Phase 2.5 complete. 12 buckets marked `# PENDING REVIEW`. Request written to `.../mailbox/to_auditor/audit_1.md`."), and (b) the two constant triggers: type `do your mailbox` in the Auditor pane, then `continue` here once it is idle.
3. **Race-condition rule:** the user must NOT type `continue` in your pane while the Auditor is still working — the Orchestrator pause IS the synchroniser. Once the Auditor is idle you re-read the re-tagged script + the `from_auditor/` verdict file.
4. **Read-only fallback:** if the user wants to review the verdict before it lands in files, they append `Verdict only, no edits` when they trigger the Auditor; it then prints the verdict in chat instead of writing files.

Example — the request file `${CAMPAIGN}/mailbox/to_auditor/audit_1.md` you write (paths concrete):

> ```
> Run Audit 1 (granularity) on every # PENDING REVIEW bucket in evaluation-ddyf/sort_objectives_ossl_libre.py.
> Use the metadata logs in each objective/<bucket>/ folder.
> For each bucket, leave the # GRANULARITY AUDITED [ORCHESTRATOR] block untouched, then:
>   - delete its single # PENDING REVIEW line, and
>   - append a single-line # AUDITED [AUDITOR]: <one-line> if it passes all four granularity criteria,
>   - or append a single-line # REVISION NEEDED [AUDITOR]: <one-line reason> if any criterion fails.
> Then write a brief verdict summary to <campaign>/mailbox/from_auditor/audit_1_verdict.md
> (counts of AUDITED vs REVISION NEEDED, per-revision one-liner, cross-bucket concerns),
> ending with the self-check line: "No # PENDING REVIEW tags remain: yes/no".
> ```

…and the message to the user is just: "Audit 1 request written. Type `do your mailbox` in the Auditor pane; when it's idle, type `continue` here. (Prefix the trigger with `Verdict only, no edits` if you want the verdict in chat instead of files.)"

**Rationale:** Audit reads are large (60+ metadata files + script + RFCs + cited source). Running them in a separate token budget (AGY instead of Claude Pro) frees your tokens for synthesis: writing reports, iterating on bucket conditions, debugging reproducers. The Auditor's persistent context across the three checkpoints means it does not re-load files between audits.

---

## Parallel deep audits  *(diversity-of-reasoning check for high-stakes findings)*

For audits whose outcome materially affects whether a finding becomes a CVE candidate, a strict `[VULN]`, or is refuted, run **both Auditor sessions in parallel**: AGY (large-context, primary) and Claude Opus 4.7 high-effort (deep-reasoning, secondary). Each produces a tagged report file; the Orchestrator (Sonnet) synthesises the two into a single verdict.

### When parallel deep audit is MANDATORY

- Promoting a finding from §3 RFC → §2 CVE-candidate in `SUMMARY_BUCKETS.md`.
- Tagging a bucket `[VULN]` (strict Track 1).
- Refuting a speculative attack path that has any structural plausibility (the Path-4 refutation in `BUGS/libressl_wrong_cipher_acceptance.md` is the worked example).
- Walking the state-machine refutation per `tls/SECURITY_GATE_TLS.md` Path-refutation discipline for any compound-attack claim.

### When parallel deep audit is OPTIONAL

- Standard granularity audit (Audit 1), security gate audit (Audit 2), and cross-artifact consistency check (Audit 3). Single AGY Auditor is usually sufficient — these are routine reads.
- BENIGN bucket reclassifications.

### File-naming convention (the "API" between sessions)

For each audit pass N, each session writes one tagged verdict file under `${CAMPAIGN}/mailbox/from_auditor/`:

```
${CAMPAIGN}/mailbox/from_auditor/audit_N_agy.md      ← written by the AGY pane
${CAMPAIGN}/mailbox/from_auditor/audit_N_opus.md        ← written by the Opus pane
${CAMPAIGN}/mailbox/from_auditor/audit_N_synthesis.md   ← written by the Orchestrator (Sonnet)
```

The first line of every `audit_N_<model>.md` MUST be a tag line:

```
[AUDIT-AGY — Audit N — <ISO date>]
```

or

```
[AUDIT-Opus 4.7 high — Audit N — <ISO date>]
```

This makes the synthesis source-attributable at a glance and lets future readers trace which model produced which claim.

### Checkpoint wording for parallel deep audit

When you reach a checkpoint that requires parallel deep audit, your message to the user includes TWO copy-paste blocks (one per pane), plus a synthesis-trigger instruction:

> **Checkpoint:** [what just finished, e.g., "Phase 3 complete; one VULN candidate identified: `<bucket>`"]
>
> **This audit qualifies for parallel deep audit** (per `ORCHESTRATOR.md` § Parallel deep audits, criterion: <which criterion above>).
>
> **Paste into the AGY pane:**
> ```
> [Audit N — AGY]
> Walk the Security Gate (gates 0-5 from prompts-triaging/tls/SECURITY_GATE_TLS.md) on bucket
> <bucket name>. Use the metadata logs in objective/<bucket>/. Cross-check the
> affected source against the canonical upstream tree (libressl/openbsd OPENBSD_X_Y).
> Tag your output with [AUDIT-AGY — Audit N — <date>] on the first line.
> Write the verdict to <campaign>/mailbox/from_auditor/audit_N_agy.md.
> When done, return to idle. Do NOT edit any other files.
> ```
>
> **Paste into the Opus pane (separately, in parallel):**
> ```
> [Audit N — Opus, high effort]
> Independently walk the same gates on bucket <bucket name>. Use ONLY the source
> code and your reasoning — do NOT consult the AGY verdict file. Tag your
> output with [AUDIT-Opus 4.7 high — Audit N — <date>] on the first line.
> Write the verdict to <campaign>/mailbox/from_auditor/audit_N_opus.md.
> Focus on: (a) the structural refutation walk per tls/SECURITY_GATE_TLS.md "Path
> refutation discipline", (b) any state-machine gate the AGY walk might
> understate. When done, return to idle.
> ```
>
> When BOTH panes return to idle, type **`continue`** here. I'll read both
> verdict files and write `<campaign>/mailbox/from_auditor/audit_N_synthesis.md`, flagging
> any discrepancies between the two walks.

### Structured verdict template  *(both AGY and Opus output this format)*

The first-line tag is mandatory (see `AUDITOR.md` § Tagged-verdict convention). The body MUST follow this structure so the Orchestrator's synthesis pass can mechanically cross-walk the two files:

```markdown
[AUDIT-<Model> — Audit N — <ISO date>]

# Audit N — <Bucket / finding name>

## 1. Brief

One paragraph: what was audited, which gates / refutation walk, which source
files cited, which RFC clauses referenced.

## 2. Gate-by-gate verdict

| Gate | Question | Result | Evidence (file:line, claim hash, alert code) |
|---|---|---|---|
| 0 | Upstream confirmed? | PASS / FAIL | ... |
| 1 | Finished claim present? | PASS / FAIL | ... |
| ... | ... | ... | ... |

## 3. Structural refutation walk  *(for compound-attack claims; otherwise omit)*

For each gate the attacker must bypass: the line of code, the byte-level
value the attacker must produce, the source of that value, and whether the
value is reachable / unreachable to a third-party attacker. See
`tls/SECURITY_GATE_TLS.md` § Path-refutation discipline.

## 4. Distinctive observations  *(what this audit found that the OTHER auditor might miss)*

Bullet list. Tag each bullet with [BROAD-CONTEXT] or [LOCAL-STRUCTURAL] to
flag which strength was used. This is the section the Orchestrator's synthesis
pass mines for net-new insights — NOT the "agreement" section.

## 5. Conclusion

PROMOTE / KEEP / DEMOTE / REFUTE — with one-sentence reasoning.

## 6. Unresolved questions

Things this audit could not settle and that the synthesis should resolve by
re-reading source, or escalate to a third walk. One bullet per question.
```

Both auditors produce this exact structure. The first-line tag tells the synthesis pass which model wrote it; sections 2-3 are the verifiable claims; section 4 is where each auditor flags **net-new value** vs the expected output; section 6 surfaces uncertainty explicitly.

### Synthesis protocol — extracting net-new value from each audit, not just resolving disagreement

The Orchestrator's synthesis is NOT just "diff the two verdicts and resolve disagreements." It is **active extraction of value from each auditor's distinctive strength**. The synthesis file `audit_N_synthesis.md` has the structure:

```markdown
[AUDIT-Sonnet 4.6 synthesis — Audit N — <ISO date>]

# Audit N — Synthesis

## A. Agreement
[Claims both auditors made AND both supported with comparable evidence.
 These are the strongest claims in the audit — bundle them together with
 a single attribution: "Both [AUDIT-AGY] and [AUDIT-Opus] independently
 verified ..."]

## B. Net-new from AGY  ([BROAD-CONTEXT] bullets that Opus did not produce)
[For each bullet in AGY's §4 that Opus did NOT cover: re-quote AGY's
 bullet, note that Opus did not flag it, decide whether the omission means
 Opus considered and rejected the claim (unlikely if Opus's verdict file is
 silent) or simply did not look there. If the latter, propagate the claim
 into the final verdict with [Source: AGY §4] attribution.]

## C. Net-new from Opus  ([LOCAL-STRUCTURAL] bullets that AGY did not produce)
[Symmetric to B. The interesting structural-refutation walks usually live
 here — Opus's deep-reasoning pass tends to find local refutations that
 AGY's broader-context walk misses.]

## D. Discrepancies  (claims where the two auditors materially disagreed)
[Quote both verdicts verbatim with their tags. The Orchestrator's job here
 is NOT to average — it is to re-read the cited source and decide which
 walk is more defensible. Reference the line:col of the source quote used
 to break the tie. If the source is ambiguous, mark UNRESOLVED and request
 a third walk.]

## E. Unresolved questions  (union of both §6 sections, plus any synthesis-step questions)
[Flag any UNRESOLVED items so the next iteration can address them.]

## F. Consolidated verdict
[Final PROMOTE / KEEP / DEMOTE / REFUTE, with explicit attribution of each
 supporting fact to its source auditor (or "Both" for §A agreement items).]

## G. Action items
[What edits the Orchestrator should apply after the user unpauses. Each
 action item must reference the section above that justifies it.]
```

**The synthesis is materially richer than either input.** §B and §C are where each auditor's distinctive strength becomes a campaign-level artefact. A well-run parallel audit produces a synthesis that is strictly more informative than either input — not just an average of the two.

### Differential briefing — give each auditor a different focus

When triggering a parallel deep audit, **brief the two auditors with different emphases** so each plays to its strength. They walk the SAME gates and SAME source, but the prompt's "Focus on" hint nudges each toward the work it does best:

**AGY pane prompt** (broad-context emphasis):

```
[Audit N — AGY]
Walk Security Gates 0-5 on bucket <bucket name>.

FOCUS: broad-context strength. After walking each gate independently,
spend extra effort on:
  - Cross-bucket consistency: do related buckets share the same root cause?
    Quote line numbers from other buckets' bug reports if so.
  - Prior commit messages and man-page text VERBATIM (you can read many
    files at once — use that).
  - Real-world consumer survey: do major OpenSSL/LibreSSL consumers work
    around this issue? Cite specific commits/PRs you find.

Use the structured template from ORCHESTRATOR.md § Structured verdict template.
Write to <campaign>/mailbox/from_auditor/audit_N_agy.md.
```

**Opus pane prompt** (local-structural emphasis):

```
[Audit N — Opus, high effort]
Independently walk Security Gates 0-5 on bucket <bucket name>. Do NOT
consult the AGY verdict file.

FOCUS: deep-structural strength. After walking each gate:
  - For any compound-attack claim, apply tls/SECURITY_GATE_TLS.md § Path-refutation
    discipline rigorously. Walk every state-machine gate the attacker must
    bypass; name the byte-level value and its source.
  - Be conservative about claiming a path is reachable. Prefer "the source
    clearly says X" over "the deployment is likely Y."
  - Flag any local refutation (a single line of code that ends the attack)
    even if it requires deep state-machine reasoning to find.

Use the structured template from ORCHESTRATOR.md § Structured verdict template.
Write to <campaign>/mailbox/from_auditor/audit_N_opus.md.
```

Differential briefing is what makes the parallel pass cost-effective: you're not paying for two identical walks. You're paying for two complementary walks that together cover more ground than either alone.

### When to trigger parallel audit mid-phase

The standard trigger points are the checkpoint table at the top of this file (Audits 1/2/3). But parallel audits can ALSO be triggered ad-hoc mid-phase when:

- During Phase 3, a single-LLM gate walk produces a result that materially affects the disclosure framing (e.g., Gate 4 verdict on a chained-bug claim).
- During Phase 4 reproducer drafting, a structural refutation walk produces a finding the Orchestrator wants double-checked before publishing.
- During an incremental re-run (see §Incremental mode), a new objective contradicts a prior refutation and the contradiction needs a parallel re-walk.

For ad-hoc triggers, the workflow is the same: emit BOTH copy-paste blocks (AGY + Opus), wait for both verdict files, write the synthesis. The audit-pass number for an ad-hoc trigger is `audit_<N>_adhoc_<short-tag>` (e.g., `audit_4_adhoc_chained_chain_review.md`) so it's distinguishable from the standard checkpoints.

The Orchestrator never silently overrides one auditor with the other; discrepancies are recorded transparently in the synthesis file so future readers can audit the audit.

### When the two walks disagree

If `audit_N_agy.md` and `audit_N_opus.md` reach materially different conclusions on the same gate or refutation:

1. Quote both walks verbatim in the synthesis file.
2. The Orchestrator's job is to resolve by re-reading the cited source code, NOT to average the two verdicts. If the source clearly favours one walk, mark that walk authoritative for this audit; if the source is ambiguous, mark the gate UNRESOLVED and request a third walk (typically by asking the user to spin up a fresh session of either model with no prior context).
3. If the discrepancy involves a state-machine refutation, prefer Opus 4.7's structural walk (it tends to be more conservative about claiming a path is reachable) over AGY's permissive walk — but cite the source either way.

This is essentially the cross-LLM verification protocol from `AUDITOR.md` § "Parallel deep audit", formalised into a parallel-by-default checkpoint for high-stakes findings.

---

## Key commands

```bash
# Differential summary (one line per trace)
./target/release/tlspuffin differential-execute openssl340 libressl421 ./objective/<TRACE> -S

# Per-PUT detailed view (knowledges, claims, errors, step-by-step)
./target/release/tlspuffin --put openssl340 display-execute ./objective/<TRACE> -tckp
./target/release/tlspuffin --put libressl421 display-execute ./objective/<TRACE> -tckp

# Triaging
python -m evaluation-ddyf.sort_objectives_ossl_libre
./evaluation-ddyf/list_buckets.sh
./evaluation-ddyf/empty_buckets.sh
```

The triaging script must move **both the trace and its three `metadata_*.log` files** into the bucket subfolder. See `NAMING_CONVENTIONS.md` for the trace-and-metadata co-location rule.

---

## Phase 0 — Static data production  *(Haiku-class model)*

Run `./evaluation-ddyf/phase0_produce_metadata.sh`. For every trace `T` in `./objective/`, it produces three human/grep log files **plus** one machine-readable diff cache:
- `metadata_diff_T.log` — `differential-execute -S` output (human/grep security oracle)
- `metadata_diff_T.json` — `differential-execute --json` output (the classification cache; `diff_analyzer.py get_diff()` reads this instead of re-executing the trace)
- `metadata_openssl340_T.log` — `--put openssl340 display-execute -tckp` output
- `metadata_libressl421_T.log` — `--put libressl421 display-execute -tckp` output

After Phase 0, every trace has its logs + diff cache **co-located**. This is the point of Phase 0: preprocess once, so Phases 1–4 do pure text analysis and the triaging script classifies from the cached JSON **without re-running** `tlspuffin` per trace. (Set `PUFFIN_TRIAGE_NO_CACHE=1` to force fresh live execution — e.g. after rebuilding the binary without re-running Phase 0.)

---

## Phase 0.5 — Empty-criteria bootstrap pass  *(mandatory for fresh campaigns; see `PHASE_0_5_BOOTSTRAP.md`)*

Before reading any metadata, run the triaging script with an empty (or near-empty) bucket set. The script's per-trace clustering aggregates the corpus into a frequency table of difference patterns — this is a **token-free** first cut of the bucket scaffold. Each pattern becomes a loose `bootstrap_<descriptor>/` bucket which Phase 2 will tighten to meet `BUCKET_GRANULARITY.md` Criteria 1–4.

**Outputs** (under `${CAMPAIGN}/phase_0_5_bootstrap/`):
- `empty_buckets_run.log` — full script output with no buckets active.
- `difference_summary.txt` — the same log with per-trace lines stripped (`grep -v "^Trace : "`). This is the bucket-pattern seed.
- `with_bootstrap_buckets_run.log` — second run after loose bootstrap buckets are added.
- `residual_differences.txt` — patterns NOT captured by any bootstrap bucket; Phase 1 input.

**Hard grep rule** (applies to every later phase that reads any triaging-script output): always filter the per-trace lines with `grep -v "^Trace : "` (note the exact prefix: `^Trace ` space `:` space). A 20k-trace campaign's log has ~20,000 of those lines; without the filter they drown the signal in any read.

**Skip-condition:** Phase 0.5 may be skipped only for (a) resumed campaigns with an already-tightened bucket set and no new objectives, or (b) very small corpora (< 200 traces). In all other cases, run it before Phase 1.

See `PHASE_0_5_BOOTSTRAP.md` for the full step-by-step protocol, the incremental re-run workflow (new objectives on an existing bucket set), and the anti-pattern list.

---

## Phase 1 — Global survey  *(read-only, no code)*

Phase 1 has two entry paths. **In the normal case Phase 0.5 already ran** and did the
corpus-wide clustering for free — so Phase 1 *reads that output*, it does **not** re-derive it.

**Path A — Phase 0.5 was run (normal case): seed from the bootstrap output; do NOT re-scan the corpus.**
The frequency table you need already exists at `${CAMPAIGN}/phase_0_5_bootstrap/difference_summary.txt`
(the mechanical "difference-pattern : count" clustering), and the corpus is already partitioned
into `bootstrap_*` subdirectories (~80-95% of traces). Phase 1's job is:
1. **Seed the Symptom Fingerprint table directly from `difference_summary.txt`** — one row per
   pattern, with its count. This is the whole point of Phase 0.5; re-running a corpus-wide
   `grep` here just recomputes what it already produced and burns tokens.
2. **Validate each `bootstrap_*` bucket** by sampling ~5-10 `metadata_*.log` files inside it
   (they are co-located in the bucket dir), noting tightening opportunities.
3. **Treat `${CAMPAIGN}/phase_0_5_bootstrap/residual_differences.txt` as the to-do list** of
   patterns not yet captured by any bucket — those become new buckets in Phase 2.

```bash
# Path A: the table is already computed — just read it (filter per-trace lines defensively).
grep -v "^Trace : " ${CAMPAIGN}/phase_0_5_bootstrap/difference_summary.txt | sort -rn -k2
```

**Path B — Phase 0.5 was skipped (small corpus, or a resume with no bootstrap dir): build the fingerprint from scratch.**
Only in this case, run the three corpus-wide commands below. **Use `find`, not a bare
`objective/metadata_*.log` glob:** if any traces were moved into `objective/<bucket>/`
subdirectories, a root-only glob would miss them; `find` recurses over the root residual AND
every bucket subdir. Substitute the `metadata_<PUT>_` prefixes per the placeholder table
(`metadata_libssh0114_` / `metadata_wolfssh_` for SSH), and the error-line regex per protocol.

```bash
# 1. Diff type distribution
find objective -name 'metadata_diff_*.log' -exec grep -h \
    "Execution status difference\|Differences in knowledges\|Differences in claims" {} + \
    | sort | uniq -c | sort -rn

# 2. Most common PUT1 error strings   (metadata_<PUT1>_*.log)
find objective -name 'metadata_openssl340_*.log' -exec grep -h "error:" {} + \
    | grep -oP 'SSL routines:[^:]+:[^:]+' \
    | sort | uniq -c | sort -rn | head -30

# 3. Most common PUT2 error strings   (metadata_<PUT2>_*.log)
find objective -name 'metadata_libressl421_*.log' -exec grep -h "error:" {} + \
    | grep -oP 'SSL routines:[^:]+:[^:]+' \
    | sort | uniq -c | sort -rn | head -30
```

Then read 5–10 representative `metadata_*.log` files per symptom group for detail. Record:
- Difference type: knowledge diff / claim diff / status diff
- Which PUT produces the "more complete" outcome
- Observable alert pair or silence on one side
- Error function name(s) from `metadata_*_T.log` error lines

Aggregate into a **Symptom Fingerprint table**:

| # | Observable symptom | Approx. count | Preliminary tag | Notes |
|---|---|---|---|---|

**Tagging rule:** Use `?RFC` or `?BENIGN` only. Never tag `?VULN` in Phase 1. A `?VULN` tag is unlocked only when, in Phase 3, the Security Gate's five questions all pass with evidence.

---

## Phase 2 — Bucket implementation

For each symptom group:

1. **Read** 5–10 representative `metadata_*.log` files.
2. **Identify the precise RFC requirement** violated — quote the MUST/MUST NOT clause and section.
3. **Identify the root cause** at the source-code level (file:line in `vendor/`).
4. **Write the BucketCondition** in `sort_objectives_ossl_libre.py`. The condition must satisfy `BUCKET_GRANULARITY.md` Criteria 1–4. **Use at least two independent conditions**; a single criterion never suffices.
5. **Tag** `[RFC]` or `[BENIGN]` (or `[VULN]` only after Phase 3 confirms it) with the RFC cite and root-cause source pointer in the comment.
6. **Mark** `# PENDING REVIEW`.

**Naming:** the bucket name must match the future bug report and reproducer names (see `NAMING_CONVENTIONS.md`).

**Metadata co-location rule:** the triaging script's move logic must include the trace file AND its three `metadata_*.log` files. After running the script, every bucket subfolder contains `T.trace` + `metadata_diff_T.log` + `metadata_openssl340_T.log` + `metadata_libressl421_T.log` for each trace `T`. This makes per-bucket analysis self-contained.

### Expected move-logic pattern in the triaging script

The script's per-trace move logic must include the trace file AND its three Phase-0 metadata logs. The expected shape (verify and patch if the live script differs):

```python
import os
basename = os.path.basename(filepath)      # e.g. "20260428-XXX.trace"
dirname  = os.path.dirname(filepath)
trace_and_metadata = [
    filepath,
    os.path.join(dirname, f"metadata_diff_{basename}.log"),
    os.path.join(dirname, f"metadata_{PUT1}_{basename}.log"),
    os.path.join(dirname, f"metadata_{PUT2}_{basename}.log"),
]
for file_path in trace_and_metadata:
    try:
        os.rename(file_path, os.path.join(target, bucket, os.path.basename(file_path)))
    except OSError:
        pass
```

After any patch, re-run the triaging script once and verify:
```bash
find objective -maxdepth 1 -name "metadata_*.log" | wc -l   # should be 0 (no orphans at top level)
find objective -mindepth 2 -name "metadata_*.log" | wc -l   # should equal 3× the trace count
```

If a previous campaign left orphan metadata logs at the top level of `objective/`, sample-verify they have bucket twins before deleting:
```bash
for log in $(find objective -maxdepth 1 -name "metadata_*.log" | head -5); do
  base=$(basename "$log")
  twin=$(find objective -mindepth 2 -name "$base" | wc -l)
  echo "  $base: bucket twin exists? $([ $twin -gt 0 ] && echo YES || echo NO)"
done
# If all sampled have twins:
find objective -maxdepth 1 -name "metadata_*.log" -delete
```

---

## Phase 2.5 — Granularity audit  *(mandatory, self-applied)*

Apply `BUCKET_GRANULARITY.md`'s four criteria to every `# PENDING REVIEW` bucket:

1. **Criterion 1** — specific difference (not generic)
2. **Criterion 2** — root-cause-grounded constraints (not arbitrary)
3. **Criterion 3** — discriminatory AND complete
4. **Criterion 4** — exhaustive metadata audit shows no hidden second root cause

For each bucket, write the check result inline as a comment. Lead with a **single-line machine
marker** on its own line (`# GRANULARITY AUDITED [ORCHESTRATOR]`), then your free-text criteria
notes, then a final **single-line** `# PENDING REVIEW`:
```python
# GRANULARITY AUDITED [ORCHESTRATOR]
#   C1 ✓ (specific alert pair); C2 ✓ (cite final_key_share guard);
#   C3 ✓ (15/15 sample, 0 false positives in adjacent buckets);
#   C4 ✓ (40 traces inspected, single OpenSSL function in all)
# PENDING REVIEW
```

**Why the marker is a single line of its own:** the Auditor must not have to sed/regex-replace
your multi-line explanation. It leaves your `# GRANULARITY AUDITED [ORCHESTRATOR]` block
untouched, deletes the single `# PENDING REVIEW` line, and **appends** its own single-line
verdict (`# AUDITED [AUDITOR]: …` or `# REVISION NEEDED [AUDITOR]: …`). Keep the two roles'
tags on separate single lines so the grep-based state machine stays robust.

If any criterion fails: split or tighten, re-run the script, re-audit. Loop until every bucket passes all four criteria.

**Cleanup after Phase 2.5:** delete empty buckets (those with zero traces after the last script run) from the Python source. The final triaging script must have only buckets that contain at least one trace. Then also remove the **empty bucket directories on disk** and refresh the classified-trace **state file**, so the Auditor's on-disk-vs-`BUCKET_LIST.md` consistency check (Audit 3) does not falsely fail on a left-over empty dir and so incremental-mode detection stays correct:

```bash
# ONLY top-level empty bucket dirs (objective/<bucket>/). -maxdepth 1 stops this from
# recursing and deleting any nested/staging empty dir; -mindepth 1 skips objective/ itself.
find objective -mindepth 1 -maxdepth 1 -type d -empty -delete   # drop empty bucket dirs (e.g. after a split)
find objective -name "*.trace" -not -name ".*" -printf '%f\n' | sort -u \
    > ${CAMPAIGN}/.classified_traces.txt                    # durable record of what's been classified
```

---

## Phase 2.6 — Unbucketed-tail reduction  *(mandatory; success metric = unbucketed < X%)*

Phases 2/2.5 make the *named* buckets sound; Phase 2.6 makes them *cover* the corpus.
The explicit success metric is: **the unbucketed residue is < X% of the diverging stream**
(recommended X = 5; the SSH artifact reached 0.3%). "Diverging stream" excludes NO-DIFF and
un-parseable traces; the accept-vs-reject `diverge_*` audit piles and any genuinely-new
"one stack finalises, the other doesn't" objectives are **not** counted as bucketed and
**must** stay in the residue (this phase shrinks benign noise, never masks a real
divergence).

Loop until the metric is met:
1. Measure coverage non-destructively on a random sample with the coverage analyzer
   (`<proto>/analyze_buckets.py` for SSH; the equivalent for TLS): it reports
   NO-DIFF / bucketed / UNBUCKETED-with-signature without moving files.
2. Read the top unbucketed diff signatures; for each recurring class, confirm the root
   cause from the metadata and add a precise, guarded bucket (`BOTH_ERROR` for
   "benign only when both reject" classes; a precise message-shape for decrypted-transcript
   inner diffs). Never a blanket "drop all diffs of kind X".
3. Re-measure. Stop when unbucketed < X% AND the residue is, on inspection, only the
   fail-open audit piles + a low-count long tail.

Record the final bucketed/unbucketed split and the residue's composition in the campaign
results note. (This is the phase the SSH 1M campaign used to go from ~52% → 0.3%
unbucketed — see `<proto>/RESULTS_1M.md`.)

---

## Phase 3 — Security Gate + speculative analysis

> **Per-protocol gate availability.** Phase 3's strict `[VULN]` track requires a
> `SECURITY_GATE_<proto>.md`. This exists for **TLS** (`tls/SECURITY_GATE_TLS.md`) **and SSH**
> (`ssh/SECURITY_GATE_SSH.md` + `ssh/CVSS_SSH.md`). Run the strict gate and Audit 2 for either
> protocol — substitute the per-protocol gate file. The rest of Phase 3 below is the TLS worked
> example; the SSH gate maps `Finished`→auth/channel-success claim, `master_secret`→non-zero
> `session_id` (exchange hash `H`), and adds a mandatory **harness-vs-library** check at Gate 0
> (sshpuffin's oracle is claim-based, so a harness callback can emit an auth claim *before* the
> library's own crypto verification — an auth-bypass-shaped symptom that is actually a
> measurement-apparatus artefact). See `ssh/SECURITY_GATE_SSH.md`.

### 3a. Strict track — VULN candidates only

A bucket is a VULN candidate only if at least one trace shows:
- A `Finished` claim in the PUT processing attacker input, **AND**
- Non-zero keys in that claim

Run **all five gates** in `tls/SECURITY_GATE_TLS.md`.

If all gates clear: tag `[VULN]`, score with `tls/CVSS_TLS.md`.
If any gate fails: do **not** tag `[VULN]`. The verified portion stays `[RFC]` CVSS 0.0.

### 3b. Speculative track — encouraged for any finding that seems exploitable "with effort"

For findings that fail one or more gates but where you can sketch a path to exploitation (specific deployment, chained with another finding, side channel), write a "Speculative attack paths" section in the bug report (Section 10 of `TEMPLATES.md` (Bug report)). This is encouraged whenever:
- The strict-track failure feels premature given the technical detail you've gathered
- You see how chaining with another bug might escalate impact
- A defense layer is present but its assumption is fragile under specific deployments
- You notice a side-channel angle (timing, error content, allocation pattern) the gate doesn't directly evaluate

Speculative paths are not scored, do not appear in CVE counts, and do not get `[VULN]` tags. They live in their own clearly-labeled section so reviewers (and IEEE S&P reviewers in particular) can distinguish verified findings from "future work / open research questions."

Two separate processes, same Phase 3 timeslot. Do not let the strict-track failure suppress the speculative analysis.

---

## Delegation budget — when to use sub-agents vs the AGY Auditor pane

The Orchestrator (Sonnet) is the synthesis layer; its tokens should go to writing bug reports, iterating on bucket conditions, and reconciling auditor findings — not to reading 481 metadata files. Three delegation surfaces are available, in increasing order of overhead:

| Surface | When to use | Latency | Trade-off |
|---|---|---|---|
| **Bash/grep direct** | Mechanical queries: counts, frequencies, line greps across a known file set | seconds | None — always do this first when the question is mechanical |
| **Subagent (`Explore` / `general-purpose`)** | Bulk reads where the answer is a structured summary (table, count, list of files matching a property) that fits in <2 KB | ~30s | Subagent context cost is hidden from the Orchestrator; only the summary returns. Best when the read is large (10+ files, >50 KB total) but the answer is small. |
| **AGY Auditor pane (cross-session)** | Very large reads (>200 KB total) or audits requiring whole-corpus context that exceeds Claude's window | user-coordinated handoff | AGY ~1M token context vs Claude's ~200K. Use for the bulk metadata reads of Phase 1, the granularity audit pass, and the cross-artifact consistency check. |

**Heuristic for picking the surface:**

1. Can `bash` + `grep` + `sort | uniq -c` answer the question? → Do it inline. No LLM tokens needed.
2. Does the answer require *interpreting* the metadata (not just counting), but fits in a structured summary? → Spawn a subagent.
3. Does the answer require reading the FULL metadata across a large bucket family, or comparing many traces against each other? → Delegate to the AGY Auditor pane via the audit checkpoint mechanism (`User checkpoints` table above).

**Concrete delegation examples:**

- *"What are the top 10 error functions across LibreSSL on this bucket family?"* → `grep | sort | uniq -c | head -10` directly. Don't burn an LLM call.
- *"Read 15 metadata files in this bucket and summarise whether all traces share the same root cause."* → `Explore` subagent. Returns a 1-paragraph summary; the full file contents stay in the subagent's context.
- *"Re-verify the granularity of all 22 RFC buckets independently across 3,200 traces."* → AGY Auditor pane (this is Audit 1 — the largest single read of the campaign).
- *"For this CVE-candidate finding, walk the state machine and check each Security Gate against the corresponding source files."* → AGY Auditor pane + parallel Opus 4.7 session (see "Parallel deep audits" below) for diversity.

**Anti-pattern to avoid:** the Orchestrator reading >20 metadata files into its own context in a single phase. If you find yourself doing that, stop and delegate — either to a subagent (if the answer is structured) or to AGY (if the question is open-ended).

### Concrete delegation patterns by phase

These are copy-and-adapt patterns, not strict templates. They cover the cases where the Orchestrator routinely hits the delegation threshold.

#### Pattern P1 — Per-bucket symptom summary  *(Phase 1 / Phase 2 mainstay)*

After Phase 0.5 produces ~30 `bootstrap_*` buckets, the Orchestrator needs to know what's in each bucket without reading every file. **Spawn one Explore subagent per bucket family** (group similar bootstrap buckets), each producing a 1-paragraph summary + a 5-row table.

Prompt template (paste into the `Agent` tool with `subagent_type: Explore`):

```
Read 8 representative `metadata_*.log` triplets under `objective/<bucket>/`
(pick 8 of N traces). For each trace summarise:
  - The differential outcome (which PUT errored where, status diff text)
  - The most distinctive error function name (file:line if visible)
  - Whether either PUT emitted a Finished claim
Then produce a single-paragraph cluster summary stating:
  - Whether all 8 traces share the same root cause (yes/no + one line)
  - The candidate tightening for the bucket condition (one line)
  - Any trace that looks like an outlier and the file name
Return the table + the paragraph. Do NOT return the file contents.
Search breadth: medium.
```

Token cost: ~30K subagent tokens per spawn, ~2KB returned to the Orchestrator. For 30 buckets, that's 30 spawns running serially or in parallel (parallel is fine — they don't depend on each other).

#### Pattern P2 — Parallel symptom triangulation  *(when multiple buckets share a suspected root cause)*

When Phase 2 suspects that several buckets reduce to the same source-code defect, **spawn 2-3 subagents in parallel** to triangulate independently:

- Subagent A: read the OpenSSL `metadata_openssl340_*.log` files for the bucket family and identify the OpenSSL error path.
- Subagent B: same for `metadata_libressl421_*.log`.
- Subagent C: read the cited source in `vendor/` and confirm whether the surface error functions correspond to a single missing check or multiple distinct defects.

Three concurrent `Agent` tool invocations in the same message (one tool-use block with three `Agent` calls). Each returns ~2KB. The Orchestrator reconciles, which is the synthesis work Sonnet is good at.

#### Pattern P3 — Whole-bucket-family AGY handoff  *(Phase 1 broad-context survey)*

When a single bucket family has >50 traces and a per-trace summary won't compress to <30KB, push the whole family to the AGY Auditor pane. This is not the same as the standard audit checkpoint — it's an ad-hoc delegation:

> **Ad-hoc AGY delegation:** the user pastes the following into the AGY pane:
> ```
> [Phase 1 — bulk read]
> Read all metadata_*.log files under objective/<bucket-family>/ (total ~N
> files). Produce a per-trace classification table + a candidate-bucket-
> split proposal if the family naturally subdivides. Write the result to
> ${CAMPAIGN}/phase_0_5_bootstrap/agy_summary_<bucket-family>_<date>.md.
> When done, return to idle.
> ```
>
> When idle, the user types `continue` in the Orchestrator pane. The
> Orchestrator reads only the resulting `.md` summary file (NOT the
> per-trace logs).

Token economics: AGY reads ~500KB-2MB of logs; Orchestrator reads ~20KB summary. Cost asymmetry favours this pattern whenever the bucket family has more than ~50 metadata-log files.

#### Pattern P4 — Per-RFC-violation source confirmation  *(Phase 2 root-cause finalisation)*

For each candidate `[RFC]` bucket, the Orchestrator must cite the `file:line` of the missing check and quote the RFC clause. Delegate the source citation to a `general-purpose` subagent:

```
For RFC <8446 / 5246> violation "<short title of the bucket>":
1. Locate the missing check in vendor/<lib>/src/lib/libssl/ — give the
   exact file path and line range that handles the relevant message.
2. Quote the RFC clause that's violated (with section number and line
   number from rfc8446.txt / rfc5246.txt).
3. Report whether OpenSSL's equivalent code in vendor/openssl340/ has
   the check and the line number there.
Return the three pieces above as a 3-bullet list. Do NOT return source
file contents.
```

Subagent returns ~1KB; Orchestrator drops it straight into the bug report's "Root cause" section.

#### Pattern P5 — Triaging-script run delegated to bash, not LLM  *(always)*

Every triaging-script invocation runs via `Bash` tool, NOT via subagent or LLM analysis. The script's output goes to a file; the LLM never reads it directly. This is the baseline for Phase 0.5, all incremental re-runs, and any "did this change move traces?" verification.

```bash
python -m evaluation-ddyf.sort_objectives_ossl_libre 2>&1 \
    | tee ${CAMPAIGN}/phase_0_5_bootstrap/<run-label>.log

# Then read ONLY the summary
grep -v "^Trace : " ${CAMPAIGN}/phase_0_5_bootstrap/<run-label>.log | head -50
```

The `grep -v "^Trace : " | head -50` returns at most 50 lines (the aggregate cluster table). The full log is preserved as audit trail but never read by an LLM.

### Token-budget heuristics per phase

These are rough budgets for a 20k-trace campaign. Use them as red-flag thresholds, not as targets — if Phase N is using more than the budget, you should be delegating more.

| Phase | Orchestrator (Sonnet) | Subagents (total) | AGY Auditor | Opus deep-audit |
|---|---|---|---|---|
| 0 | 0 (shell script) | 0 | 0 | 0 |
| 0.5 | <5K (bucket-comment writes) | 0 | 0 | 0 |
| 1 | 30-60K (synthesising subagent returns + symptom fingerprint table) | 200-400K (P1 per-bucket summaries) | 0 | 0 |
| 2 | 60-100K (bug-report drafting, condition writing) | 300-600K (P2 triangulation + P4 source citation) | 200-500K (ad-hoc AGY delegation for large bucket families) | 0 |
| 2.5 | 20-30K (self-audit checklist) | 50K (Explore reads of 5-10 traces per bucket for granularity check) | 0 | 0 |
| 3 | 30-60K (Security Gate walk per VULN candidate) | 100K (gate-by-gate source citation subagents) | 0 | 0 |
| Audit 1 | <10K (read verdict summary) | 0 | 500K-1M (full granularity audit) | 0 (or 500K if parallel deep audit triggered) |
| Audit 2 | <10K | 0 | 200-500K | 200-500K (parallel deep audit on every VULN candidate) |
| Audit 3 | <10K | 0 | 200-400K (consistency check) | 0 (or 200K if a CVE candidate's classification is contested) |
| 4 | 80-150K (bug reports + reproducers + campaign report) | 100-200K (P4 source citations for every bug report) | 0 | 0 |

**Red flag:** if the Orchestrator (Sonnet) row exceeds 200K total across all phases, it's reading too much itself. Apply Patterns P1-P5 more aggressively.

**Red flag:** if Phase 1 burns more than 60K Orchestrator tokens, the subagents aren't returning compact-enough summaries — tighten their prompts to "return ≤500 words" and re-spawn.

### Scaling by campaign size band

The table above is calibrated for 20K traces / ~67 buckets. For other sizes, scale as follows (assumptions: bucket count plateaus around ~100 for a single PUT pair; per-bucket sampling depth grows mildly for statistical confidence at scale; the number of CVE/VULN candidates is approximately independent of trace count):

| Size band | Trace count | Orchestrator (Sonnet) total | Subagents total | AGY Auditor total | Opus deep-audit total | Grand total |
|---|---|---|---|---|---|---|
| Small | <500 | <100K | <100K | <200K | 0-200K | <500K |
| Medium | 500-5,000 | 150-300K | 300-600K | 500K-1M | 200K-1M | 1-3M |
| Large | 5,000-50,000 | 250-500K | 700K-1.5M | 1-2.5M | 600K-2.5M | 3-8M |
| Very large | 50,000-500,000 | 400-700K | 1.5-3M | 2.5-5M | 1-3M | 7-12M |
| **Extra large** | **500,000-2,000,000** | **500K-1M** | **3-5M** | **4-8M** | **2-4M** | **10-20M** |

**What drives the growth between size bands:**

- **Orchestrator:** scales with bucket count (1.2× from 20K→1M), Δ3 refinement-pass frequency (more chance of loose criteria at 1M traces), and Phase 4 bug-report count.
- **Subagents:** scales with bucket count + per-bucket sampling depth (5-10 at 20K → 15-25 at 1M for statistical confidence). Δ3 refinement passes also drive subagent calls.
- **AGY Auditor:** Audit 1 (granularity) per-bucket reads grow with sample depth; Audit 3 (consistency) grows with bug-report file count. Each individual audit still fits in AGY's ~1M context — the budget growth is from MORE audits, not bigger ones.
- **Opus deep-audit:** approximately constant in *count* (3-6 parallel audits per campaign regardless of trace count), so the per-token growth is mostly from each individual deep audit having more bucket context to reason over.

**For 500K-1M-trace campaigns specifically (Extra large band):**
- The dominant cost is the AGY Auditor (4-8M tokens).
- The Orchestrator's 500K-1M share is the binding constraint on session persistence — see § "Session lifecycle for large campaigns" and § "Extra-large campaign caveats".
- Phase 0 wall-clock dominates (>30 hours at default PARALLELISM=20 for 1M traces); raise parallelism or distribute across hosts.
- Δ3 refinement passes are routine, not exceptional — budget 5-10 passes per campaign.

---

## Session lifecycle for large campaigns

### Why one session doesn't work past the Medium band

The Orchestrator's context window is ~200K tokens. Auto-compaction extends a session's lifetime but **erodes fidelity** — earlier bucket decisions, audit rationales, and refutation reasoning get summarised away. By Phase 4, an auto-compacted session's memory of Phase 2 decisions is materially weaker than the persistent files on disk.

For campaigns in the **Large** or **Very large** size band, the Orchestrator's total token budget (250-800K) exceeds the window 1-4 times, so auto-compaction would fire multiple times. The fidelity loss compounds:

- Bucket decisions from Phase 2 are forgotten by Phase 4 (Orchestrator drafts a bug report that contradicts the bucket comment it wrote earlier).
- Audit 1 reasoning is lost by Audit 3 (Orchestrator can't recognise a stale-claim audit obligation triggered by Audit 1).
- Subagent return summaries from Phase 1 are compacted, so Phase 2 has to re-spawn subagents to rebuild context.

Each of these is a real cost. The cleanest mitigation is **phase-bounded sessions** with explicit file-based handoff.

### Recommended session boundaries

Each phase produces persistent artefacts; a fresh session can re-bootstrap from these files in ~5K tokens. Use these natural handoff points:

| Session | Spans | Reads to bootstrap | Approx Orchestrator budget |
|---|---|---|---|
| S1 — **Pre-analysis + Phase 0 + Phase 0.5** | Corpus sizing, metadata generation kick-off, bootstrap-bucket scaffold | (none; first session) | 30-80K |
| S2 — **Phase 1 + Phase 2** | Symptom fingerprint, bucket tightening | `BUCKET_LIST.md`, `phase_0_5_bootstrap/difference_summary.txt`, the live script | 150-300K |
| S3 — **Phase 2.5 + Audit 1 trigger + post-audit fixes** | Granularity self-audit, then external Audit 1, then condition-fix iterations | live script, `mailbox/from_auditor/audit_1_verdict.md` | 50-150K |
| S4 — **Phase 3 + Audit 2 trigger** | Security Gate work on VULN candidates | live script, `mailbox/from_auditor/audit_1_verdict.md` | 80-200K |
| S5 — **Phase 4 bug reports** | Drafting one bug report per finding | live script, audit verdicts, `BUCKET_LIST.md` | 100-250K |
| S6 — **Phase 4 reproducers** | L1-L4 evidence progression per finding | bug reports from S5 | 80-200K |
| S7 — **Phase 4 summary + Audit 3 trigger + finalisation** | `SUMMARY_BUCKETS.md`, `CAMPAIGN_REPORT.md`, disclosure folder | all prior artefacts | 50-150K |

For **Small** and **Medium** size bands, sessions S1-S7 can collapse into 1-2 sessions because the total Orchestrator budget stays under one window's worth.

For **Large** and **Very large**, the 7-boundary structure above is the recommended default. Each boundary is a natural "good place to stop for the day" for human-in-the-loop campaigns.

### Handoff message at session boundaries

At the end of each session (when the next phase is a natural boundary), the Orchestrator emits a handoff message:

```
[Session S<n> complete — handoff for S<n+1>]

What's done:
  - <bullet list of phases / audits completed>

Where state lives (read these to resume):
  - evaluation-ddyf/sort_objectives_ossl_libre.py (current bucket set, tags)
  - <campaign>/BUCKET_LIST.md  (counts as of this session)
  - <campaign>/mailbox/from_auditor/audit_<N>_verdict.md  (most recent audit)
  - <other phase-specific artefacts>

Next session (S<n+1>) should:
  - <one-line: which phase to enter>
  - <one-line: which files to read first>

When you're ready to resume, start a new Orchestrator session and paste:
  "Resume DDYF triaging at S<n+1> per ORCHESTRATOR.md § Session lifecycle.
   Read <campaign>/mailbox/from_auditor/audit_<N>_verdict.md and the live triaging script
   first."
```

The user can either continue the same session (if context budget allows) or spin a fresh one. Either way, the handoff message is persistent: it lives in the chat transcript AND is referenced in the next session's startup read.

### When to spin a fresh session ahead of schedule

Even within the S1-S7 plan, spin a fresh session if:

- Auto-compaction has fired and the Orchestrator notices it has lost specific detail it needs (e.g., it can't recall the exact root-cause line for a bucket without re-reading).
- A long subagent return (>20K tokens) is about to be ingested and the current session is already past 100K used tokens.
- The user requests a session restart explicitly.

Phase-bounded sessions are a **default**, not a constraint. The cost of starting a new session is ~5K tokens for re-bootstrap; the cost of pushing an auto-compacted session into work that depends on lost context can be much higher.

### Extra-large campaign caveats  *(500,000-2,000,000 traces)*

Extra-large campaigns are an expected operating point — campaigns producing 500K-1M+ traces from production-scale fuzzing runs are routine, not pathological. They need a few specific accommodations beyond the standard phase-bounded protocol:

**Phase 0 wall-clock is the dominant cost.** At default `PARALLELISM=20` and ~2.5 s/trace, 1M traces takes ~35 hours of pure shell I/O. Mitigations:

1. **Raise PARALLELISM** in `evaluation-ddyf/phase0_produce_metadata.sh` to 80-128 if the host CPU count allows (each `tlspuffin display-execute` is mostly CPU-bound). At PARALLELISM=80 and 1M traces, Phase 0 is ~9 hours.
2. **Distribute across hosts** if available — the script's outer loop is embarrassingly parallel. Split `objective/` into N shards, run the script on each host, merge.
3. **Run Phase 0 before involving the LLM at all** — kick it off on a beefy machine via `nohup`/`screen` and only invoke the Orchestrator once the metadata is fully generated. The pre-analysis step's wall-clock estimate tells the user what to expect.

**Disk and inode headroom.** Metadata logs are ~30 KB per trace triplet (one diff log + two display-execute logs). At 1M traces that's ~30 GB. Each trace also produces 4 files (the trace + 3 metadata logs); some filesystems (older ext, FAT) have low inode caps. Pre-flight:

```bash
df -h objective       # space headroom
df -i objective       # inode headroom (e.g., 4M inodes for 1M traces × 4 files + buffer)
```

**Token-budget pacing.** A 1M-trace campaign is 10-20M tokens total. The Claude Pro plan has a weekly cap; pacing matters:

- The Orchestrator's per-session budget (250-500K) stays within the cap easily.
- The AGY Auditor pane is on a separate budget — pace AGY's audits across days so each Audit 1/2/3 doesn't crowd out other AGY usage.
- The Opus deep-audit slot is the most expensive per-call; reserve it for the 3-5 highest-stakes findings (Track 1 / Track 2 promotions, compound-attack refutations).

**Δ3 refinement is more frequent at scale.** With 1M traces, a loose bucket criterion that "looked right" at 20K traces routinely captures a long-tail-of-traces with a distinct root cause. Budget extra Phase 2 + scoped-Audit-1 cycles for refinement passes. A reasonable rule of thumb: expect 5-10 Δ3 passes during the campaign, each ~30-100K Orchestrator tokens + a scoped audit appendix.

**Phase 1 sampling depth grows.** At 20K traces, 5-10 sample reads per bucket is sufficient for confidence. At 1M, raise the per-bucket sample to 15-25 (some buckets have >100K traces and need more sampling to catch the long tail). This is what drives the subagent budget growth from ~1.5M to ~4M tokens between Large and Extra large.

**Phase 0.5 incremental-mode discipline is critical.** Extra-large campaigns often grow over time (the user fuzzes for more weeks; more traces are appended). The incremental re-run protocol (§ Detect campaign mode → Incremental mode protocol) is the supported way to add new traces without re-running Phase 0 on the whole corpus. The Δ1/Δ2/Δ3/Δ4 outcome handling becomes routine, not exceptional.

**Disclosure-pipeline patience.** A 1M-trace campaign at Track 2 promotion is high-credibility evidence. Coordinated-disclosure timelines should reflect the campaign scale — expect 30-90 day vendor response windows for findings with this much evidence behind them.

---

## Targeted investigation delegation  *(use when Phase 3 leaves unresolved source questions)*

When a finding fails the strict gates but has a speculative path you cannot structurally refute from metadata alone — particularly when it requires deep source-code reading in a separate code path — delegate the investigation to a separate Claude Code session rather than spending Orchestrator tokens on it.

**When to delegate:** after Phase 3, for any finding where (a) the strict gate fails, (b) you have a specific technical question ("does mechanism X prevent attack Y?"), and (c) answering requires reading 200+ lines of vendor source not already in context.

**How to write the investigation prompt:** use `TEMPLATES.md` (Investigation prompt). The template produces a self-contained brief: the finding, the relevant source files and line numbers, the technical question, and an explicit verdict format. The investigation session must **not** see your reasoning — the goal is an independent walk.

**On return:** record the verdict in the appropriate place:
- `NOT A BUG` or `REFUTED` → add a brief appendix to the bug report (see `libressl_record_overflow_bypass.md` for the canonical example). Apply the stale-claim audit sweep per the rule below.
- `CONFIRMED` → promote the finding per the CVE-candidate track in `tls/SECURITY_GATE_TLS.md`.
- `NEEDS MORE EVIDENCE` → document what evidence is missing in the bug report's speculative-paths section.

---

## Phase 4 — Reports, reproducers, summary

### 4a. Bug reports

Write one report per **root cause** (not per bucket) in `${CAMPAIGN}/BUGS/` using `TEMPLATES.md` (Bug report). Every claim must trace to a metadata log line or source file:line.

### 4b. Reproducers

For every report write a minimal standalone reproducer at `${CAMPAIGN}/BUGS/reproduce_<root_name>.py` following `TEMPLATES.md` (Reproducer):
- No absolute paths
- Self-starts its own server/client via subprocess
- ≤ ~150 lines of executable code
- Build/run instructions at the top
- Concise output: trigger + verdict, not a re-statement of the bug report

Naming: `${CAMPAIGN}/BUGS/reproduce_libressl_X.py` corresponds to `${CAMPAIGN}/BUGS/libressl_X.md`. See `NAMING_CONVENTIONS.md`.

### 4c. `BUCKET_LIST.md`  *(mandatory, dedicated)*

Write `${CAMPAIGN}/BUCKET_LIST.md` using the helper script:

```bash
python -m evaluation-ddyf.generate_bucket_list ${CAMPAIGN}
```

The script reads `SUMMARY_BUCKETS.md` (first-occurrence rule) and `objective/` for live counts. The result is a minimal flat table — one row per non-empty bucket, no prose, no sub-sections:

```markdown
# Bucket List — <PUT1> vs <PUT2>, MM-DD

| Bucket | Status | Traces | Root cause (one line) |
|---|---|---|---|
| `<bucket_name>` | CVE / CVE candidate / RFC / Bug / BENIGN | N | ... |
```

**Status values (canonical order):** `CVE` (VULN passing all 5 strict gates, CVSS ≥ 4.0) → `CVE candidate` (empirical PoC + non-zero CVSS framing + disclosure path) → `RFC` (RFC violation, no CVE-filing path) → `Bug` (non-RFC defect) → `BENIGN` (spec-permitted difference).

**Status canonical source:** SUMMARY_BUCKETS.md first-occurrence wins. A bucket tagged `[BENIGN]` in the triaging script but placed in §3 (Bugs) of SUMMARY_BUCKETS.md gets status `Bug` in BUCKET_LIST.md. Buckets without any `[TAG]` in the script (e.g., housekeeping `no_errors`) default to `BENIGN`.

### 4d. `SUMMARY_BUCKETS.md`  *(full summary)*

Write `${CAMPAIGN}/SUMMARY_BUCKETS.md` — the comprehensive summary with bug-report links, RFC citations, and one-liners. Use `TEMPLATES.md` (Summary-buckets). **Canonical category order:**
1. **CVE** — passes all 5 strict Security Gates, CVSS ≥ 4.0
2. **CVE candidate** — empirical PoC + non-zero CVSS framing + documented disclosure path
3. **RFC violations** — `[RFC]` with a confirmed root cause, no CVE-filing path
4. **Library bugs (non-RFC)** — internal API defects, application-side defects, etc.
5. **Benign differences** — `[BENIGN]`

Each row: bucket name, bug-report link, trace count, severity/framing, one-line root cause.

### 4e. Campaign report

`${CAMPAIGN}/CAMPAIGN_REPORT.md`. Must contain the **bug-to-bucket mapping (both directions)**:
- Bug → buckets it covers (with trace counts)
- Bucket → bug that covers it (must be 1-to-1 after consolidation)

Every non-empty `[RFC]`/`[VULN]`/CVE-candidate bucket appears in exactly one row. `[BENIGN]` buckets are listed in `SUMMARY_BUCKETS.md` but not necessarily mapped to a bug report. See `TEMPLATES.md` (Summary-buckets) §1–§4 for cardinality rules per category.

### 4f. Triaging script snapshot  *(do last)*

After all other artifacts are finalized, copy the triaging script into the campaign folder:

```bash
cp evaluation-ddyf/sort_objectives_${PUT1}_${PUT2}.py ${CAMPAIGN}/sort_objectives_${PUT1}_${PUT2}.py
```

This snapshot makes the campaign folder self-contained: the classification logic, the bug reports, and the bucket data are all in one place. The original in `evaluation-ddyf/` is kept for execution.

### 4g. Re-triage verification  *(determinism check — MANDATORY, CI-enforceable)*

This step is **mandatory**, not optional: a campaign is not complete until the re-triage
round-trip is shown to be deterministic. It is also cheap to enforce mechanically — the
same move-back + re-run + count-compare can run as a CI job (or a pre-declare script) that
**fails** on any per-bucket count deviation, so determinism is checked by machine rather
than trusted. Move all traces back to `objective/` top-level and re-run the script to
confirm the bucket distribution is deterministic (no ordering bug, no unintended overlap):

```bash
find objective/ -mindepth 2 -name "*.trace" -exec mv {} objective/ \;
find objective/ -mindepth 2 -name "*.log"   -exec mv {} objective/ \;
python -m evaluation-ddyf.sort_objectives_ossl_libre
# Compare per-bucket counts against the Phase 2.5 baseline:
for d in objective/*/; do
  count=$(find "$d" -maxdepth 1 -name "*.trace" | wc -l)
  echo "$count $(basename $d)"
done | sort -rn
```

Expected: every bucket count matches the pre-move baseline exactly, and the top-level uncategorized count is unchanged. Any deviation means a bucket condition has an ordering dependency or an unintended overlap — investigate before proceeding to Audit 3.

---

## Cross-artifact synchronisation rule  *(applies throughout)*

Before declaring the campaign complete, verify (all paths relative to `${CAMPAIGN}/`):

| Bucket name | Bug report name | Reproducer name | All present? |
|---|---|---|---|
| `libre_record_overflow_bypass/` | `BUGS/libressl_record_overflow_bypass.md` | `BUGS/reproduce_libressl_record_overflow_bypass.py` | ✓ |
| ... | ... | ... | ... |

Specifically:
- Every bug report references its bucket(s) by full name
- Every bucket comment in the triaging script references its bug report
- Every reproducer header references its bug report
- `BUCKET_LIST.md`, `SUMMARY_BUCKETS.md`, and `CAMPAIGN_REPORT.md` use the same names and the same category throughout
- Every `[RFC]`/`[VULN]`/CVE-candidate bucket appears in exactly one row of SUMMARY_BUCKETS.md §1–§4

See `NAMING_CONVENTIONS.md` for the canonical naming scheme.

---

## Stale-claim audit  *(mandatory after every refutation, severity change, or category promotion)*

Whenever (a) a speculative attack path is marked REFUTED, (b) a finding's severity changes, (c) a bucket is promoted/demoted between §1–§5 of `SUMMARY_BUCKETS.md`, or (d) a key code-location reference (file:line) is corrected, perform a stale-claim sweep.

The audit has **two tiers**: structural (tables, cross-reference stubs, line numbers) AND **narrative** (executive summaries, abstracts, paragraph-level claims). Both must be swept. The narrative tier is the most often-missed — a table row can be mechanically updated while the paragraph above the table still asserts the pre-promotion classification. The §1 Executive Summary of `CAMPAIGN_REPORT.md` is the historical worst offender; sweep it explicitly every time.

### Tier 1 — Structural sweep

```sh
# Grep the entire campaign tree for the original phrasing.
grep -rln "<original phrasing>" --include="*.md" --include="*.py" \
    ${CAMPAIGN}/ evaluation-ddyf/ prompts-triaging/
```

For each match: either update with the refutation note + date, or replace with a cross-reference to the canonical location.

Specifically check that these stay in sync:

- The bug report's **header severity / CVSS line** matches the body's analysis after any path refutation.
- `SUMMARY_BUCKETS.md` §5 (Speculative attack paths) entries match the corresponding bug report's "Speculative Attack Paths" section verbatim.
- Cross-reference stubs in `SUMMARY_BUCKETS.md` (`*(<bucket> — promoted to §N; see above)*`) point to the correct section number after any renumbering.
- `CAMPAIGN_REPORT.md` and `BUCKET_LIST.md` carry the same one-line description for the bucket.

### Tier 2 — Narrative sweep  *(the part frequently missed)*

After any category promotion (RFC → CVE candidate, or CVE candidate → CVE; rarely the reverse), run an **explicit narrative-pattern grep** before declaring the audit done. The known stale-narrative patterns are:

```sh
# These phrases imply "no CVE-candidate finding exists" and become stale the
# moment any bucket is promoted to §1 or §2 of SUMMARY_BUCKETS.md.
grep -rnE "(No (exploitable )?(CVEs?|vulnerabilities?) (were|was)|\
all (initially )?suspicious|\
no security impact|\
all classified as RFC|\
[0-9]+ confirmed bugs|\
all CVE candidates investigated and refuted|\
no bucket passes [^.]+VULN)" \
    --include="*.md" ${CAMPAIGN}/ 2>/dev/null
```

Every match must be reviewed by hand — most need rewording to reflect the current classification. The list above is the historical list of stale phrasings discovered in past campaigns; extend it whenever a new failure mode emerges.

### Narrative locations that MUST be re-read after any category promotion

These are the paragraph-level places where stale classification claims have escaped tier-1 table sweeps in past campaigns. Re-read each whenever a bucket moves between sections of `SUMMARY_BUCKETS.md`:

| File | Section to re-read | What to verify |
|---|---|---|
| `${CAMPAIGN}/CAMPAIGN_REPORT.md` | §1 Executive Summary | The "Key findings" bullet list AND the opening paragraph reflect the current §1/§2/§3/§4 classification. NO "no CVE / no exploitable" phrasing if any §1/§2 bucket exists. |
| `${CAMPAIGN}/CAMPAIGN_REPORT.md` | §3 Classification Summary | Counts in the table match `SUMMARY_BUCKETS.md` §1-§5 totals. Audit-trail comment underneath references the promotion. |
| `${CAMPAIGN}/CAMPAIGN_REPORT.md` | §8 CVE Assessment | The "two CVE candidates" / "no strict VULN" framing matches §1's narrative. |
| `${CAMPAIGN}/CAMPAIGN_REPORT.md` | "On the relationship between buckets and bugs" paragraph | Bucket counts per section AND the count of bug reports match. |
| `${CAMPAIGN}/SUMMARY_BUCKETS.md` | Header (date, total traces, coverage) | If trace count changed via an incremental re-run, this header reflects it. |
| `${CAMPAIGN}/SUMMARY_BUCKETS.md` | §6 (or whichever number) Speculative attack paths | Each row's REFUTED / KEEP status reflects the latest audit findings. |
| `${CAMPAIGN}/SUMMARY_BUCKETS.md` | Totals table footer | Bucket + trace counts per category sum to grand total; per-category percentages sum to 100%. |
| `${CAMPAIGN}/BUGS/<bug-report>.md` | Header severity / CVSS line | Matches the body's CVSS multi-framing analysis. |
| `${CAMPAIGN}/BUGS/<bug-report>_SUMMARY.md` (if present) | "Defect" table | Matches the bug report's header and §6. |
| `${CAMPAIGN}/disclosure/email_<root>.md` | All sections | If a CVE-candidate finding had a drafted disclosure email, re-read it; the framing of the affected versions, the CVSS table, and the impact narrative must match the latest bug report. |

### Workflow

1. Identify the change (refutation / promotion / severity update).
2. Run the Tier-1 phrase grep for the original phrasing being replaced.
3. Run the Tier-2 narrative pattern grep (the regex above).
4. Sweep the table of narrative locations above, paragraph by paragraph.
5. Update every match either with the new claim + date or with a cross-reference to the canonical location.
6. If the change involved a category promotion, **also re-read the Executive Summary §1 last** as a final sanity check — that paragraph is the highest-visibility narrative in the campaign and the historically most often-missed.

A 5-minute pass per refutation/promotion. The cost of skipping is documents that contradict each other and confuse the next campaign — and an Executive Summary that asserts "no CVEs" while §1 of `SUMMARY_BUCKETS.md` lists two CVE candidates is the worst kind of internal contradiction: the kind a casual reader will believe.

---

## Disclosure folder convention  *(mandatory when any CVE candidate exists)*

For every finding promoted to **§1 (CVE)** or **§2 (CVE candidates)** of `SUMMARY_BUCKETS.md`, a corresponding draft email must exist in `${CAMPAIGN}/disclosure/`:

```
${CAMPAIGN}/
├── BUGS/
│   ├── <root>.md                              ← bug report
│   ├── <root>_SUMMARY.md                      ← one-page summary card (optional)
│   └── reproduce_<root>.py                    ← reproducer(s)
└── disclosure/
    ├── README.md                              ← conventions, sending procedure, footer template
    └── email_<root>.md                        ← draft email to the relevant security@<vendor>
```

Cross-reference `disclosure/email_<root>.md` from:

- The bug report's §6 (CVSS / disclosure status section).
- The corresponding `SUMMARY_BUCKETS.md` §1/§2 row's `Status` column.
- The `CAMPAIGN_REPORT.md` §4 CVE-Candidate Buckets row.

After sending, append a "Disclosure log" footer to the email file (one line per state change: sent, ack received, CVE assigned, patch landed, public disclosure). This feeds the `Status` column.

Apply the canonical category-order rule from `TEMPLATES.md` (Summary-buckets) (CVE → CVE candidate → RFC → Bug → BENIGN) consistently.

---

## Handoff protocol

Each tag is a **single line of its own**; the Orchestrator and Auditor never mutate each
other's lines — they add or remove whole lines. This keeps the grep-based state machine (and
the resume-detection in `START_HERE.md`) robust.

- `# GRANULARITY AUDITED [ORCHESTRATOR]` + free-text criteria lines — Orchestrator's Phase-2.5 self-audit. The Auditor leaves this block untouched.
- `# PENDING REVIEW` — Orchestrator adds when Phase 2.5 passes. The Auditor **deletes** this line once it has processed the bucket.
- `# AUDITED [AUDITOR]: <one-line>` — Auditor **appends** when all criteria pass. **Never add it yourself.**
- `# REVISION NEEDED [AUDITOR]: <reason>` — Auditor **appends**; Orchestrator fixes, then removes the auditor's line and re-adds `# PENDING REVIEW` for re-audit.

A bucket is "awaiting audit" iff it has a `# PENDING REVIEW` line; "audited" iff it has an `# AUDITED [AUDITOR]` line and no `# PENDING REVIEW`. No bucket should ever carry both at once — the Auditor's verdict template self-checks this (see `AUDITOR.md` Audit 1).

---

## BucketCondition primitives

| Primitive | When to use |
|---|---|
| `KnowledgeDiffC(first_type, second_type)` | Knowledge-level type difference (always combine with content constraint, see C1) |
| `InnerKnowledgeC("Different(A, B)", "AlertMessagePayload")` | Specific alert pair |
| `StatusC(PUT, "error string", first_to_fail=True/False)` | Error from execution log |
| `DifferentClaimC(in_first_type, in_second_type)` | Claim present/absent (always specify types, see C1) |
| `TermContainsC(PUT, "fn_symbol")` | Function symbol in trace term |
| `TermContainsReC(PUT, r"regex")` | Regex on trace-term string |
| `ClaimContainsC(PUT, r"field: value")` | Regex on claim text |
| `StepC(lambda f, s, total: ...)` | Relative step-of-failure |
| `NotC(...)` | Exclusion |
| `AllC(...)` / `AnyC(...)` | Conjunction / disjunction |

### `first_to_fail` guidance

| Trace type | Use | Why |
|---|---|---|
| Status difference | `first_to_fail=True` | `Status` field is populated |
| Knowledge difference | `first_to_fail=False` | `Status` field is `None`; reads per-PUT display-execute error string instead |

When in doubt: run `differential-execute -S` once and check whether the output shows `Execution status difference` (use `True`) or only `Differences in knowledges` (use `False`).

### Avoiding the v2 overlap bug

The `*_silent_*` family and `libre_finished_claim_silent_ossl` both match `KnowledgeDiffC(AlertMessagePayload, ())`. Add `NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished"))` to all silent-abort buckets to keep them separate.

---

## Reproducer rules  *(learned from practice)*

1. **Use the project binaries** at `vendor/libressl421/src/vendor/apps/openssl/openssl` and `vendor/openssl340/bin/openssl`. Hardcode the relative paths as constants.
2. **Never pass `-quiet` to `openssl s_server`** — the project's sanitized OpenSSL 3.4.0 binary crashes (null pointer at PC=0x0) on any ClientHello with `-quiet`. Suppress output via `subprocess.Popen(..., stdout=DEVNULL, stderr=DEVNULL)`.
3. The OpenSSL binary is a **sanitized UBSan/ASan debug build**. For crash findings, verify with the system binary (`/usr/bin/openssl`) before assigning a security score.
4. Some bugs only reproduce in the multi-agent tlspuffin harness. If your standalone reproducer shows PASS but the tlspuffin traces show the bug, document both observations explicitly — do not discard the finding.
5. A TCP RST (`Connection reset by peer`, errno 104) and a silent close both mean **no TLS alert** — treat them identically as RFC violations.

See `TEMPLATES.md` (Reproducer) for the full template.


---

## Appendix — reading tlspuffin diff output (TLS reference card)

Reference for interpreting `tlspuffin` output in `metadata_*.log` (formerly `ORCHESTRATOR.md` (Appendix — reading diff output)). Read once before Phase 1; refer back as needed. TLS-specific; the shapes generalise to other protocols.

Reference card for interpreting `tlspuffin` outputs in `metadata_*.log` files. Read once before Phase 1; refer back as needed.

---

### `differential-execute -S` output

```bash
./target/release/tlspuffin differential-execute openssl340 libressl421 <TRACE> -S
```

Three top-level result types:

#### 1. No difference observed

```
Differences between the PUTs:

```
*(empty body)*

→ The trace ran identically on both PUTs. Goes to bucket `no_errors/` (flaky / non-deterministic execution).

#### 2. Execution status difference

```
Differences between the PUTs:

Execution status difference
    first put : (step 5/5) Success
    second put : (step 2/5) SSL_ERROR_SSL (1): error:1402542E:SSL routines:ACCEPT_SR_CLNT_HELLO:tlsv1 alert protocol version
```

→ One PUT errored at a specific step; the other went further or succeeded. **Use `StatusC(..., first_to_fail=True)`** in the bucket condition.

Step notation: `(step f/total)` where `f` is the step at which this PUT first failed, and `total` is the trace length.

#### 3. Knowledge difference

```
Differences in knowledges: knowledge[0]
  (tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload, agent:0) :
  [Description(Different(HandshakeFailure, MissingExtension))]
```

→ Both PUTs ran all steps. They produced different content at the same knowledge index. **Use `StatusC(..., first_to_fail=False)`** in the bucket condition (the `Status` field in the diff record is `None` for these traces).

Common patterns:
- `Different(AlertA, AlertB)` — both PUTs sent an alert; the codes differ.
- `Different(<Type>, ())` — first PUT produced something; second PUT produced nothing (silent abort).
- `Different((), <Type>)` — first PUT produced nothing; second produced something.

#### 4. Claim difference

```
Differences in claims: claim[2]
  (Finished, agent:0) : [Different(Finished {...}, ())]
```

→ Both PUTs ran. One emitted a claim (e.g., Finished) where the other emitted nothing. **Use `DifferentClaimC(in_first_type, in_second_type)`** in the bucket condition.

---

### `display-execute -tckp` output (per-PUT)

```bash
./target/release/tlspuffin --put openssl340 display-execute <TRACE> -tckp
```

Flags: `-t` terms, `-c` claims, `-k` knowledges, `-p` payloads.

Output structure (one block per step):

```
==== Executing step #N ====
Action: Input (attacker -> agent.X)         ← step type
Term: fn_<symbol>(...)                       ← what was sent (Input) or output (Output)
>>> OpaqueMessageFlight { messages: [...] } ← raw bytes returned BY the agent
>>> MessageFlight { messages: [...] }        ← decoded version of the same
+++ TranscriptServerHello(...)               ← claim emitted at this step
```

Final lines:
```
Extra knowledges :
Error : error in PUT : SSL_ERROR_SSL (1): ... :file.c:line:
```

#### Reading direction conventions

| Action type | What `>>>` shows |
|---|---|
| `Input (attacker -> agent.X)` | The PUT's **response** to the attacker's input (often an Alert if the input was rejected) |
| `Output (agent.X -> attacker)` | What the agent **sent out** (the term being captured) |

The bytes the attacker sent **into** the agent are computed at runtime from the `Term:` line; they are not directly displayed in `-p` output.

#### Pitfall: "Finished" in metadata logs ≠ Finished claim  *(Gate 1 common mistake)*

The `display-execute -tckp` log contains **two distinct places** where the word "Finished" appears. Confusing them leads to incorrect Gate 1 assessments.

**1. Decryption-attempt section** — these are attempted lookups by the fuzzer, NOT extracted facts:
```
(Some(Agent(AgentName(1))), 0)[None]/Finished     ← [None] = NOT FOUND
```
`grep -l "Finished" metadata_libressl421_*.log` will match here and produce false positives. All 107 traces in `ossl_record_failure_libre_accepts` matched this grep yet had **zero actual Finished claims**.

**2. Extra knowledges section** — the only authoritative source. Located at the bottom of each log:
```
Extra knowledges :
+++ Finished { outbound: true, ... }   ← this is a real claim
```
An empty `Extra knowledges :` section (next line is `Success` or `Error`) means **no claims were extracted**.

**Correct Gate 1 command:**
```bash
grep -A200 "Extra knowledges" metadata_libressl421_T.log | grep -c "Finished {"
```
Not `grep -c "Finished"` — that includes the decryption-attempt section.

---

#### Finished claim format

```
+++ Finished {
    outbound: true,
    client_random: [...],
    server_random: [...],
    session_id: [...],
    authenticate_peer: false,
    peer_certificate: [],
    early_secret:     [0, 0, 0, ...],
    handshake_secret: [0, 0, 0, ...],
    master_secret:    [0, 0, 0, ...],
    tls_version: CLAIM_TLS_VERSION_V1_2,
    chosen_cipher: 4865,
    available_ciphers: [...],
    signature_algorithm: 0,
    peer_signature_algorithm: 0
}
```

**Security Gate red flags in this output:**

| Field | Meaning if zero/false | Gate |
|---|---|---|
| `early_secret`, `handshake_secret`, `master_secret` all 64 zeros | Key schedule never initialized — Finished is a state-machine artifact, not a real session | **Gate 3 fails** |
| `authenticate_peer: false` | Peer was never authenticated | Confirms Gate 3 failure |
| `server_random: [1, 1, 1, ..., 1]` (all ones) | tlspuffin stub value — no real server participated | **Gate 2 fails** |
| `tls_version: CLAIM_TLS_VERSION_V1_2` + `chosen_cipher: 4865` (TLS 1.3 cipher) | Version-cipher mismatch; key schedule guaranteed zero | RFC violation, Gate 3 fails |

---

### Common error string patterns

Useful as `StatusC(..., "<substring>", ...)` matchers:

| Substring | Meaning |
|---|---|
| `unexpected message` | OpenSSL `ossl_statem_*_read_transition` rejecting an out-of-order message |
| `wrong cipher returned` | Client received a cipher it did not offer |
| `record layer failure` | TLS record decryption or MAC verification failed |
| `unsafe legacy renegotiation disabled` | Server lacks `renegotiation_info`; OpenSSL refuses |
| `final_key_share` / `no key share` | TLS 1.3 server has no matching group |
| `tls_parse_stoc_key_share` | OpenSSL parsing an HRR's key_share |
| `bad key share` | OpenSSL: HRR selected_group not offered |
| `length mismatch` | OpenSSL: extension parser found extra bytes |
| `no shared cipher` / `no shared signature algorithms` | Server cannot pick a cipher/sigalg |
| `tls13_lib.c` (LibreSSL) | LibreSSL TLS 1.3 path |
| `ssl_pkt.c` (LibreSSL) | LibreSSL record layer |
| `tlsv1 alert <name>` | A fatal alert was sent (the alert text is on the line) |

---

### Trace file layout

```
objective/
  <bucket_name>/                           ← named after triaging script bucket
    20260428-XXX-YYY.trace                 ← the trace file (binary serialised)
    metadata_diff_20260428-XXX-YYY.trace.log         ← Phase 0
    metadata_openssl340_20260428-XXX-YYY.trace.log   ← Phase 0
    metadata_libressl421_20260428-XXX-YYY.trace.log  ← Phase 0
```

Phase 0 produces the three `metadata_*.log` files; Phases 1–4 read them.
