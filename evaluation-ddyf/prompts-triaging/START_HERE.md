# START HERE — User Entry Point

This is the single file you give to your main LLM session to launch a DDYF triaging campaign. The Orchestrator reads this file, follows it step-by-step, and tells you exactly when to spawn auxiliary sessions (Auditor, Phase-0 data producer) and with which prompt.

You only have to do four things manually:
1. Place traces in `./objective/`.
2. Run Phase 0 (metadata generation) — see Step 2 below. This is just a shell script; no LLM needed.
3. Launch the **Orchestrator** session (Step 3). Its first user message is one of:
   - **Fresh campaign:** `"Begin DDYF triaging campaign. Phase 0 metadata logs are in place. Start at Phase 0.5 (bootstrap) per prompts-v3/START_HERE.md."` *(Phase 0.5 is a new, token-cheap, mechanical bootstrap pass that creates a loose first-cut bucket scaffold by running the triaging script with empty buckets. It sits between Phase 0 and Phase 1. See `PHASE_0_5_BOOTSTRAP.md`.)*
   - **Incremental re-run** (new objectives appended to an existing campaign): `"Resume DDYF triaging campaign in incremental mode. New objectives placed; Phase 0 metadata generated for them. Detect incremental mode per ORCHESTRATOR.md Launch-time preconditions and run the Phase 0.5 incremental re-run."`
   - **Resume after stop:** see "Continuing a triaging campaign already in progress" below for the resumption template.
4. When the Orchestrator pauses and asks you to send a prompt to the Auditor pane, do the handoff (Step 4).

The Orchestrator handles all coordination between checkpoints. You are the human-in-the-loop only at the explicit Auditor checkpoints below.

---

## Pre-requisites

These are environmental things to confirm before kicking off the first new campaign, not changes to the prompts themselves:

  1. Tooling sanity check. gh auth status, python3 -c "import cryptography", ls vendor/<lib>/lib/libssl.a vendor/<lib>/lib/libcrypto.a — confirm GH CLI authed (the maintainer-history check uses it), pyca/cryptography is installed (some PoC scripts need it), and the vendor static libs are built (the C harnesses in reproduce_*_full.py link against them).
  2. Gemini and Claude CLI installed and ready to use. 
  3. Disk budget for Extra-large campaigns. If you're planning to run a 500K-1M-trace campaign, pre-confirm ~30 GB free under the partition that hosts objective/ AND that the filesystem has enough inodes (df -i objective). Some default ext4 inode counts
  run out before disk space on these workloads.
  4. tlspuffin parallelism. Raise PARALLELISM in evaluation-ddyf/phase0_produce_metadata.sh to ~80 if you're targeting Extra-large; the default of 20 gives a 30+ hour Phase 0 wall-clock at 1M traces.
  5. Pace the weekly Claude Pro budget. An Extra-large campaign is 10-20M tokens across all sessions; that's the right order of magnitude for the Pro plan's weekly cap, so don't try to land a 1M-trace campaign and a parallel research project in the same
  week.

What to do mid-campaign if something feels off. The prompts are dense enough that the Orchestrator may occasionally drift into work the prompts try to discourage. If you notice it:

  - Reading more than ~20 metadata files itself instead of spawning subagents → tell it "apply Pattern P1 from ORCHESTRATOR.md § Concrete delegation patterns."
  - Asserting a CVE claim without parallel deep audit → "this finding requires parallel deep audit per ORCHESTRATOR.md § Parallel deep audits before promotion."
  - Updating a bucket classification without sweeping the narrative paragraphs → "run the Tier 2 narrative sweep before declaring this done."
  - Skipping the upstream-verification step → "Gate 0 (upstream-build verification) is mandatory before Track 1 or Track 2 promotion."

---

## Why this multi-session orchestration?

We use **two persistent LLM sessions** (Orchestrator + primary Auditor) running in long-lived tmux panes, plus an **on-demand third session** for parallel deep audits of high-stakes findings, plus one short-lived Producer call:

| Session | Model | Lifetime | Why this model |
|---|---|---|---|
| **Producer** | Claude Haiku 4.5 | One-shot per campaign | Pure I/O — runs the Phase 0 shell script and verifies counts. Near-zero token cost. |
| **Orchestrator** | Claude Sonnet 4.6 (Pro plan), Claude Code CLI in tmux | Persistent through campaign | Mid-tier. Handles synthesis: bucket conditions, bug reports, reproducers. Token budget is the binding constraint. |
| **Auditor — primary (Gemini pane)** | Gemini Pro 3.x CLI in tmux | Persistent through campaign | Large context (~1M tokens) holds the entire triaging script + 60+ metadata files + cited RFCs + cited source files simultaneously. Separate token budget from Claude Pro. Used for ALL three standard checkpoints (Audit 1 / 2 / 3). |
| **Auditor — deep (Opus pane)** | Claude Opus 4.7 high effort, Claude Code CLI in tmux | On-demand, launched when a parallel deep audit is needed | Deep structural reasoning on state machines, conservative refutation walks. Used in parallel with the Gemini pane for `[VULN]` candidates, CVE-candidate promotions, compound-attack refutations. See `ORCHESTRATOR.md` § "Parallel deep audits". |

**The persistence point matters.** Because both Auditor sessions live in tmux for the whole campaign (or for the duration of a deep-audit thread), the audit checkpoints become messages to the *same* session — context loaded for one audit is still warm for the next. Auditors do not re-read the script or the metadata files three separate times.

**The parallel-audit point matters too.** For high-stakes findings (anything being promoted to §1/§2 of `SUMMARY_BUCKETS.md`, anything tagged `[VULN]`, any speculative path refutation that materially changes the disclosure framing), running both Gemini AND Opus in parallel on the same audit produces two tagged verdict files (`audit/audit_N_gemini.md` and `audit/audit_N_opus.md`). The Orchestrator synthesises both, flags discrepancies, and writes `audit/audit_N_synthesis.md`. This catches reasoning gaps that any single model misses — see the Path-4 refutation in `BUGS/libressl_wrong_cipher_acceptance.md` for a worked example.

**Handoff (constrained-write Auditor):** the Auditor edits audit tag comments in `evaluation-ddyf/sort_objectives_ossl_libre.py` directly and writes its verdict summary to `<campaign>/audit/audit_<N>_verdict.md`. The user does not copy-paste verdicts between panes — after the Auditor returns to idle, the user just types `continue` in the Orchestrator pane. The race-condition rule: the Orchestrator must be paused (waiting for input) the entire time the Auditor is editing. A "verdict only, no edits" fallback mode is available if the user wants chat-text verdicts instead — see Step 4.

**Token economics rationale:** Claude Pro has a fixed weekly token budget. Audit passes are token-heavy (reading many large files in one context) but compute-light (mostly verification, not synthesis). Pushing audits to Gemini Pro (different budget) leaves Orchestrator tokens for the work only Sonnet can do well: iterating on bucket conditions, writing reports, debugging reproducers.

You will be told to switch sessions at the right moments. The Orchestrator outputs a verbatim prompt for you to paste into the Auditor session, and waits for you to type `continue` after the Auditor has finished writing its verdict to the script and to `<campaign>/audit/audit_<N>_verdict.md`.

---

## What to expect — campaign size, timing, and tokens

Before launching the Orchestrator, the campaign falls into one of five size bands. The first thing the Orchestrator does on launch is emit a **pre-analysis report** that tells you which band you're in and what to expect. You can also estimate it yourself from the trace count:

| Size band | Traces | Expected buckets | Total token budget | Phase 0 wall-clock (`PARALLELISM=20`) | LLM-phase wall-clock | Session lifecycle |
|---|---|---|---|---|---|---|
| **Small** | <500 | <20 | <500K | ~1 min | <2 h | 1 Orchestrator session total |
| **Medium** | 500-5,000 | 20-50 | 1-3M | ~10 min | 2-12 h | 1 Orchestrator session typical |
| **Large** | 5,000-50,000 | 50-80 | 3-8M | ~40 min – 1.5 h | 12 h - 2 d | Phase-bounded (4-7 Orchestrator sessions) |
| **Very large** | 50,000-500,000 | ~80-100 | 7-12M | 1.5 h - 18 h | 2-6 d | Phase-bounded (7 sessions; mandatory) |
| **Extra large** | 500,000-2M | ~80-100 | 10-20M | 18 h - 70 h **at PARALLELISM=20** | 1-3 weeks | Phase-bounded (7+ sessions; mandatory); raise PARALLELISM ≥80 or distribute across hosts |

**Phase 0 wall-clock dominates for the Extra-large band.** At 1M traces with default PARALLELISM=20, Phase 0 alone takes ~35 hours of pure shell I/O. Mitigations are documented in `ORCHESTRATOR.md` § "Extra-large campaign caveats" — the short version: raise PARALLELISM in `phase0_produce_metadata.sh` to 80+ on a beefy host (or distribute the script across hosts), and confirm you have ~30 GB disk headroom and enough inodes for the metadata logs.

**The Orchestrator emits the pre-analysis BEFORE running Phase 0**, so you can interrupt and reconsider if the size band doesn't match what you intended (e.g., you ran the fuzzer for longer than expected and ended up with 5× more traces than the campaign was scoped for).

**You will see a heads-up if size band ≥ Large.** The Orchestrator will use phase-bounded sessions (one Claude Code session per natural phase boundary), emit explicit handoff messages, and route bulk reads to the Gemini Auditor pane. You don't need to do anything different — just type `continue` between sessions as instructed.

For Extra-large campaigns, you'll also see budget pacing notes (a 1M-trace campaign can consume a full weekly Claude Pro budget) and a recommendation to schedule the campaign across calendar days rather than trying to land it in one block.

---

## Campaign folder

Every campaign's output artifacts are isolated in a single dated folder at the repo root:

```
triaging-<put1>-<put2>-MM-DD/
├── BUGS/                            ← bug reports (*.md) and reproducers (reproduce_*.py)
├── audit/                           ← audit verdict files (audit_N_verdict.md)
├── sort_objectives_<p1>_<p2>.py     ← snapshot of the finalized triaging script
├── BUCKET_LIST.md                   ← dedicated bucket list: name, CVE/RFC/BENIGN status, count
├── SUMMARY_BUCKETS.md               ← full summary table with bug-report links and one-liners
└── CAMPAIGN_REPORT.md               ← complete campaign report
```

**Naming rule:** strip all digits from each PUT name and append today's date as `MM-DD`.
Examples: `openssl340` + `libressl421` launched on May 18 → `triaging-openssl-libressl-05-18`.

The Orchestrator computes the name on launch:
```bash
python3 -c "
import re, datetime
s = open('evaluation-ddyf/sort_objectives_ossl_libre.py').read()
p1 = re.sub(r'\d+','', re.search(r'FIRST_PUT\s*=\s*\"(\w+)\"',s).group(1))
p2 = re.sub(r'\d+','', re.search(r'SECOND_PUT\s*=\s*\"(\w+)\"',s).group(1))
print(f'triaging-{p1}-{p2}-{datetime.date.today().strftime(\"%m-%d\")}')"
```

Traces and metadata logs stay in `objective/` — they are inputs, not outputs. The triaging script is **copied** (not moved) into the campaign folder at the end of Phase 4 as an archival snapshot; the original in `evaluation-ddyf/` is kept for execution (`python -m evaluation-ddyf.sort_objectives_...`).

---

## Pipeline overview

```
You ─── place traces in objective/
   │
   ▼
[Orchestrator session 1 — Sonnet 4.6, Claude Code in tmux]
   First message: "Begin DDYF triaging campaign. Start at corpus pre-analysis."
   → emits a Campaign pre-analysis report:
     - Trace count, expected bucket count
     - Size band (Small / Medium / Large / Very large / Extra large)
     - Expected token budget across all sessions
     - Expected Phase 0 + LLM wall-clock
     - Heads-up if size band ≥ Large (phase-bounded sessions, etc.)
     - For Extra large (500K+): Phase 0 parallelism, disk space,
       weekly-budget pacing notes
   → waits for your "proceed" before running Phase 0
   │
   ▼
You ─── (if Orchestrator says to) run ./evaluation-ddyf/phase0_produce_metadata.sh
        (Phase 0; deterministic shell script; ~no LLM needed; wall-clock
        scales linearly with trace count — for 500K-1M+ campaigns,
        RAISE PARALLELISM in the shell script first)
   │
   ▼
You ─── confirm: every trace has 3 metadata_*.log files alongside it
   │
   ▼
[Orchestrator session — same or new]
   Phase 0.5: empty-criteria bootstrap pass (mechanical, ~no tokens)
              → builds loose `bootstrap_*` buckets from the difference
                summary table
   Phase 1: survey (subagent-delegated per Pattern P1; see ORCHESTRATOR.md)
   Phase 2: write/tighten bucket conditions
   Phase 2.5: self-audit granularity
   │
   ╞══► PAUSE: emits Auditor prompt for Audit 1
   │   └─► [Auditor — Gemini Pro 2.5, persistent tmux pane]
   │        edits # PENDING REVIEW → # AUDITED / # REVISION NEEDED
   │        writes <campaign>/audit/audit_1_verdict.md
   │
   ▼   you type `continue` in Orchestrator
   Phase 3: Security Gate (strict) + speculative paths (encouraged)
   │
   ╞══► PAUSE (only if [VULN] candidates exist): emits Auditor prompt for Audit 2
   │   └─► [same Auditor pane — context still warm from Audit 1]
   │        independently re-runs all 5 gates
   │        writes <campaign>/audit/audit_2_verdict.md
   │
   ▼   you type `continue` in Orchestrator
   Phase 4: bug reports, reproducers, BUCKET_LIST.md, SUMMARY_BUCKETS.md, CAMPAIGN_REPORT.md
   │        (all written inside <campaign>/)
   │
   ╞══► PAUSE: emits Auditor prompt for Audit 3
   │   └─► [same Auditor pane]
   │        cross-artifact consistency + global family pass
   │        writes <campaign>/audit/audit_3_verdict.md
   │
   ▼   you type `continue` in Orchestrator
Campaign complete: review <campaign>/BUCKET_LIST.md, <campaign>/SUMMARY_BUCKETS.md, <campaign>/CAMPAIGN_REPORT.md, <campaign>/BUGS/
```

---

## Fresh campaign — step-by-step

### Step 1: place traces

```bash
mkdir -p objective
cp /path/to/fuzzer/output/*.trace objective/
```

### Step 2: launch the Producer session  *(or just run the script yourself)*

**Recommended:** run the shell script directly. There's no decision-making in Phase 0:
```bash
./evaluation-ddyf/phase0_produce_metadata.sh
```

**Or, if you prefer the LLM-driven path:** open a Claude Haiku session with
```bash
claude --append-system-prompt "$(cat prompts-v3/PHASE0_DATA_PRODUCER.md)"
```
First user message: `"Run Phase 0. Produce metadata logs for every trace in objective/."`

The Producer will run `./evaluation-ddyf/phase0_produce_metadata.sh` and report when done.

**Verify** before continuing:
```bash
N=$(find objective -name "*.trace" | wc -l)
echo "Traces: $N"
echo "Diff logs: $(find objective -name 'metadata_diff_*.log' | wc -l) / $N"
```
All three counts (diff / openssl / libressl logs) must equal `N`.

### Step 3: launch the Orchestrator session

**Open a Claude Code session** (Sonnet 4.6, Pro plan) in a tmux pane. Launch with:

```bash
claude --append-system-prompt "$(cat prompts-v3/ORCHESTRATOR.md)"
```

`--append-system-prompt` (not `--system-prompt`) is important: it **appends** your instructions to Claude Code's default system prompt, preserving the built-in tool-use wiring (Read/Edit/Bash/etc.) that the v3 prompts assume. Using `--system-prompt` instead would replace Claude Code's defaults entirely and break tool calls.

First user message — pick **one** depending on your scenario:

**Fresh campaign launch** (traces placed, Phase 0 done, no prior triaging):

> Begin DDYF triaging campaign. Phase 0 metadata logs are in place. Start at Phase 1 per `prompts-v3/START_HERE.md`.

**Resume an interrupted campaign:** see "Continuing a triaging campaign already in progress" below — the resumption template includes the detection-command output and tells the Orchestrator exactly which phase to resume at.

The Orchestrator will then run Phases 1, 2, and 2.5, and at the end of Phase 2.5 will pause and give you a prompt to paste into an Auditor session.

### Step 4: first Auditor checkpoint (after Phase 2.5)

**This is the first time you touch the Auditor pane.** Launch the Auditor pane now if you haven't yet:

```bash
# Option A — Gemini CLI (preferred for the large context window)
gemini --prompt-interactive "$(cat prompts-v3/AUDITOR.md)"

# Option B — Claude Code as a fallback Auditor (Opus or Sonnet in a fresh session)
claude --append-system-prompt "$(cat prompts-v3/AUDITOR.md)"
```

`--prompt-interactive` sends the `AUDITOR.md` content as the first user message and then drops into the interactive chat. Gemini will treat that opening message as instructions for the rest of the conversation, which is exactly what we need (the system-prompt distinction matters less in Gemini than in Claude Code).

When the Orchestrator says something like:
> "Phase 2.5 complete. N buckets tagged `# PENDING REVIEW`. Paste the prompt below into the Auditor pane. When the Auditor returns to idle, type `continue` here."

The Orchestrator's prompt to paste into the Auditor will look like:

> "Run Audit 1 (granularity) on every `# PENDING REVIEW` bucket in `evaluation-ddyf/sort_objectives_ossl_libre.py`. Use the metadata logs in each `objective/<bucket>/` folder. For each bucket, edit its comment block to replace `# PENDING REVIEW` with either `# AUDITED` (passes all four granularity criteria) or `# REVISION NEEDED: <one-line reason>` (fails any criterion). Write a brief verdict summary to `<campaign>/audit/audit_1_verdict.md`."

**The full handoff procedure — exactly what you do at each turn:**

| # | Pane | Your action |
|---|---|---|
| 1 | Orchestrator | Copy the user message the Orchestrator told you to paste (everything between its quote marks). |
| 2 | Auditor | Paste it and press Enter. **Wait for the Auditor to finish.** Large audits can take minutes because it reads 60+ metadata files. The Auditor is done when it stops typing and the prompt returns idle. While it works, do NOT type "continue" in the Orchestrator pane — that would race the Auditor's writes. |
| 3 | Auditor | When the Auditor finishes, it will have edited the triaging script directly (audit tags) and written a verdict summary to `<campaign>/audit/audit_<N>_verdict.md`. Briefly skim its final chat reply to spot anything weird. |
| 4 | Orchestrator | Type `continue` (or anything that resumes it — e.g., "Audit 1 done, please proceed"). The Orchestrator re-reads the script + verdict file and acts on the audit results. |

**Why the protocol is simpler in v3 (with edit-capable Auditor):**
- The Auditor edits its own audit tag comments in `evaluation-ddyf/sort_objectives_ossl_libre.py` (limited write surface — only its tag comments and the verdict summary file; nothing else).
- The verdict survives in git history as a real artifact, not just chat text.
- You no longer have to copy-paste the verdict — the file system carries it.

**Race-condition rule (must obey):** The Orchestrator must be paused (waiting for your input) the entire time the Auditor is working. Do not type "continue" or any message into the Orchestrator pane until the Auditor has finished and returned to idle. This is the one constraint that makes the constrained-write design safe.

**Fallback to read-only audit:** if you want to review the verdict before it lands in any file (e.g., a particularly sensitive audit, or you want a paper-trail in the chat history), tell the Auditor `"Verdict only, no edits"` at the start of its prompt. It will print the full verdict in chat instead of editing files, and you copy-paste it to the Orchestrator like the old v3 flow. Either mode works.

**If anything else goes wrong:** type `git status` in any pane to see what was actually written; `git diff` to inspect changes. The constrained write surface (audit tag comments + `<campaign>/audit/audit_<N>_verdict.md`) means the blast radius of any Auditor mistake is small and easy to revert.

### Step 5: Security Gate Auditor checkpoint (only if any VULN candidates)

If Phase 3 produces any `[VULN]` candidate, the Orchestrator pauses and gives you a follow-up user message to send to the **same Auditor pane** (no re-launching — the persistent session already has the AUDITOR.md instructions loaded).

Same handoff loop as Step 4 (now simpler with the constrained-write Auditor):
1. Copy the Orchestrator's prompt → paste into Auditor pane → wait for Auditor to finish writing tags + `<campaign>/audit/audit_2_verdict.md`.
2. When the Auditor returns to idle, type `continue` (or "Audit 2 done") in the Orchestrator pane.

The Auditor will have already loaded the triaging script and metadata files during Audit 1, so this audit is fast.

If there are no VULN candidates, this step is skipped automatically by the Orchestrator.

### Step 6: reports, reproducers, summary

The Orchestrator writes everything inside the campaign folder (e.g., `triaging-openssl-libressl-05-18/`):
- `<campaign>/BUGS/*.md` (one per root cause)
- `<campaign>/BUGS/reproduce_*.py` (one per report, following `REPRODUCER_TEMPLATE.md`)
- `<campaign>/BUCKET_LIST.md` *(dedicated flat bucket list — name, CVE/RFC/BENIGN status, trace count)*
- `<campaign>/SUMMARY_BUCKETS.md` (full summary with links and one-liners)
- `<campaign>/CAMPAIGN_REPORT.md`
- `<campaign>/sort_objectives_<p1>_<p2>.py` *(archival snapshot of the finalized triaging script)*

At the end, it pauses and gives you a third follow-up prompt for the **same Auditor pane** — the cross-artifact consistency audit. Same simplified handoff: copy Orchestrator's prompt → paste into Auditor → wait → type `continue` in Orchestrator. The Auditor's loaded context from Audits 1 and 2 makes this audit cheap. (During Audit 3 the Auditor writes only `<campaign>/audit/audit_3_verdict.md` — it does not edit files in `<campaign>/BUGS/`, `<campaign>/CAMPAIGN_REPORT.md`, or `<campaign>/SUMMARY_BUCKETS.md`; those belong to the Orchestrator.)

### Step 7: review the final artifacts

After the third Auditor pass, the Orchestrator presents the final state. You review:
- `<campaign>/BUCKET_LIST.md` for the at-a-glance status of every bucket
- `<campaign>/SUMMARY_BUCKETS.md` for the full summary table with bug-report links
- `<campaign>/CAMPAIGN_REPORT.md` for the complete report
- `<campaign>/BUGS/` for the per-bug detail

That's the deliverable.

---

## Determining campaign state on launch

Before deciding which phase to start at, run the detection commands below (see "Continuing a triaging campaign already in progress") and read the output. Based on what's already on disk:

- **Empty `objective/`** → fresh campaign, start at Phase 0.
- **Traces present, no metadata logs** → fresh campaign with Phase 0 missing.
- **Traces present, metadata logs present, no buckets defined in the triaging script** → resume at Phase 1.
- **Buckets defined, all `# AUDITED`, no `BUGS/`** → resume at Phase 4.
- **Buckets defined, some `# PENDING REVIEW` or `# REVISION NEEDED`** → resume at Phase 2.5.
- **Full prior campaign present** (buckets, BUGS, CAMPAIGN_REPORT) → the user is most likely running an upgrade pass against newer prompt standards. Confirm with the user before overwriting anything; their first message should make the intent explicit.

If starting a **fresh campaign** on a repo that contains prior work, nothing needs to be moved aside: each campaign produces its own dated folder (`triaging-<put1>-<put2>-MM-DD/`). The v3 pipeline writes to that folder and to `objective/` (traces + metadata logs) and `evaluation-ddyf/sort_objectives_ossl_libre.py` (triaging script). If two campaigns run on the same day, rename the existing folder before starting the second one (e.g., append `-v2`).

---

## Continuing a triaging campaign already in progress

If a previous campaign was started but not finished (e.g., the Orchestrator session ran out of tokens, or you stopped mid-way), restart with a different opening message.

### Detecting where you are

Run these commands from the repo root and read the output:

```bash
# Are metadata logs in place?
echo "metadata-logs: $(find objective -name 'metadata_diff_*.log' | wc -l) of $(find objective -name '*.trace' | wc -l)"

# Are buckets defined?
grep -c '^\s*"[^"]*/":' evaluation-ddyf/sort_objectives_ossl_libre.py || echo "no buckets defined"

# How many buckets have been audited?
grep -c "# AUDITED" evaluation-ddyf/sort_objectives_ossl_libre.py || echo "0 audited"
grep -c "# PENDING REVIEW" evaluation-ddyf/sort_objectives_ossl_libre.py || echo "0 pending"
grep -c "# REVISION NEEDED" evaluation-ddyf/sort_objectives_ossl_libre.py || echo "0 revisions"

# Find the campaign folder — use the computed name (robust to multiple triaging-* folders)
CAMPAIGN=$(python3 -c "
import re, datetime, os, sys
try:
    s = open('evaluation-ddyf/sort_objectives_ossl_libre.py').read()
    p1 = re.sub(r'\d+','', re.search(r'FIRST_PUT\s*=\s*\"(\w+)\"',s).group(1))
    p2 = re.sub(r'\d+','', re.search(r'SECOND_PUT\s*=\s*\"(\w+)\"',s).group(1))
    name = f'triaging-{p1}-{p2}-{datetime.date.today().strftime(\"%m-%d\")}/'
    print(name if os.path.isdir(name) else '')
except: print('')" 2>/dev/null)
# Fallback: if today's folder doesn't exist, list all triaging-* folders for the user to pick
if [ -z "$CAMPAIGN" ]; then
  existing=$(ls -d triaging-*/ 2>/dev/null)
  if [ -n "$existing" ]; then
    echo "No campaign folder for today. Existing folders: $existing"
    echo "Set CAMPAIGN manually, e.g.: CAMPAIGN=triaging-openssl-libressl-04-28/"
  fi
fi
echo "Campaign folder: ${CAMPAIGN:-(none)}"

# Have any bug reports been written?
ls "${CAMPAIGN}BUGS/"*.md 2>/dev/null | wc -l
ls "${CAMPAIGN}BUGS/"reproduce_*.py 2>/dev/null | wc -l

# Are summary artifacts present?
test -f "${CAMPAIGN}BUCKET_LIST.md" && echo "BUCKET_LIST.md present" || echo "BUCKET_LIST.md missing"
test -f "${CAMPAIGN}SUMMARY_BUCKETS.md" && echo "SUMMARY_BUCKETS.md present" || echo "SUMMARY_BUCKETS.md missing"
test -f "${CAMPAIGN}CAMPAIGN_REPORT.md" && echo "CAMPAIGN_REPORT.md present" || echo "CAMPAIGN_REPORT.md missing"
```

### Decide which phase to resume from

The "First Orchestrator message" column gives the verbatim text to paste as the resumption template's "Specific instruction" line (see Resuming — Orchestrator launch below).

| What you find | Resume at | Specific instruction |
|---|---|---|
| No metadata logs in `objective/` | (do Phase 0 first — not via Orchestrator) | Run `./evaluation-ddyf/phase0_produce_metadata.sh` yourself, then resume with "Phase 0 done. Begin Phase 1 (survey)." |
| Metadata logs present, no buckets defined in the triaging script | Phase 1 | "Phase 0 done. Begin Phase 1 (survey)." |
| Buckets defined, some still `# PENDING REVIEW` (no `# AUDITED` yet) | Phase 2.5 | "Phases 1–2 done. Run Phase 2.5 (granularity self-audit) on every `# PENDING REVIEW` bucket." |
| `# REVISION NEEDED` comments present in script | Apply revisions, then re-audit | "Resolve all `# REVISION NEEDED` comments in the triaging script, then re-run Phase 2.5 and request Audit 1 again." |
| All buckets `# AUDITED`, `<campaign>/audit/audit_1_verdict.md` exists, no `<campaign>/BUGS/*.md` | Phase 3 then Phase 4 | "Audit 1 complete. Run Phase 3 Security Gate on any VULN candidates, then Phase 4 (bug reports + reproducers + SUMMARY)." |
| `<campaign>/BUGS/*.md` exist, no `<campaign>/BUCKET_LIST.md` | Phase 4c & 4d | "Reports written. Generate `BUCKET_LIST.md`, `SUMMARY_BUCKETS.md` and `CAMPAIGN_REPORT.md` inside the campaign folder, then request the consistency Audit (Audit 3)." |
| Everything written but no `<campaign>/audit/audit_3_verdict.md` | Audit 3 only | "Phase 4 complete. Request the final consistency audit (Audit 3) — emit the Auditor prompt." |

### Resuming — Orchestrator launch

Launch the Orchestrator pane:
```bash
claude --append-system-prompt "$(cat prompts-v3/ORCHESTRATOR.md)"
```

First user message:

> Resume DDYF triaging campaign already in progress.
>
> Current state (verbatim output of the detection commands from `START_HERE.md` "Continuing a triaging campaign already in progress"):
> ```
> [paste the output here]
> ```
>
> Resume at: [one of the phases from the table above]
>
> Specific instruction: [the row's "First Orchestrator message" verbatim]

The Orchestrator will read the current state, verify it matches what you describe, and continue from that point. It will pause at the same checkpoints (Auditor invocations) as in a fresh campaign.

### Handling mid-Audit interruptions

If a previous Auditor session was running when interrupted: simply restart that Auditor (Step 4 procedure). Auditor passes are idempotent — running them again on the same triaging script produces the same audit comments. The Orchestrator does not need to know that a previous Auditor was interrupted.

---

## Quick reference — what each session needs

| Session | System prompt file | Main role | Token cost |
|---|---|---|---|
| Producer | `prompts-v3/PHASE0_DATA_PRODUCER.md` | Run the Phase 0 shell script. Verify counts. | Low (Haiku) |
| Orchestrator | `prompts-v3/ORCHESTRATOR.md` | Drives Phases 1–4. Pauses for Auditor checkpoints. | Medium-high (Sonnet Pro) |
| Auditor | `prompts-v3/AUDITOR.md` | Three independent audit passes (granularity, VULN, consistency). | Medium (Gemini Pro / Opus) |

---

## Files in `prompts-v3/`

| File | Purpose |
|---|---|
| `START_HERE.md` | **You are here.** Driver for the whole pipeline. |
| `ORCHESTRATOR.md` | Lead engineer prompt (system prompt for the Orchestrator session). |
| `AUDITOR.md` | Reviewer prompt (multi-pass; system prompt for the Auditor session). |
| `PHASE0_DATA_PRODUCER.md` | Phase 0 producer prompt (system prompt for the Producer session, if used). |
| `BUCKET_GRANULARITY.md` | Hard criteria each bucket must satisfy. |
| `SECURITY_GATE.md` | 5-question discipline for `[VULN]` tag + speculative-paths guidance. |
| `CVSS_TLS.md` | TLS-specific CVSS guidance and traps. |
| `BUG_REPORT_TEMPLATE.md` | Structure for every `BUGS/*.md`. |
| `REPRODUCER_TEMPLATE.md` | Strict template for `BUGS/reproduce_*.py`. |
| `SUMMARY_BUCKETS_TEMPLATE.md` | Structure for the campaign-wide bucket summary. |
| `NAMING_CONVENTIONS.md` | Naming rules + cross-artifact consistency. |
| `DIFF_OUTPUT_REFERENCE.md` | Reference card for tlspuffin output, including common pitfalls when reading metadata logs. |
| `INVESTIGATION_PROMPT_TEMPLATE.md` | Template for delegating targeted source-code investigations to a separate LLM session. |
| `README.md` | High-level overview (this is for documentation; `START_HERE.md` is for execution). |

---

## When to deviate from this pipeline

- **Skip Phase 0** if metadata logs are already present and the trace set hasn't changed.
- **Skip Phase 1** if you have a previous campaign's bucket map you want to reuse — but you must still run Phase 2.5 to verify granularity.
- **Skip Phase 3** if no bucket has a Finished claim in any trace (the data shows zero CVE candidates).
- **Never skip Phase 2.5** — granularity is what distinguishes a useful campaign from a wall of unactionable buckets.
- **Never skip the cross-artifact audit** at the end of Phase 4 — naming drift between buckets, reports, and reproducers is the most common silent failure.
