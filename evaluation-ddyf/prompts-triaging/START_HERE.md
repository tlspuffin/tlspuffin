# START HERE — User Entry Point

This is the single file you give to your main LLM session to launch a DDYF triaging campaign. The Orchestrator reads this file, follows it step-by-step, and tells you exactly when to spawn auxiliary sessions (Auditor, Phase-0 data producer) and with which prompt.

You only have to do four things manually:
1. Place traces in `./objective/`.
2. Run Phase 0 (metadata generation) — see Step 2 below. This is just a shell script — run it yourself (no LLM needed), or optionally delegate it to a cheap one-shot Producer session that only runs the script and verifies counts (Step 2).
3. Launch the **Orchestrator** session (Step 3). Its first user message is one of:
   - **Fresh campaign:** `"Begin DDYF triaging campaign. Phase 0 metadata logs are in place. Start at Phase 0.5 (bootstrap) per prompts-triaging/START_HERE.md."` *(Phase 0.5 is a new, token-cheap, mechanical bootstrap pass that creates a loose first-cut bucket scaffold by running the triaging script with empty buckets. It sits between Phase 0 and Phase 1. See `PHASE_0_5_BOOTSTRAP.md`.)*
   - **Incremental re-run** (new objectives appended to an existing campaign): `"Resume DDYF triaging campaign in incremental mode. New objectives placed; Phase 0 metadata generated for them. Detect incremental mode per ORCHESTRATOR.md Launch-time preconditions and run the Phase 0.5 incremental re-run."`
   - **Resume after stop:** see "Continuing a triaging campaign already in progress" below for the resumption template.
4. When the Orchestrator pauses at an Auditor checkpoint, type the two constant mailbox triggers — `do your mailbox` in the Auditor pane, then `continue` in the Orchestrator pane (Step 4).

The Orchestrator handles all coordination between checkpoints. You are the human-in-the-loop only at the explicit Auditor checkpoints below.

---

## Protocol configuration

This prompt set is **protocol-agnostic**. The workflow (Phase 0 → survey → buckets → granularity → security gate → reports) is identical for any two implementations of any protocol; only a handful of names change. Throughout the prompts, **TLS (OpenSSL vs LibreSSL) is used as the running worked example** — wherever you see the concrete names below, substitute your protocol's values.

| Placeholder | Meaning | TLS (worked example) | SSH (this repo) |
|---|---|---|---|
| `<puffin>` | fuzzer binary | `target/release/tlspuffin` | `target/release/sshpuffin` |
| `<put1>` / `<put2>` | the two implementations under test | `openssl340` / `libressl421` | `libssh0114` / `wolfssh150` |
| `<triaging_script>` | protocol's bucket-sorting script | `tls/sort_objectives_ossl_libre.py` | `ssh/sort_objectives_libssh_wolfssh.py` |
| `<metadata_prefix>` | Phase-0 per-PUT log prefix | `metadata_openssl340_` / `metadata_libressl421_` | `metadata_libssh0114_` / `metadata_wolfssh150_` |
| `<proto>/SECURITY_GATE_<proto>.md` | per-protocol security gate | `tls/SECURITY_GATE_TLS.md` | `ssh/SECURITY_GATE_SSH.md` |
| security spec | the normative reference | TLS 1.2/1.3 RFCs | RFC 4251–4254, 8308, 8332 |

The per-protocol triaging scripts live under `evaluation-ddyf/<proto>/`; the shared engine
(`diff_analyzer.py`), the parametric Phase-0 producer (`phase0_produce_metadata.sh`), and this
prompt set are protocol-independent. The `SECURITY_GATE_<proto>.md` and `CVSS_<proto>.md` files
are deliberately protocol-specific (one pair per protocol, under `tls/` and `ssh/`); everything
else is shared.

**SSH security gate:** `ssh/SECURITY_GATE_SSH.md` and `ssh/CVSS_SSH.md` exist, so an SSH
campaign runs the full `[VULN]` / `[RFC]` / `[BENIGN]` track and the Phase-3 strict gate /
Audit 2, exactly like TLS. The SSH gate adds one protocol-specific check the TLS gate does not
need — a **harness-vs-library** step (Gate 0) that distinguishes a real auth-state divergence
from a claim-oracle artefact, because sshpuffin's oracle is claim-based and a harness callback
can emit a claim before the library's own crypto verification runs. Most SSH differential
findings are RFC-conformance divergences (CVSS 0.0); the gate is what lets you demonstrate that
rather than assert it.

---

## Pre-requisites

These are environmental things to confirm before kicking off the first new campaign, not changes to the prompts themselves:

  1. Tooling sanity check. gh auth status, python3 -c "import cryptography", ls vendor/<lib>/lib/libssl.a vendor/<lib>/lib/libcrypto.a — confirm GH CLI authed (the maintainer-history check uses it), pyca/cryptography is installed (some PoC scripts need it), and the vendor static libs are built (the C harnesses in reproduce_*_full.py link against them).
  2. AGY and Claude CLI installed and ready to use. 
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
| **Auditor — primary (AGY pane)** | AGY CLI in tmux | Persistent through campaign | Large context (~1M tokens) holds the entire triaging script + 60+ metadata files + cited RFCs + cited source files simultaneously. Separate token budget from Claude Pro. Used for ALL three standard checkpoints (Audit 1 / 2 / 3). |
| **Auditor — deep (Opus pane)** | Claude Opus 4.7 high effort, Claude Code CLI in tmux | On-demand, launched when a parallel deep audit is needed | Deep structural reasoning on state machines, conservative refutation walks. Used in parallel with the AGY pane for `[VULN]` candidates, CVE-candidate promotions, compound-attack refutations. See `ORCHESTRATOR.md` § "Parallel deep audits". |

> **AGY** = the agentic-mode CLI of Gemini (the large-context Auditor pane). It is used
> for the routine audit checkpoints on its own token budget, and paired with an Opus pane
> for high-stakes parallel audits. Swap in any large-context agentic CLI; the role, not the
> vendor, is what matters.

**The persistence point matters.** Because both Auditor sessions live in tmux for the whole campaign (or for the duration of a deep-audit thread), the audit checkpoints become messages to the *same* session — context loaded for one audit is still warm for the next. Auditors do not re-read the script or the metadata files three separate times.

**The parallel-audit point matters too.** For high-stakes findings (anything being promoted to §1/§2 of `SUMMARY_BUCKETS.md`, anything tagged `[VULN]`, any speculative path refutation that materially changes the disclosure framing), running both AGY AND Opus in parallel on the same audit produces two tagged verdict files (`mailbox/from_auditor/audit_N_agy.md` and `mailbox/from_auditor/audit_N_opus.md`). The Orchestrator synthesises both, flags discrepancies, and writes `mailbox/from_auditor/audit_N_synthesis.md`. This catches reasoning gaps that any single model misses — see the Path-4 refutation in `BUGS/libressl_wrong_cipher_acceptance.md` for a worked example.

**Handoff (filesystem mailbox — no copy-paste courier).** The two panes communicate through a filesystem mailbox instead of you pasting prompts between them:

- `<campaign>/mailbox/to_auditor/audit_<N>.md` — the Orchestrator **writes** each audit request here (the task, the bucket list, the exact instructions). You never copy it.
- `<campaign>/mailbox/from_auditor/audit_<N>_verdict.md` — the Auditor **writes** its verdict here (and still edits the audit tag comments in `<triaging_script>` directly).

Per checkpoint you type just **two constant triggers** — never variable pasted content:
1. **`do your mailbox`** in the **Auditor (AGY) pane** — the Auditor reads the newest unhandled request in `to_auditor/`, does the work, writes its verdict to `from_auditor/`, and returns to idle.
2. **`continue`** in the **Orchestrator pane** — once the Auditor is idle. The Orchestrator reads the verdict file and proceeds.

This keeps the Auditor on its **separate token budget** (AGY stays its own process) and keeps the **human milestone gate** (nothing advances until you type the two triggers), while removing both the copy-paste courier and the race-by-convention. **Race-condition rule (unchanged):** the Orchestrator must stay paused the whole time the Auditor is working — do not type `continue` until the Auditor is idle. A "verdict only, no edits" fallback (chat-text verdict, no file writes) is still available — see Step 4.

**Recovery from a lost Auditor session** (crash, hard token limit, closed pane — most likely on Large/Extra-large campaigns): the mailbox makes audits **replayable** — the request survives in `${CAMPAIGN}/mailbox/to_auditor/audit_<N>.md` and any partial verdict in `from_auditor/`. Just **re-launch the Auditor pane** (same `agy …`/`claude …` command) and type **`do your mailbox`** again; it re-reads the newest unhandled request and re-does the audit from scratch (audits are idempotent — re-running overwrites the same tag comments + verdict file). No campaign state is lost, because the durable state lives on disk (the script's tags + `${CAMPAIGN}/mailbox/` + `.classified_traces.txt`), not in the Auditor's context window.

**Autonomous mode (single continuous session, no human-typed triggers).** The two-trigger
loop above assumes a human is present to type `do your mailbox` / `continue` at each
checkpoint. For long unattended campaigns (multi-hour/day) you can instead run the Auditor as
an **autonomous polling session**: at launch, append to its opening prompt something like *"You
are now autonomous. Re-check `<campaign>/mailbox/to_auditor/` regularly and respond when there
is a new unhandled request; recheck every ~10 minutes."* The Auditor then loops on its own —
no human triggers needed — and this has been used successfully end-to-end. Rules that keep it
safe and unchanged:
- **The mailbox is still the synchroniser.** The Auditor acts only on a *new, unhandled*
  request (an `audit_<N>.md` in `to_auditor/` with no matching `from_auditor/audit_<N>_verdict.md`).
  A poll that finds nothing new is a no-op — it must not re-audit already-handled requests.
- **Empty mailbox on the first poll is normal, not an error** — the Orchestrator may not have
  written the first request yet. Stand by and poll again next interval; do not improvise work.
- **The race-condition rule is unchanged:** the Orchestrator must be paused while the Auditor
  writes. In autonomous mode the Orchestrator enforces this by not proceeding past a checkpoint
  until the verdict file exists (it polls `from_auditor/` the same way). A ~10-minute cadence on
  both sides keeps them from writing the triaging script at the same instant.
- **Pick the cadence to the campaign:** ~10 min is a good default; shorter wastes tokens on
  empty polls, much longer stalls the pipeline.

**Token economics rationale:** Claude Pro has a fixed weekly token budget. Audit passes are token-heavy (reading many large files in one context) but compute-light (mostly verification, not synthesis). Pushing audits to AGY (different budget) leaves Orchestrator tokens for the work only Sonnet can do well: iterating on bucket conditions, writing reports, debugging reproducers.

---

## What to expect — campaign size, timing, and tokens

Before launching the Orchestrator, the campaign falls into one of five size bands. The first thing the Orchestrator does on launch is emit a **pre-analysis report** that tells you which band you're in and what to expect. You can also estimate it yourself from the trace count.

> **These bands are ESTIMATES, not measured.** The token-budget and wall-clock columns
> below are order-of-magnitude planning figures, not benchmarks — treat them as such. The
> one **measured** anchor to date (SSH, 2026-09-17): a clean 29-core differential campaign
> produced **511,060 objectives** in ~27 min of fuzzing (**not** the Phase-0 metadata step),
> and the offline triage characterised the corpus from a **10k random sample** (minutes) plus
> a 25k decryption scan and a 30k audit sweep — i.e. at ≥0.5M objectives the triage is driven
> by *sampling*, not by re-executing every trace. Replace a band's figures with real numbers
> whenever you have them.
>
> **On triage parallelism (read before trusting the LLM-phase wall-clock).**
> `SSHPUFFIN_TRIAGE_PARALLELISM` (default 24) sizes the classifier's `ThreadPool`, and it
> **is** wired through to the pool. But `ps` will typically show only a *handful* of
> concurrent `sshpuffin` subprocesses even at `=60` — this is expected, not a bug: each
> per-trace `differential-execute` is short, so the instantaneous count is low even though
> throughput scales with the pool. **More importantly, after Phase 0 the classifier reads the
> pre-baked `metadata_diff_T.json` cache and spawns _no_ subprocess per trace at all** (see
> `ORCHESTRATOR.md` Phase 0 / `diff_analyzer.py get_diff()`), so triage is I/O- and
> JSON-parse-bound, not exec-bound. Treat the LLM-phase wall-clock column as optimistic
> order-of-magnitude planning only; do not size a campaign assuming N× subprocess speed-up
> from a big `PARALLELISM`.

| Size band | Traces | Expected buckets | Total token budget | Phase 0 wall-clock (`PARALLELISM=20`) | LLM-phase wall-clock | Session lifecycle |
|---|---|---|---|---|---|---|
| **Small** | <500 | <20 | <500K | ~1 min | <2 h | 1 Orchestrator session total |
| **Medium** | 500-5,000 | 20-50 | 1-3M | ~10 min | 2-12 h | 1 Orchestrator session typical |
| **Large** | 5,000-50,000 | 50-80 | 3-8M | ~40 min – 1.5 h | 12 h - 2 d | Phase-bounded (4-7 Orchestrator sessions) |
| **Very large** | 50,000-500,000 | ~80-100 | 7-12M | 1.5 h - 18 h | 2-6 d | Phase-bounded (7 sessions; mandatory) |
| **Extra large** | 500,000-2M | ~80-100 | 10-20M | 18 h - 70 h **at PARALLELISM=20** | 1-3 weeks | Phase-bounded (7+ sessions; mandatory); raise PARALLELISM ≥80 or distribute across hosts |

**Phase 0 wall-clock dominates for the Extra-large band.** At 1M traces with default PARALLELISM=20, Phase 0 alone takes ~35 hours of pure shell I/O. Mitigations are documented in `ORCHESTRATOR.md` § "Extra-large campaign caveats" — the short version: raise PARALLELISM in `phase0_produce_metadata.sh` to 80+ on a beefy host (or distribute the script across hosts), and confirm you have ~30 GB disk headroom and enough inodes for the metadata logs.

**The Orchestrator emits the pre-analysis BEFORE running Phase 0**, so you can interrupt and reconsider if the size band doesn't match what you intended (e.g., you ran the fuzzer for longer than expected and ended up with 5× more traces than the campaign was scoped for).

**You will see a heads-up if size band ≥ Large.** The Orchestrator will use phase-bounded sessions (one Claude Code session per natural phase boundary), emit explicit handoff messages, and route bulk reads to the AGY Auditor pane. You don't need to do anything different — just type `continue` between sessions as instructed.

For Extra-large campaigns, you'll also see budget pacing notes (a 1M-trace campaign can consume a full weekly Claude Pro budget) and a recommendation to schedule the campaign across calendar days rather than trying to land it in one block.

---

## Campaign folder

Every campaign's output artifacts are isolated in a single dated folder at the repo root:

```
triaging-<put1>-<put2>-MM-DD/
├── BUGS/                            ← bug reports (*.md) and reproducers (reproduce_*.py)
├── mailbox/from_auditor/                           ← audit verdict files (audit_N_verdict.md)
├── sort_objectives_<p1>_<p2>.py     ← snapshot of the finalized triaging script
├── BUCKET_LIST.md                   ← dedicated bucket list: name, CVE/RFC/BENIGN status, count
├── SUMMARY_BUCKETS.md               ← full summary table with bug-report links and one-liners
└── CAMPAIGN_REPORT.md               ← complete campaign report
```

**Naming rule:** strip all digits from each PUT name and append today's date as `MM-DD`.
Examples: `openssl340` + `libressl421` launched on May 18 → `triaging-openssl-libressl-05-18`.

The Orchestrator computes the name on launch (protocol-agnostic — resolves the triaging script
by glob, so it runs as-is for TLS or SSH):
```bash
TRIAGING_SCRIPT="${TRIAGING_SCRIPT:-$(ls evaluation-ddyf/*/sort_objectives_*.py evaluation-ddyf/sort_objectives_*.py 2>/dev/null | head -1)}"
TRIAGING_SCRIPT="$TRIAGING_SCRIPT" python3 -c "
import re, datetime, os
s = open(os.environ['TRIAGING_SCRIPT']).read().splitlines()
# Last quoted token on the FIRST_PUT/SECOND_PUT line — handles both the plain form
# (FIRST_PUT = \"openssl340\") and the env form (os.environ.get(\"...\", \"libssh0114\")).
def put(tag):
    line = next(l for l in s if re.match(r'\s*'+tag+r'\s*=', l))
    return re.sub(r'\d+','', re.findall(r'\"([^\"]+)\"', line)[-1])
print(f'triaging-{put(\"FIRST_PUT\")}-{put(\"SECOND_PUT\")}-{datetime.date.today().strftime(\"%m-%d\")}')"
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
   │   └─► [Auditor — AGY, persistent tmux pane]
   │        deletes # PENDING REVIEW, appends # AUDITED [AUDITOR] / # REVISION NEEDED [AUDITOR]
   │        writes <campaign>/mailbox/from_auditor/audit_1_verdict.md
   │
   ▼   you type `continue` in Orchestrator
   Phase 3: Security Gate (strict) + speculative paths (encouraged)
   │
   ╞══► PAUSE (only if [VULN] candidates exist): emits Auditor prompt for Audit 2
   │   └─► [same Auditor pane — context still warm from Audit 1]
   │        independently re-runs all 5 gates
   │        writes <campaign>/mailbox/from_auditor/audit_2_verdict.md
   │
   ▼   you type `continue` in Orchestrator
   Phase 4: bug reports, reproducers, BUCKET_LIST.md, SUMMARY_BUCKETS.md, CAMPAIGN_REPORT.md
   │        (all written inside <campaign>/)
   │
   ╞══► PAUSE: emits Auditor prompt for Audit 3
   │   └─► [same Auditor pane]
   │        cross-artifact consistency + global family pass
   │        writes <campaign>/mailbox/from_auditor/audit_3_verdict.md
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
claude --append-system-prompt "$(cat prompts-triaging/PHASE0_DATA_PRODUCER.md)"
```
First user message: `"Run Phase 0. Produce metadata logs for every trace in objective/."`

The Producer will run `./evaluation-ddyf/phase0_produce_metadata.sh` and report when done.

**Verify** before continuing:
```bash
N=$(find objective -name "*.trace" -not -name ".*" | wc -l)   # -not -name ".*" skips LibAFL hidden sidecars
echo "Traces: $N"
echo "Diff logs: $(find objective -name 'metadata_diff_*.log' | wc -l) / $N"
```
All three counts (diff / openssl / libressl logs) must equal `N`.

### Step 3: launch the Orchestrator session

**Open a Claude Code session** (Sonnet 4.6, Pro plan) in a tmux pane. Launch with:

```bash
claude --append-system-prompt "$(cat prompts-triaging/ORCHESTRATOR.md)"
```

`--append-system-prompt` (not `--system-prompt`) is important: it **appends** your instructions to Claude Code's default system prompt, preserving the built-in tool-use wiring (Read/Edit/Bash/etc.) that the v3 prompts assume. Using `--system-prompt` instead would replace Claude Code's defaults entirely and break tool calls.

First user message — pick **one** depending on your scenario:

**Fresh campaign launch** (traces placed, Phase 0 done, no prior triaging):

> Begin DDYF triaging campaign. Phase 0 metadata logs are in place. Start at Phase 0.5 (bootstrap) per `prompts-triaging/START_HERE.md`.

(Phase 0.5 runs the triaging script with empty buckets to build the loose bucket scaffold mechanically; Phase 1 then tightens it. Only skip straight to Phase 1 for a corpus < 200 traces — see `PHASE_0_5_BOOTSTRAP.md` § "When this phase can be skipped".)

**Resume an interrupted campaign:** see "Continuing a triaging campaign already in progress" below — the resumption template includes the detection-command output and tells the Orchestrator exactly which phase to resume at.

The Orchestrator will then run Phases 1, 2, and 2.5, and at the end of Phase 2.5 will pause, write the audit request to the mailbox, and tell you the two triggers to run the first Auditor checkpoint.

### Step 4: first Auditor checkpoint (after Phase 2.5)

**This is the first time you touch the Auditor pane.** Launch the Auditor pane now if you haven't yet:

```bash
# Option A — AGY CLI (preferred for the large context window)
agy --dangerously-skip-permissions --prompt-interactive "$(cat prompts-triaging/AUDITOR.md)"

# Option B — Claude Code as a fallback Auditor (Opus or Sonnet in a fresh session)
claude --append-system-prompt "$(cat prompts-triaging/AUDITOR.md)"
```

`--prompt-interactive` sends the `AUDITOR.md` content as the first user message and then drops into the interactive chat. AGY will treat that opening message as instructions for the rest of the conversation, which is exactly what we need (the system-prompt distinction matters less in AGY than in Claude Code).

When the Orchestrator reaches the checkpoint it will say something like:
> "Phase 2.5 complete. N buckets tagged `# PENDING REVIEW`. Audit request written to `<campaign>/mailbox/to_auditor/audit_1.md`. Type `do your mailbox` in the Auditor pane; when it returns to idle, type `continue` here."

The Orchestrator has already **written** the request to `<campaign>/mailbox/to_auditor/audit_1.md` (you do not see or copy it). It contains the task, e.g.:

> "Run Audit 1 (granularity) on every `# PENDING REVIEW` bucket in `<triaging_script>`. Use the metadata logs in each `objective/<bucket>/` folder. For each bucket, leave the `# GRANULARITY AUDITED [ORCHESTRATOR]` block untouched, delete its `# PENDING REVIEW` line, and append a single-line `# AUDITED [AUDITOR]: <one-line>` (passes all four granularity criteria) or `# REVISION NEEDED [AUDITOR]: <one-line reason>` (fails any criterion). Write a brief verdict summary to `<campaign>/mailbox/from_auditor/audit_1_verdict.md`, ending with `No # PENDING REVIEW tags remain: yes/no`."

**The full handoff procedure — exactly what you do at each turn:**

| # | Pane | Your action |
|---|---|---|
| 1 | Auditor | Type the constant trigger **`do your mailbox`** and press Enter. The Auditor reads the newest unhandled request in `<campaign>/mailbox/to_auditor/`, then works. **Wait for it to finish** — large audits take minutes (it reads 60+ metadata files); it is done when it stops typing and the prompt returns idle. While it works, do NOT type into the Orchestrator pane — that would race the Auditor's writes. |
| 2 | Auditor | When the Auditor finishes, it will have edited the triaging script directly (audit tags) and written its verdict to `<campaign>/mailbox/from_auditor/audit_<N>_verdict.md`. Briefly skim its final chat reply to spot anything weird. |
| 3 | Orchestrator | Type the constant trigger **`continue`**. The Orchestrator reads the verdict file + the re-tagged script and acts on the audit results. |

**Why the protocol is simple (mailbox + edit-capable Auditor):**
- You type only two **constant** strings per checkpoint (`do your mailbox`, `continue`) — no variable content is ever copied between panes.
- The Auditor edits its own audit tag comments in `<triaging_script>` (limited write surface — only its tag comments and the `from_auditor/` verdict file; nothing else).
- Request and verdict both survive in git history as real artifacts under `<campaign>/mailbox/`, not just chat text.

**Race-condition rule (must obey):** The Orchestrator must be paused (waiting for your input) the entire time the Auditor is working. Do not type `continue` into the Orchestrator pane until the Auditor has finished and returned to idle. This is the one constraint that makes the constrained-write design safe.

**Fallback to read-only audit:** if you want to review the verdict before it lands in any file (e.g., a particularly sensitive audit, or you want a paper-trail in the chat history), tell the Auditor `"Verdict only, no edits"` at the start of its prompt. It will print the full verdict in chat instead of editing files, and you copy-paste it to the Orchestrator like the old v3 flow. Either mode works.

**If anything else goes wrong:** type `git status` in any pane to see what was actually written; `git diff` to inspect changes. The constrained write surface (audit tag comments + `<campaign>/mailbox/from_auditor/audit_<N>_verdict.md`) means the blast radius of any Auditor mistake is small and easy to revert.

### Step 5: Security Gate Auditor checkpoint (only if any VULN candidates)

If Phase 3 produces any `[VULN]` candidate, the Orchestrator pauses and writes the Audit-2 request to the mailbox for the **same Auditor pane** (no re-launching — the persistent session already has the AUDITOR.md instructions loaded).

Same two-trigger mailbox loop as Step 4:
1. Type `do your mailbox` in the Auditor pane → wait for it to finish writing tags + `<campaign>/mailbox/from_auditor/audit_2_verdict.md`.
2. When the Auditor returns to idle, type `continue` (or "Audit 2 done") in the Orchestrator pane.

The Auditor will have already loaded the triaging script and metadata files during Audit 1, so this audit is fast.

If there are no VULN candidates, this step is skipped automatically by the Orchestrator.

### Step 6: reports, reproducers, summary

The Orchestrator writes everything inside the campaign folder (e.g., `triaging-openssl-libressl-05-18/`):
- `<campaign>/BUGS/*.md` (one per root cause)
- `<campaign>/BUGS/reproduce_*.py` (one per report, following `TEMPLATES.md` (Reproducer))
- `<campaign>/BUCKET_LIST.md` *(dedicated flat bucket list — name, CVE/RFC/BENIGN status, trace count)*
- `<campaign>/SUMMARY_BUCKETS.md` (full summary with links and one-liners)
- `<campaign>/CAMPAIGN_REPORT.md`
- `<campaign>/sort_objectives_<p1>_<p2>.py` *(archival snapshot of the finalized triaging script)*

At the end, it pauses and writes the Audit-3 request to the mailbox for the **same Auditor pane** — the cross-artifact consistency audit. Same two-trigger loop: type `do your mailbox` in the Auditor pane → wait → type `continue` in Orchestrator. The Auditor's loaded context from Audits 1 and 2 makes this audit cheap. (During Audit 3 the Auditor writes only `<campaign>/mailbox/from_auditor/audit_3_verdict.md` — it does not edit files in `<campaign>/BUGS/`, `<campaign>/CAMPAIGN_REPORT.md`, or `<campaign>/SUMMARY_BUCKETS.md`; those belong to the Orchestrator.)

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
echo "metadata-logs: $(find objective -name 'metadata_diff_*.log' | wc -l) of $(find objective -name '*.trace' -not -name '.*' | wc -l)"

# Resolve the triaging script for this protocol (glob; or set TRIAGING_SCRIPT explicitly).
TRIAGING_SCRIPT="${TRIAGING_SCRIPT:-$(ls evaluation-ddyf/*/sort_objectives_*.py evaluation-ddyf/sort_objectives_*.py 2>/dev/null | head -1)}"

# Are buckets defined?  (Count REAL buckets separately from the always-present housekeeping
# buckets no_errors/non_triaged — a script with only those is effectively a fresh campaign.
# NB: don't use `grep -c ... || echo`: grep -c prints 0 AND exits 1 on no matches, so the
# `||` fires and you get a confusing double line. Capture the count instead.)
ALL_BUCKETS=$(grep -cE '^\s*"[^"]*/":' "$TRIAGING_SCRIPT")
REAL_BUCKETS=$(grep -oE '^\s*"[^"]*/":' "$TRIAGING_SCRIPT" | grep -vcE '"(no_errors|non_triaged)/"')
echo "buckets defined: ${ALL_BUCKETS} total, ${REAL_BUCKETS} real (non-housekeeping)"
[ "${REAL_BUCKETS}" -eq 0 ] && echo "  -> no real buckets yet: treat as fresh (start at Phase 0.5)"

# How many buckets have been audited?  (Capture the count — same reason as above: `grep -c`
# prints 0 AND exits 1 on no matches, so a `... || echo` would double-print.)
echo "audited:   $(grep -c '# AUDITED' "$TRIAGING_SCRIPT")"
echo "pending:   $(grep -c '# PENDING REVIEW' "$TRIAGING_SCRIPT")"
echo "revisions: $(grep -c '# REVISION NEEDED' "$TRIAGING_SCRIPT")"

# Find the campaign folder. This is the RESUME helper, so prefer the newest EXISTING folder
# for this PUT pair (whatever its date) — that survives a run that crossed midnight at any
# phase. Only fall back to today's name if none exists yet.
PREFIX=$(TRIAGING_SCRIPT="$TRIAGING_SCRIPT" python3 -c "
import re, os
s = open(os.environ['TRIAGING_SCRIPT']).read().splitlines()
def put(tag):
    line = next(l for l in s if re.match(r'\s*'+tag+r'\s*=', l))
    return re.sub(r'\d+','', re.findall(r'\"([^\"]+)\"', line)[-1])
print(f'triaging-{put(\"FIRST_PUT\")}-{put(\"SECOND_PUT\")}-')")
CAMPAIGN=$(ls -d ${PREFIX}*/ 2>/dev/null | sort | tail -1 | sed 's,/$,,')
if [ -z "$CAMPAIGN" ]; then
  echo "No existing ${PREFIX}*/ folder — nothing to resume (this looks like a fresh campaign)."
  CAMPAIGN="${PREFIX}$(date +%m-%d)"   # name a fresh one for reference only; not yet created
fi
echo "Campaign folder: ${CAMPAIGN}"

# Guard every ${CAMPAIGN}-prefixed check: if CAMPAIGN were empty, "${CAMPAIGN}BUGS/" would
# expand to "BUGS/" and silently scan the CWD. It is always set above, but stay defensive.
if [ -n "$CAMPAIGN" ] && [ -d "$CAMPAIGN" ]; then
  # Have any bug reports been written?
  echo "bug reports:  $(ls "${CAMPAIGN}/BUGS/"*.md 2>/dev/null | wc -l)"
  echo "reproducers:  $(ls "${CAMPAIGN}/BUGS/"reproduce_*.py 2>/dev/null | wc -l)"
  # Are summary artifacts present?
  for f in BUCKET_LIST.md SUMMARY_BUCKETS.md CAMPAIGN_REPORT.md; do
    test -f "${CAMPAIGN}/${f}" && echo "${f} present" || echo "${f} missing"
  done
else
  echo "(no campaign folder on disk yet — bug-report / summary checks skipped)"
fi
```

### Decide which phase to resume from

The "First Orchestrator message" column gives the verbatim text to paste as the resumption template's "Specific instruction" line (see Resuming — Orchestrator launch below).

| What you find | Resume at | Specific instruction |
|---|---|---|
| No metadata logs in `objective/` | (do Phase 0 first — not via Orchestrator) | Run `./evaluation-ddyf/phase0_produce_metadata.sh` yourself, then resume with "Phase 0 done. Begin Phase 1 (survey)." |
| Metadata logs present, no buckets defined in the triaging script | Phase 1 | "Phase 0 done. Begin Phase 1 (survey)." |
| Buckets defined, some still `# PENDING REVIEW` (no `# AUDITED` yet) | Phase 2.5 | "Phases 1–2 done. Run Phase 2.5 (granularity self-audit) on every `# PENDING REVIEW` bucket." |
| `# REVISION NEEDED` comments present in script | Apply revisions, then re-audit | "Resolve all `# REVISION NEEDED` comments in the triaging script, then re-run Phase 2.5 and request Audit 1 again." |
| All buckets `# AUDITED`, `<campaign>/mailbox/from_auditor/audit_1_verdict.md` exists, no `<campaign>/BUGS/*.md` | Phase 3 then Phase 4 | "Audit 1 complete. Run Phase 3 Security Gate on any VULN candidates, then Phase 4 (bug reports + reproducers + SUMMARY)." |
| `<campaign>/BUGS/*.md` exist, no `<campaign>/BUCKET_LIST.md` | Phase 4c & 4d | "Reports written. Generate `BUCKET_LIST.md`, `SUMMARY_BUCKETS.md` and `CAMPAIGN_REPORT.md` inside the campaign folder, then request the consistency Audit (Audit 3)." |
| Everything written but no `<campaign>/mailbox/from_auditor/audit_3_verdict.md` | Audit 3 only | "Phase 4 complete. Request the final consistency audit (Audit 3) — emit the Auditor prompt." |

### Resuming — Orchestrator launch

Launch the Orchestrator pane:
```bash
claude --append-system-prompt "$(cat prompts-triaging/ORCHESTRATOR.md)"
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
| Producer | `prompts-triaging/PHASE0_DATA_PRODUCER.md` | Run the Phase 0 shell script. Verify counts. | Low (Haiku) |
| Orchestrator | `prompts-triaging/ORCHESTRATOR.md` | Drives Phases 1–4. Pauses for Auditor checkpoints. | Medium-high (Sonnet Pro) |
| Auditor | `prompts-triaging/AUDITOR.md` | Three independent audit passes (granularity, VULN, consistency). | Medium (AGY / Opus) |

---

## Files in `prompts-triaging/`

| File | Purpose |
|---|---|
| `START_HERE.md` | **You are here.** Driver for the whole pipeline; the appendix below is the prompt-set overview + design rationale. |
| `ORCHESTRATOR.md` | Lead engineer prompt (system prompt for the Orchestrator session). Its appendix is the tlspuffin diff-output reference card (pitfalls when reading metadata logs). |
| `AUDITOR.md` | Reviewer prompt (multi-pass; system prompt for the Auditor session). |
| `PHASE0_DATA_PRODUCER.md` | Phase 0 producer prompt (system prompt for the Producer session, if used). |
| `BUCKET_GRANULARITY.md` | Hard criteria each bucket must satisfy. |
| `tls/SECURITY_GATE_TLS.md` | 5-gate discipline for `[VULN]` tag + speculative-paths guidance (per-protocol; TLS). |
| `tls/CVSS_TLS.md` | TLS-specific CVSS guidance and traps. |
| `ssh/SECURITY_GATE_SSH.md` | SSH counterpart of the gate (auth/channel claim, exchange-hash `H`, signature-verify defense layers, harness-vs-library trap). |
| `ssh/CVSS_SSH.md` | SSH-specific CVSS guidance, incl. the "finding is in sshpuffin itself → CVSS N/A" case. |
| `ssh/README.md` | Pointer to the two SSH gate files above. |
| `TEMPLATES.md` | The Phase-4 output templates in one file: Bug report, Reproducer, Summary-buckets, Investigation prompt (each a section). |
| `NAMING_CONVENTIONS.md` | Naming rules + cross-artifact consistency. |

---

## When to deviate from this pipeline

- **Skip Phase 0** if metadata logs are already present and the trace set hasn't changed.
- **Skip Phase 1** if you have a previous campaign's bucket map you want to reuse — but you must still run Phase 2.5 to verify granularity.
- **Skip Phase 3** if no bucket has a Finished claim in any trace (the data shows zero CVE candidates).
- **Never skip Phase 2.5** — granularity is what distinguishes a useful campaign from a wall of unactionable buckets.
- **Never skip the cross-artifact audit** at the end of Phase 4 — naming drift between buckets, reports, and reproducers is the most common silent failure.


---

## Appendix — prompt-set overview & design rationale

*(Folded in from the former `README.md`. `START_HERE.md` (above) is the execution driver; this appendix is the high-level overview and the design lessons the prompt set encodes.)*

Self-contained prompt set for triaging Differential Dolev-Yao Fuzzing (DDYF) output between two TLS implementations. Designed for reuse on future campaigns with minimal adaptation.

### Pipeline


```
   ┌────────────┐   ┌──────────┐   ┌────────────┐   ┌──────────┐   ┌────────────┐   ┌────────────┐
   │  Phase 0   │ → │ Phase 1  │ → │ Phase 2    │ → │ Phase 2.5│ → │ Phase 3    │ → │ Phase 4    │
   │ Data prod  │   │ Survey   │   │ Buckets    │   │ Granul.  │   │ Sec. Gate  │   │ Reports +  │
   │ (Haiku)    │   │ (Sonnet) │   │ (Sonnet)   │   │ Audit    │   │ (Sonnet)   │   │ Summary    │
   └────────────┘   └──────────┘   └────────────┘   └──────────┘   └────────────┘   └────────────┘
                                          │              ↑                                  │
                                          └──────────────┘                                  │
                                          split or merge until pass                         │
                                                                                            ▼
                                          ┌────────────────────────────────────┐    BUGS/*.md
                                          │  Auditor (parallel after Phase 2.5)│  + reproduce_*.py
                                          │  (Opus / AGY)               │  + SUMMARY_BUCKETS.md
                                          └────────────────────────────────────┘  + CAMPAIGN_REPORT.md
```

### Output artifacts produced by the pipeline (NOT files in this directory)


| Artifact | Produced at | Produced by | Template |
|---|---|---|---|
| `<campaign>/mailbox/from_auditor/audit_1_verdict.md` | End of Audit 1 (after Phase 2.5) | Auditor | n/a — see `AUDITOR.md` Audit 1 |
| `<campaign>/mailbox/from_auditor/audit_2_verdict.md` | End of Audit 2 (after Phase 3, if any VULN candidate) | Auditor | n/a — see `AUDITOR.md` Audit 2 |
| `<campaign>/mailbox/from_auditor/audit_3_verdict.md` | End of Audit 3 (after Phase 4) | Auditor | n/a — see `AUDITOR.md` Audit 3 |
| `<campaign>/BUCKET_LIST.md` | Phase 4c | Orchestrator | See `TEMPLATES.md` (Summary-buckets) |
| `<campaign>/SUMMARY_BUCKETS.md` | Phase 4d | Orchestrator | `TEMPLATES.md` (Summary-buckets) |
| `<campaign>/CAMPAIGN_REPORT.md` | Phase 4e | Orchestrator | Structure described in `ORCHESTRATOR.md` Phase 4e |
| `<campaign>/sort_objectives_<p1>_<p2>.py` | Phase 4f | Orchestrator | Snapshot copy of `evaluation-ddyf/sort_objectives_<p1>_<p2>.py` |
| `<campaign>/BUGS/<root_name>.md` | Phase 4a | Orchestrator | `TEMPLATES.md` (Bug report) |
| `<campaign>/BUGS/reproduce_<root_name>.py` | Phase 4b | Orchestrator | `TEMPLATES.md` (Reproducer) |
| `objective/<bucket>/*.trace` + `metadata_*.log` | Phase 2 (move logic) | Orchestrator (via triaging script) | n/a |
| Audit tag comments (`# AUDITED [AUDITOR]`, `# REVISION NEEDED [AUDITOR]`; append single lines, delete `# PENDING REVIEW`) in `evaluation-ddyf/sort_objectives_ossl_libre.py` | Audits 1 & 2 (in-place edits) | Auditor | n/a |

### Lessons baked into v3


These v3 additions address failure modes observed during the OpenSSL-vs-LibreSSL campaign that v2 did not prevent:

1. **Single-criterion buckets slipped past v2.** Buckets like `ossl_alert_libre_silent` (`KnowledgeDiffC(AlertMessagePayload, ())` only) and `status_libre_earlier_ossl_later` (`StepC(...)` only) classified traces by symptom shape without tying them to a root cause. v3's `BUCKET_GRANULARITY.md` rejects such buckets at Phase 2.5.

2. **Trace metadata lived separately from traces.** v2 left `metadata_*.log` files in the parent `objective/` directory while buckets were subfolders. v3 mandates the triaging script move metadata with the trace.

3. **Reproducers were inconsistent in size, style, and verbosity.** Some repeated the entire bug report in a docstring; some hardcoded `/tmp/...` paths; some had no build instructions. v3's `TEMPLATES.md` (Reproducer) enforces a minimal, standalone, no-absolute-paths style with explicit build/run instructions at the top.

4. **No single source of truth for "what buckets exist and what category."** v2 had the bug-to-bucket mapping in `CAMPAIGN_REPORT.md`, but no flat list categorised by severity. v3 mandates `SUMMARY_BUCKETS.md`.

5. **Naming drift between artifacts.** A bucket might be `libre_v12_sh_v13_cipher_zero_keys`, its bug report `libressl_wrong_cipher_acceptance.md`, and the reproducer `reproduce_wrong_cipher.py` — three different names for the same finding. v3's `NAMING_CONVENTIONS.md` enforces a single root name across all three artifacts.

6. **Empty buckets accumulated.** After splitting, the original parent bucket often kept zero traces. v3 mandates cleanup at end of Phase 2.5.

7. **All v2 lessons retained:** Security Gate, CVSS traps, sanitized-binary caveats, `-quiet` prohibition, TCP RST vs silent close equivalence, chained-bug guidance, harness-vs-standalone discrepancy handling.

8. **Two-track analysis: strict (CVE-tagging) + speculative (research notes).** v2's Security Gate framed gate failures as terminal ("STOP — not a CVE"). v3 reframes: the gate is strict only for the `[VULN]` tag and CVSS scoring; for *thinking*, speculative attack paths are encouraged and have their own clearly-labeled home (Section 10 of bug reports, Section 5 of `SUMMARY_BUCKETS.md`). This matches academic-publication norms — reviewers expect to see verified findings AND honest discussion of paths that don't yet meet the bar.

9. **Constrained-write Auditor.** v2 (and the early v3 draft) made the Auditor strictly read-only — every audit verdict had to be copy-pasted by the user from the Auditor pane back to the Orchestrator pane. v3-final lets the Auditor edit a tightly bounded surface: audit tag comments in `evaluation-ddyf/sort_objectives_ossl_libre.py` (only appending single-line `# AUDITED [AUDITOR]` / `# REVISION NEEDED [AUDITOR]` verdicts and deleting `# PENDING REVIEW` lines — never mutating the Orchestrator's `# GRANULARITY AUDITED [ORCHESTRATOR]` block) and the per-audit summary files `<campaign>/mailbox/from_auditor/audit_<N>_verdict.md`. Nothing else. This eliminates the copy-paste handoff (the user just types `continue` in the Orchestrator pane after the Auditor returns to idle) and puts the verdict in git history rather than ephemeral chat text. Race conditions are avoided by the protocol "Orchestrator paused → user pings Auditor → Auditor edits → user resumes Orchestrator." A read-only fallback (`"Verdict only, no edits"` prefix in the audit prompt) is preserved for cases where the user wants to review the verdict before it lands.