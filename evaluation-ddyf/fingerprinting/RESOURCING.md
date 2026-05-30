# Resourcing & launch plan (Claude Pro, server-hosted, AI-free method)

Companion to `PLAN.md` and `LLM_PROMPT.md`. This file says **who runs what, with which
model/effort, and the exact prompt to paste**. Everything runs locally in this repo on
a long-lived server, so long campaigns are free (wall-clock); the only scarce resource
is the **Claude Pro account quota** (Sonnet only, ~5h session + weekly caps).

## Guiding principle

AI is used **only to author scripts and paper text, once**. The fingerprinting method
itself is AI-free at deploy time (replay fixed probe traces → hash responses → walk
static `tree.json`). So: spend Claude on the *reasoning-heavy authoring*; run all
builds, campaigns, and the deterministic pipeline as **plain shell on the server, no
agent attached**.

## Who runs what

| Stage | Tool | Model / effort | AI in loop? |
|---|---|---|---|
| Author reasoning core: `triage.py`, `signatures.py`, `build_tree.py` + validate on existing 3-version data | **Claude Code** | **Sonnet 4.6**, extended thinking ("think hard"); **no subagents** | yes (authoring only) |
| Author boilerplate: `presets_gen.py`, `build_all.sh`, `discover.sh`, `run_all.sh` | **Gemini Pro / Antigravity** | Gemini 2.5/3 Pro, normal | yes (authoring only) |
| Run builds + campaigns + full pipeline | **Shell in `tmux`** (no agent) | — | **no** |
| Paper write-up (Phase 7) | **Claude Code or Gemini** | Sonnet / Gemini Pro | yes (authoring only) |

Rationale: the boilerplate is fully specified in `LLM_PROMPT.md`, so Gemini can write it
without burning Claude quota. The algorithmic scripts (volatile-field signature
canonicalization, decision-tree/set-cover) are where a strong model + thinking pays off
— give those to Claude. Builds/campaigns are pure shell; never attach an agent to them.

## Order of operations (2 days, server)

**Day 1**
1. *Gemini/Antigravity (Launch B):* write `presets_gen.py`, `build_all.sh`, `discover.sh`,
   `run_all.sh`; smoke-test (no long campaigns).
2. *Shell, tmux (no AI):* run `presets_gen.py`, then `build_all.sh`. **Checkpoint:** which
   versions build (PUT + harness)? Cap the range to the contiguous prefix that builds;
   do NOT patch Rust — ask the human if newer versions break.
3. *Claude (Launch A), in parallel with step 2:* **bootstrap** `triage.py`,
   `signatures.py`, `build_tree.py` against the existing `experiments/` objectives
   (enough to debug all code paths). **Do not trust the existing data for the
   regression check** — it is thin/uneven (500vs520 barely ran, ~6 objectives) and
   5.1.1 is not built.
4. *Shell, tmux (no AI):* run a **fresh short validation campaign** — make sure 5.1.1 is
   built (Launch B presets include it), then run all pairs among {5.0.0,5.1.0,5.1.1,5.2.0}
   for ~30–60 min each. Claude then validates the pipeline against this output: it must
   reproduce the appendix result (A0=5.0.0, A1={5.1.0,5.1.1}, B=5.2.0 + the two named
   distinguishing traces). Only then scale up.
5. *Shell, tmux (no AI), overnight:* `discover.sh` — adjacent-pair campaigns over the
   full buildable range, 1h each, parallelized across the 10 cores / distinct ports.
   Resumable.

**Day 2**
5. *Shell, tmux (no AI):* run the validated pipeline (`run_all.sh` from triage onward) on
   the full campaign output → `signatures.csv`, `clusters.json`, `tree.{json,dot}`,
   `report.md`, `RESULTS.md`.
6. *Claude (Launch A continued):* Phase 6 hardening (leave-one-pair-out, stability,
   stealth assertion, git-diff explanations for indistinguishable pairs).
7. *Claude or Gemini (Launch D):* Phase 7 paper write-up; build the PDF.

## Server execution notes (AI-free stages)

- Run long jobs detached: `tmux new -s fp` then inside `nix-shell ./shell.nix`.
- `export LIBAFL_EDGES_MAP_SIZE=262144` before any fuzzing.
- All scripts must be **resumable/idempotent** (re-running skips done work) so a dropped
  ssh session never costs progress.
- Parallel campaigns: one unique `-p <PORT>` per concurrent campaign; split the 10 cores
  across them or give all 10 to one campaign at a time.

## Quota-protection rules for Claude sessions

- Keep Claude sessions focused on one script at a time; close the loop fast.
- When something fails, paste Claude the **concrete error/output**, not "make it work".
- Never let Claude sit in a polling loop watching a campaign — that's a shell job.
- No subagents (each multiplies quota; the flow is sequential with checkpoints).

---

## Copy-paste launch prompts

Each launch is a standalone file under `evaluation-ddyf/fingerprinting/prompts/`,
ready to `cat` and paste:

- `prompts/A_claude_core.txt`     — Claude Code (Sonnet, extended thinking): reasoning core, then hardening + paper.
- `prompts/B_gemini_boilerplate.txt` — Gemini Pro / Antigravity: mechanical scripts only.
- `prompts/C_server_shell.sh`     — server shell, NO AI: builds, validation campaign, campaigns, pipeline.
- `prompts/D_paper_writeup.txt`   — paper write-up (Claude or Gemini).

```
cat evaluation-ddyf/fingerprinting/prompts/A_claude_core.txt
```
