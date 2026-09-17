# DDYF Triaging Prompts — v3

Self-contained prompt set for triaging Differential Dolev-Yao Fuzzing (DDYF) output between two TLS implementations. Designed for reuse on future campaigns with minimal adaptation.

> **If you are a user about to start a campaign, open [`START_HERE.md`](START_HERE.md).** That file is the driver — it tells you which LLM sessions to launch, in what order, with what prompts. The current file (README) is documentation about the prompt set itself.

**v3 over v2:** stricter bucket granularity (no single-criterion buckets, root-cause traceability required), minimal standalone reproducer template, `SUMMARY_BUCKETS.md` mandated artifact, metadata-follows-trace rule, cross-artifact naming-consistency rule, end-of-campaign cleanup of empty buckets.

## Pipeline

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
                                          │  (Opus / Gemini Pro)               │  + SUMMARY_BUCKETS.md
                                          └────────────────────────────────────┘  + CAMPAIGN_REPORT.md
```

## Files in this directory (prompts only)

| File | Role | Read by |
|---|---|---|
| `START_HERE.md` | User entry point — driver for the whole pipeline | The user |
| `PHASE0_DATA_PRODUCER.md` | Bulk metadata-log generation for every trace | Haiku-class model |
| `ORCHESTRATOR.md` | Lead engineer — Phases 1–4, granularity enforcement | Sonnet-class model |
| `BUCKET_GRANULARITY.md` | Strict criteria a bucket must satisfy | Orchestrator + Auditor |
| `SECURITY_GATE.md` | 5-question discipline for the `[VULN]` tag + speculative-paths guidance | Orchestrator + Auditor |
| `CVSS_TLS.md` | CVSS v3.1 scoring guide tailored to TLS findings | Orchestrator + Auditor |
| `AUDITOR.md` | Independent reviewer — verifies buckets, gates, mapping | Opus / Gemini Pro |
| `BUG_REPORT_TEMPLATE.md` | Structure for every `BUGS/*.md` report | Orchestrator |
| `REPRODUCER_TEMPLATE.md` | Strict template for minimal standalone Python reproducers | Orchestrator |
| `SUMMARY_BUCKETS_TEMPLATE.md` | Template for the `SUMMARY_BUCKETS.md` campaign artifact | Orchestrator |
| `DIFF_OUTPUT_REFERENCE.md` | Reference card for tlspuffin output interpretation | All phases |
| `NAMING_CONVENTIONS.md` | Rules for keeping bucket / report / reproducer names in sync | All phases |
| `README.md` | This file — documentation about the prompt set | The user |

## Output artifacts produced by the pipeline (NOT files in this directory)

| Artifact | Produced at | Produced by | Template |
|---|---|---|---|
| `<campaign>/audit/audit_1_verdict.md` | End of Audit 1 (after Phase 2.5) | Auditor | n/a — see `AUDITOR.md` Audit 1 |
| `<campaign>/audit/audit_2_verdict.md` | End of Audit 2 (after Phase 3, if any VULN candidate) | Auditor | n/a — see `AUDITOR.md` Audit 2 |
| `<campaign>/audit/audit_3_verdict.md` | End of Audit 3 (after Phase 4) | Auditor | n/a — see `AUDITOR.md` Audit 3 |
| `<campaign>/BUCKET_LIST.md` | Phase 4c | Orchestrator | See `SUMMARY_BUCKETS_TEMPLATE.md` |
| `<campaign>/SUMMARY_BUCKETS.md` | Phase 4d | Orchestrator | `SUMMARY_BUCKETS_TEMPLATE.md` |
| `<campaign>/CAMPAIGN_REPORT.md` | Phase 4e | Orchestrator | Structure described in `ORCHESTRATOR.md` Phase 4e |
| `<campaign>/sort_objectives_<p1>_<p2>.py` | Phase 4f | Orchestrator | Snapshot copy of `evaluation-ddyf/sort_objectives_<p1>_<p2>.py` |
| `<campaign>/BUGS/<root_name>.md` | Phase 4a | Orchestrator | `BUG_REPORT_TEMPLATE.md` |
| `<campaign>/BUGS/reproduce_<root_name>.py` | Phase 4b | Orchestrator | `REPRODUCER_TEMPLATE.md` |
| `objective/<bucket>/*.trace` + `metadata_*.log` | Phase 2 (move logic) | Orchestrator (via triaging script) | n/a |
| Audit tag comments (`# AUDITED`, `# REVISION NEEDED`) in `evaluation-ddyf/sort_objectives_ossl_libre.py` | Audits 1 & 2 (in-place edits) | Auditor | n/a |

## Running a fresh campaign

1. Place traces in `./objective/`.
2. **Phase 0:** run `./evaluation-ddyf/phase0_produce_metadata.sh`. After completion every trace has three `metadata_*` log files alongside it.
3. **Phase 1:** Orchestrator surveys logs and produces a Symptom Fingerprint table.
4. **Phase 2:** Orchestrator writes bucket conditions; the triaging script moves each trace AND its three metadata logs into the bucket subfolder.
5. **Phase 2.5:** Orchestrator runs `BUCKET_GRANULARITY.md` checks on every bucket. Buckets failing the checks must be split or merged. Loop until all pass.
6. **Phase 3:** For any VULN candidate, Orchestrator runs full Security Gate.
7. **Phase 4:** Orchestrator writes one bug report per root cause + one minimal reproducer per report + `SUMMARY_BUCKETS.md` + final campaign report.
8. Auditor runs in parallel after Phase 2.5 emits `# PENDING REVIEW` buckets.

## Mandatory artifacts produced

| Artifact | When | Purpose |
|---|---|---|
| `metadata_*.log` triplet per trace | End of Phase 0 | Static input for all subsequent phases |
| Symptom Fingerprint table | End of Phase 1 | Catalogue of observable difference types |
| Triaging script with `# PENDING REVIEW` tags | End of Phase 2 | Mutually-exclusive bucket conditions |
| Granularity-audit results | End of Phase 2.5 | Each bucket either passes or is queued for split |
| `<campaign>/BUGS/<name>.md` reports | Phase 4 | One per root cause |
| `<campaign>/BUGS/reproduce_<name>.py` reproducers | Phase 4 | One per bug report, minimal, standalone, no abs paths |
| `<campaign>/BUCKET_LIST.md` | End of Phase 4c | Flat bucket list: name, CVE/RFC/Bug/BENIGN status, trace count |
| `<campaign>/SUMMARY_BUCKETS.md` | End of Phase 4d | Full summary table with bug-report links and one-liners |
| `<campaign>/CAMPAIGN_REPORT.md` | End of campaign | Top-level summary, bug-to-bucket mapping (both directions) |

## Lessons baked into v3

These v3 additions address failure modes observed during the OpenSSL-vs-LibreSSL campaign that v2 did not prevent:

1. **Single-criterion buckets slipped past v2.** Buckets like `ossl_alert_libre_silent` (`KnowledgeDiffC(AlertMessagePayload, ())` only) and `status_libre_earlier_ossl_later` (`StepC(...)` only) classified traces by symptom shape without tying them to a root cause. v3's `BUCKET_GRANULARITY.md` rejects such buckets at Phase 2.5.

2. **Trace metadata lived separately from traces.** v2 left `metadata_*.log` files in the parent `objective/` directory while buckets were subfolders. v3 mandates the triaging script move metadata with the trace.

3. **Reproducers were inconsistent in size, style, and verbosity.** Some repeated the entire bug report in a docstring; some hardcoded `/tmp/...` paths; some had no build instructions. v3's `REPRODUCER_TEMPLATE.md` enforces a minimal, standalone, no-absolute-paths style with explicit build/run instructions at the top.

4. **No single source of truth for "what buckets exist and what category."** v2 had the bug-to-bucket mapping in `CAMPAIGN_REPORT.md`, but no flat list categorised by severity. v3 mandates `SUMMARY_BUCKETS.md`.

5. **Naming drift between artifacts.** A bucket might be `libre_v12_sh_v13_cipher_zero_keys`, its bug report `libressl_wrong_cipher_acceptance.md`, and the reproducer `reproduce_wrong_cipher.py` — three different names for the same finding. v3's `NAMING_CONVENTIONS.md` enforces a single root name across all three artifacts.

6. **Empty buckets accumulated.** After splitting, the original parent bucket often kept zero traces. v3 mandates cleanup at end of Phase 2.5.

7. **All v2 lessons retained:** Security Gate, CVSS traps, sanitized-binary caveats, `-quiet` prohibition, TCP RST vs silent close equivalence, chained-bug guidance, harness-vs-standalone discrepancy handling.

8. **Two-track analysis: strict (CVE-tagging) + speculative (research notes).** v2's Security Gate framed gate failures as terminal ("STOP — not a CVE"). v3 reframes: the gate is strict only for the `[VULN]` tag and CVSS scoring; for *thinking*, speculative attack paths are encouraged and have their own clearly-labeled home (Section 10 of bug reports, Section 5 of `SUMMARY_BUCKETS.md`). This matches academic-publication norms — reviewers expect to see verified findings AND honest discussion of paths that don't yet meet the bar.

9. **Constrained-write Auditor.** v2 (and the early v3 draft) made the Auditor strictly read-only — every audit verdict had to be copy-pasted by the user from the Auditor pane back to the Orchestrator pane. v3-final lets the Auditor edit a tightly bounded surface: audit tag comments in `evaluation-ddyf/sort_objectives_ossl_libre.py` (only `# AUDITED` / `# REVISION NEEDED` / removing `# PENDING REVIEW`) and the per-audit summary files `<campaign>/audit/audit_<N>_verdict.md`. Nothing else. This eliminates the copy-paste handoff (the user just types `continue` in the Orchestrator pane after the Auditor returns to idle) and puts the verdict in git history rather than ephemeral chat text. Race conditions are avoided by the protocol "Orchestrator paused → user pings Auditor → Auditor edits → user resumes Orchestrator." A read-only fallback (`"Verdict only, no edits"` prefix in the audit prompt) is preserved for cases where the user wants to review the verdict before it lands.
