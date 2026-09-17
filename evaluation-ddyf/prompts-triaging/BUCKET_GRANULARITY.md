# Bucket Granularity — Strict Criteria

This file defines what makes a bucket valid. Every bucket must pass these criteria before it can be tagged `# PENDING REVIEW`. Buckets that fail are split (most common) or merged (rare).

The objective: every bucket maps to exactly one identified bug or one identified BENIGN difference class, with a root-cause-grounded condition that is both **discriminatory** (rejects traces outside the class) and **complete** (captures every trace in the class).

---

## The four mandatory criteria

A bucket condition is valid if and only if all four hold.

### Criterion 1 — Specific difference, not generic

The bucket condition must constrain **what** differs at a level finer than "there is a difference."

| ❌ Insufficient | ✅ Acceptable |
|---|---|
| `KnowledgeDiffC(AlertMessagePayload, ())` | `InnerKnowledgeC("Different(HandshakeFailure, MissingExtension)", "AlertMessagePayload")` |
| `DifferentClaimC()` | `DifferentClaimC(in_first_type="()", in_second_type="Finished")` |
| `StatusC(LIBRE, "tls13_lib.c", first_to_fail=True)` | `StatusC(LIBRE, "tls13_lib.c", first_to_fail=True) + StatusC(LIBRE, "unexpected message", first_to_fail=False)` |
| `StepC(lambda f, s, total: f < s)` alone | `StepC(...)` + a status/term constraint identifying *which* error caused the earlier failure |

**Rule:** if you cannot describe the difference in one sentence that names the specific alert code, claim type, error string, or message type involved, the condition is too generic.

### Criterion 2 — Root-cause-grounded constraint on the trace

Every additional constraint (function symbol present, agent configuration, cipher offered, etc.) must correspond to a **real root cause** identified during analysis — not an arbitrary observation about what happens to be in the traces.

| ❌ Insufficient | ✅ Acceptable |
|---|---|
| `TermContainsC(OSSL, "fn_certificate")` because most traces in the bucket happen to contain this | `TermContainsReC(OSSL, r"fn_append_certificate(.|\n)*fn_append_certificate")` because the root cause is "an oversized Certificate built by repeated append" |
| `ClaimContainsC(LIBRE, r"chosen_cipher: 4865")` because 4865 is "interesting" | `ClaimContainsC(LIBRE, r"chosen_cipher: (4865|4866)")` because the root cause is "TLS 1.3-only ciphers accepted in TLS 1.2 context" |
| `StatusC(OSSL, "tls13_lib.c")` because the file appears in logs | `StatusC(OSSL, "ossl_statem_server_read_transition")` because that function is the specific RFC §6.2 guard whose absence in LibreSSL is the root cause |

**Rule:** for each constraint you add, write a one-line justification: "this constraint identifies traces where [root cause]." If the justification is "this just happens to filter the bucket," delete the constraint and find a real one.

### Criterion 3 — Discriminatory AND complete

The combined conditions must:
- **Reject** any trace that does not exhibit the identified root cause (no false positives).
- **Capture** every trace that does exhibit the identified root cause (no false negatives).

**How to verify:**

```bash
# Sample N traces matching the bucket; confirm each one exhibits the root cause
for T in objective/<bucket>/*.trace; do
  inspect $T  # verify root cause indicators
done | head -20

# Sample N traces from adjacent buckets; confirm they would NOT match this condition
# (run the triaging script and check that none of them fell into this bucket)
```

**If discriminatory fails** (a trace matches but doesn't exhibit the root cause): tighten the condition.

**If complete fails** (a trace exhibits the root cause but doesn't match): either loosen the condition (if the missing case shares the same root cause) or create a new sibling bucket (if it has a different root cause).

### Criterion 4 — Exhaustive metadata audit shows no second root cause hiding

For every bucket with ≥ 10 traces, read the `metadata_diff_*.log` of all traces (or at least sample 15 evenly across creation timestamps). Confirm:
- Same error function in the same PUT across traces
- Same alert pair (or same status outcome) across traces
- No subset of traces exhibits a different root cause that the condition accidentally captures

If any subset exhibits a different root cause: split into a sub-bucket with a sibling condition, then re-verify Criteria 1–4 on both new buckets.

---

## Anti-patterns that v2 did not catch

The following bucket patterns appeared in the campaign and slipped past v2 audits. v3 rejects them.

### Anti-pattern A: "Knowledge difference of type X" alone

```python
# REJECT
"ossl_alert_libre_silent/": KnowledgeDiffC(
    first_type_name="...AlertMessagePayload",
    second_type_name="()",
)
```

This captures every trace where OpenSSL sends an alert and LibreSSL doesn't. Different traces can have different alert codes, different OpenSSL error functions, different attacker terms — and therefore different root causes. **Always split by the specific error function or alert code.**

### Anti-pattern B: "Status of PUT X" alone

```python
# REJECT
"status_libre_earlier_ossl_later/": AllC(
    StepC(lambda f, s, total: s < f),
    NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
    NotC(DifferentClaimC()),
)
```

The condition says "LibreSSL fails first" without saying *what* LibreSSL failed at. Split by the specific LibreSSL error message (`tls13_lib.c` + specific reason) or by what the attacker did (function symbol). If after splitting some traces don't fit any specific sub-bucket, those probably belong in a different category entirely — investigate before keeping them in a catch-all.

### Anti-pattern C: "OpenSSL has record failure, LibreSSL proceeds" without specifying what made the record fail

```python
# REJECT
"ossl_record_failure_libre_proceeds/": AllC(
    StatusC(OSSL, "record layer failure", first_to_fail=True),
    StepC(lambda f, s, total: f < s),
)
```

"Record layer failure" can mean a wrong MAC, an oversized record, an unexpected record type, etc. Split by the function symbol in the attacker's trace term (what kind of malformed record was sent) and verify each sub-bucket has a single OpenSSL error function in its `metadata_openssl340_*.log`.

### Anti-pattern D: "One PUT emits a claim the other doesn't" without specifying what messages preceded it

```python
# REJECT
"ossl_finished_libre_absent/": DifferentClaimC(
    in_first_type="Finished",
    in_second_type="()",
)
```

Why does OpenSSL emit Finished while LibreSSL doesn't? The condition needs to identify the protocol path: which messages did the attacker send, what state did each PUT reach, what claim was emitted. Even with only 4 traces, the condition must reflect this analysis.

---

## Granularity audit procedure  *(Phase 2.5)*

For each `# PENDING REVIEW` bucket, in order:

1. **Read the four criteria above and check each.** Write the result on a checklist.
2. **If any criterion fails**, do not proceed — split or tighten the condition, then re-check.
3. **Once all four pass**, add a `# GRANULARITY AUDITED` comment alongside `# PENDING REVIEW`.
4. **After all buckets pass**, run the triaging script. Any bucket folder that is now empty must be deleted from the script. Any trace falling into the catch-all `non_triaged` must be investigated (it indicates a missing bucket).

The Auditor in Phase 3+ will re-verify Criteria 1–4 independently on every `# GRANULARITY AUDITED` bucket. Do not skip the self-audit just because the Auditor will run it.

### Outcomes of the granularity audit

Each bucket lands in exactly one of three states after the audit:

| Outcome | Marker | Meaning |
|---|---|---|
| **Accepted** | `# GRANULARITY AUDITED` | All four criteria pass; bucket stands as-is. |
| **Pending revision** | `# REVISION NEEDED: <reason>` | One or more criteria fail; bucket needs splitting or tightening before next pass. |
| **Refuted (for a specific speculative claim)** | `# GRANULARITY AUDITED; SPECULATIVE CLAIM X REFUTED` | The bucket itself remains a valid RFC violation / BENIGN difference (Criteria 1–4 pass for what it actually classifies), but an attached speculative attack path was structurally refuted. Add a 1–2 line note in the bucket comment pointing to the refutation, e.g., `# Speculative path "weak key recovery via HRR group confusion" REFUTED — tls13_client.c:443 returns 0 before key_share_generate is reached. See BUGS/libressl_bad_key_share_stoc.md §10.` |

The third outcome is needed when a bucket was created with a hypothesis attached and the hypothesis didn't hold up. Demoting the bucket entirely is wrong (the symptom is still observable and may still be an RFC violation); silently dropping the hypothesis is also wrong (it leaves stale claims in `SUMMARY_BUCKETS.md` §5 Speculative). The audited+refuted-claim marker is the honest middle ground.

When recording a refutation, follow the stale-claim audit step in `ORCHESTRATOR.md` to propagate the change to `SUMMARY_BUCKETS.md`, `BUCKET_LIST.md`, `CAMPAIGN_REPORT.md`, and the bug report's "Speculative Attack Paths" section.

---

## When splitting is not possible

If a candidate bucket genuinely cannot be split (all traces analysed share the same root cause and same constraints), Criterion 4 passes trivially. But Criterion 1 still applies: the difference must be specific, not generic. A bucket of 4 traces with a single root cause is fine; a bucket of 4 traces with `KnowledgeDiffC(...)` alone is not, even if all 4 share a root cause — the condition must encode it.

If a candidate bucket cannot be tied to any root cause (the differences are genuinely noise / flakiness): tag `[BENIGN]` with a `flaky` or `non_deterministic` suffix in the name, document the absence of root cause in the comment, and keep the condition minimal.

---

## Examples of accepted vs rejected bucket conditions  *(this campaign)*

| Bucket | Status | Why |
|---|---|---|
| `ossl_alert_silent_server_unexpected_msg` | ✅ Accepted | Combines `KnowledgeDiffC(Alert, ())` + `NotC(DifferentClaimC(Finished))` + `StatusC(OSSL, "ossl_statem_server_read_transition")` — three independent conditions, ties to a specific OpenSSL state-machine guard |
| `libre_record_overflow_bypass` | ✅ Accepted | `InnerKnowledgeC("Different(RecordOverflow, UnknownCA)")` + `TermContainsReC` for repeated `fn_append_certificate` — specific alert pair + specific root cause (oversized cert chain) |
| `libre_v12_sh_v13_cipher_zero_keys` | ✅ Accepted | Three claim-content constraints: `tls_version: V1_2`, `chosen_cipher: 4865/4866`, `handshake_secret: [0,...]` — all reflecting the specific schism root cause |
| `ossl_alert_libre_silent` (v2 catch-all) | ❌ Rejected | Single criterion `KnowledgeDiffC(Alert, ())` — every silent-abort root cause classifies here |
| `status_libre_earlier_ossl_later` | ❌ Rejected | No constraint on *what* LibreSSL failed at — multiple unrelated bugs collapse here |
| `ossl_record_failure_libre_proceeds` (v2 form) | ❌ Rejected | "Record failure" is too coarse; split by trace term to identify what input caused the failure |
