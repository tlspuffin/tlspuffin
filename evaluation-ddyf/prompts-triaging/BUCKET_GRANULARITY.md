# Bucket Granularity — Strict Criteria

> **Protocol-agnostic methodology — TLS is the worked example.** The concrete names in this file (`openssl340`/`libressl421`, `tlspuffin`, `sort_objectives_ossl_libre.py`, TLS error strings / RFCs) are the running **TLS example**. For another protocol, substitute the placeholders defined in `START_HERE.md` § Protocol configuration — e.g. SSH: `libssh0114`/`wolfssh150`, `sshpuffin`, `ssh/sort_objectives_libssh_wolfssh.py`, RFC 4251-4254.


This file defines what makes a bucket valid. Every bucket must pass these criteria before it can be tagged `# PENDING REVIEW`. Buckets that fail are split (most common) or merged (rare).

> **Who edits vs who recommends.** The imperative "split / tighten / merge the condition"
> throughout this file is an action for the **Orchestrator** (it owns the bucket conditions).
> When the **Auditor** applies these criteria (Phase 3+ re-verification), it does **not** edit
> bucket conditions — it records the required split/tighten in its verdict file as a
> `# REVISION NEEDED: <reason>` note and lets the Orchestrator apply it. This preserves the
> Auditor's read-only-on-conditions boundary (see `AUDITOR.md` Authority) without contradiction.

The objective: every bucket maps to exactly one identified bug or one identified BENIGN difference class, with a root-cause-grounded condition that is both **discriminatory** (rejects traces outside the class) and **complete** (captures every trace in the class).

---

## The five mandatory criteria

A bucket condition is valid if and only if all five hold (Criterion 5 applies to any bucket tagged `[BENIGN]`).

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

### Criterion 5 — A `[BENIGN]` tag requires an explained cause, permitted on BOTH sides

Criteria 1–4 check that a condition selects what it claims. Criterion 5 checks that the **claim is true**. A bucket may be
tagged `[BENIGN]` only when (a) the cause of the divergence is established (source line, debug-build log, or packet-level
evidence — not a hypothesis), and (b) the behaviour of **each** PUT is shown to be permitted by the RFC for that input.
"Cause not root-caused this round" is incompatible with `[BENIGN]`: such a bucket is an **audit pile** (`diverge_*` /
`*_unexplained`), whatever its size.

Four rules that follow (each broke in the 09-23 libssh0114-vs-wolfssh150 campaign):

1. **"Nothing bad happened" is not an explanation.** "The completing side reaches no auth claim, so benign" argues from
   the absence of one harm; it never asked why one PUT accepted what the other rejected. It hid CVE-2026-59847
   (libssh ignores AES-GCM tag failures) behind ~664k objectives tagged benign.
2. **The rejecting side is not presumed to be the odd one.** Names and reasoning of the form `X_completes_Y_rejects`
   treat completion as normal. When the rejection is cryptographic or protocol-mandated, the *accepting* PUT is the
   prime suspect (`ssh/SECURITY_GATE_SSH.md` Gate 1-bis).
3. **A harness blind spot is not evidence.** If a PUT's behaviour surfaces only as a mapper/replay error, or as
   "Success" because it went silent, its behaviour is **unobserved**. Unobserved ≠ benign: get a debug/packet log.
4. **Key buckets on the first divergence, and root-cause the largest class first.** Outcome-keyed buckets ("who
   completed", "who authenticated") scatter one cause across many buckets, each of which looks plausible on its own;
   the gerr=-180 cause (40% of the corpus) sat in five buckets and was never root-caused as a whole. Key on the first
   observable divergence (per role), and investigate the largest divergence class at packet/source level before
   declaring the campaign audited.

## Root-cause keying — a construction that satisfies C1–C3 by design

The criteria above judge a bucket condition *after* it is written. Writing conditions one at a time scales badly on a
large corpus: each new condition can overlap an existing one, first-match order silently decides who wins, and a bucket
keyed on an *outcome* ("who completed", "who authenticated") scatters a single cause across many buckets. All three
failure modes are on record in past campaigns.

An alternative construction inverts the problem. Instead of N hand-written predicates, write ONE function mapping an
objective to a single **root-cause key** — its first observable divergence, qualified by the PUT's role — and define

    bucket(K) = { objective : root_cause_key(objective) == K }

Properties that come free:

* **C3 (discriminatory) holds by construction.** Keys are mutually exclusive, so buckets cannot overlap and dict order
  cannot move a trace between them. The entire class of first-match-ordering defects disappears.
* **C1 (specific) holds if the key names the CHECK that fired**, not the outcome that followed — "PUT B refused with
  its own error code, at the message it refused" rather than "PUT A completed and PUT B did not".
* **Coverage is total, and fail-open survives.** Every objective gets a key. The bucket table pins the keys seen in
  THIS corpus, so a genuinely new phenomenon in a later corpus produces a key in no row and lands in the visible
  residual.

**C4 is NOT free — this is the trap.** A key is a *signature*, not a proof of one cause: a single error code can have
several reasons behind it. Keying buys disjointness and coverage, never homogeneity. Audit for homogeneity separately
(see the screen in the audit procedure below).

### The precedence ladder

The key is the FIRST applicable rung, most security-bearing first. The rungs are protocol-agnostic; what fills them is
not.

| Rung | Key | What it captures |
|---|---|---|
| 1 | `named:<mechanism>` | a documented mechanism recognised semantically (findings, harness gaps, known upstream bugs) |
| 2 | `<security>_unexplained:<role>` | the PUTs disagree on a security-bearing outcome (authentication, access) and the disagreement is NOT a consequence of the losing side having already failed earlier → audit pile, never benign |
| 3 | `<crypto-reject>:<role>:<cause>` | one PUT rejected on an integrity/crypto check; the key names WHY the input was invalid |
| 4 | `status:<role>:<side>:<error-class>` | execution-status divergence, keyed on the FIRST-failing PUT and its own check |
| 5 | `claim:<role>:<side>:<error-class>` | exactly one PUT reached a protocol milestone (e.g. finalised key exchange), keyed on the one that did NOT |
| 6 | `shape:<role>:<first-difference>` | output-only divergence: the first position at which the two transcripts differ |

**Rung 2 is what makes the lower rungs safe to call benign.** A benign bucket may absorb a security-outcome
disagreement ONLY when that disagreement is a consequence of the bucket's own cause — i.e. the losing PUT had already
stopped before the deciding step. Encode that test explicitly; never assume it. Without rung 2, a benign bucket keyed
on an error string will quietly swallow genuine accept/reject divergences (this is exactly how a CVE was mislabelled
benign for an entire campaign).

### Deriving sub-causes from data, not from guesses

Where a rejection's cause cannot be read off the error string, derive it empirically: collect the input shapes the
rejecting PUT **accepted** elsewhere in the corpus, then classify a rejected input by whether its shape is in that
reference set. Always state the reference's coverage — it is a heuristic, and inputs in its tail will be
misattributed. Worked example: `evaluation-ddyf/ssh/ssh_rootcause.py`, whose AEAD rung distinguishes
"mutated key schedule" from "non-canonical exchange hash" against two `aead_accepted_*.json` reference sets built from
traces the PUT fully accepted.

### When to prefer keying over hand-written conditions

Use keying when the corpus is large (>10k objectives), when one cause plausibly spans many outcomes, or when a previous
cut is suspected of outcome-keying. Hand-written conditions remain fine for a small corpus, or for pinning one exact
transcript shape. The two compose: rung 1 (`named:`) is exactly a set of hand-written semantic predicates, evaluated in
order, on top of the mechanical rungs beneath.

## Anti-patterns that v2 did not catch

### Anti-pattern E: adding a rule to a precedence ladder without diffing the populations

When buckets are keyed by a precedence ladder (first applicable cause wins), a rule's **position is part of its
meaning**. A rule that is correct in isolation can still be wrong where it sits, because it may out-rank an
existing cause that already explains the same traces.

Worked example (SSH re-cut, 2026-09-25). A rule `broken_key_schedule_term` was written to rescue ~862 traces
that passed every reference-set check and were nonetheless plainly broken on the face of the term. Placed early
in the ladder it captured **259,272** traces, because a structurally broken schedule is usually also a form the
peer never accepted anywhere — so it simply out-ranked the existing `mutated_key_schedule` cause and renamed an
already-established one. Moved to the end of the ladder, just before the fall-through, it captured 861 and left
the large buckets untouched.

**The validation that catches this is a population diff, not a target check.** Confirming the new rule fires on
its intended traces (861/862) passes in BOTH placements. What distinguishes them is re-keying a sample of every
OTHER bucket and confirming it is unchanged — in the worked example, 150/150 from each of the three large
neighbours. Do that whenever a rule is added to or moved within a ladder.

Corollary: do not widen a rule to absorb its own last exception. One of the 862 was not captured and was left in
the fail-open residue. A rule stretched until it has no exceptions has stopped being a claim about a mechanism.

### Anti-pattern F: a cause established by measurement is not the same as a cause encoded in a rule

A bucket's tag describes what the RULE establishes, not what the analyst happens to know about the traces
currently in it. In the same campaign, the residual `*_unexplained` AEAD bucket was measured — by executing every
trace in it and comparing the attacker's computed exchange hash against the PUT's own session-id claim — to be a
mismatch in 3,772/3,772, i.e. the cause was established for that population. The bucket nonetheless kept its
AUDIT tag, because no rule distinguishes it: a future corpus landing traces there would inherit a label nothing
had verified for them. Record the measurement in the bucket's explanation, keep the tag honest, and say plainly
which traces were measured and which rule (if any) would catch them again.


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

1. **Read the five criteria above and check each.** Write the result on a checklist.
2. **If any criterion fails**, do not proceed — split or tighten the condition, then re-check.
3. **Once all five pass**, add a `# GRANULARITY AUDITED` comment alongside `# PENDING REVIEW`.
4. **After all buckets pass**, run the triaging script. Any bucket folder that is now empty must be deleted from the script. Any trace falling into the catch-all `non_triaged` must be investigated (it indicates a missing bucket).

The Auditor in Phase 3+ will re-verify Criteria 1–5 independently on every `# GRANULARITY AUDITED` bucket. Do not skip the self-audit just because the Auditor will run it.

### Heterogeneity screen — a cheap, mechanical C4 pre-filter

C4 ("no hidden second root cause") is the criterion that does not survive scale: nobody reads 200 buckets' metadata by
hand. Screen them first, then audit the flagged ones.

For each bucket, compute the distribution of a signature built **only from features NOT used to form the bucket** —
typically both PUTs' error classes, the set of difference kinds, and a few boolean milestone flags (did each side reach
authentication / the connection phase). Report the share held by the most common signature. A bucket carrying one root
cause concentrates; a bucket carrying several spreads.

Two rules for reading the result, both learned the hard way:

1. **It over-flags by design.** A bucket keyed on one PUT's check leaves the other PUT's reaction free to vary, so
   diversity there is expected and is NOT by itself evidence of a second cause. Treat the output as a *ranked list for
   the C4 audit*, never as a verdict.
2. **Calibrate before believing it.** Include buckets you are confident are single-cause; if they do not score near
   100%, the signature is wrong, not the buckets. (In the SSH campaign the mechanical `claim:`-rung buckets scored
   99.8–100%, which is what made a 25% score elsewhere worth investigating.)

Prioritise flagged **named/finding** buckets over flagged benign ones: in a named bucket a hidden second cause corrupts
a finding, whereas in a mechanical bucket it usually only splits a count.

### Outcomes of the granularity audit

Each bucket lands in exactly one of three states after the audit:

| Outcome | Marker | Meaning |
|---|---|---|
| **Accepted** | `# GRANULARITY AUDITED` | All five criteria pass; bucket stands as-is. |
| **Pending revision** | `# REVISION NEEDED: <reason>` | One or more criteria fail; bucket needs splitting or tightening before next pass. |
| **Refuted (for a specific speculative claim)** | `# GRANULARITY AUDITED; SPECULATIVE CLAIM X REFUTED` | The bucket itself remains a valid RFC violation / BENIGN difference (Criteria 1–4 pass for what it actually classifies), but an attached speculative attack path was structurally refuted. Add a 1–2 line note in the bucket comment pointing to the refutation, e.g., `# Speculative path "weak key recovery via HRR group confusion" REFUTED — tls13_client.c:443 returns 0 before key_share_generate is reached. See BUGS/libressl_bad_key_share_stoc.md §10.` |

The third outcome is needed when a bucket was created with a hypothesis attached and the hypothesis didn't hold up. Demoting the bucket entirely is wrong (the symptom is still observable and may still be an RFC violation); silently dropping the hypothesis is also wrong (it leaves stale claims in `SUMMARY_BUCKETS.md` §5 Speculative). The audited+refuted-claim marker is the honest middle ground.

When recording a refutation, follow the stale-claim audit step in `ORCHESTRATOR.md` to propagate the change to `SUMMARY_BUCKETS.md`, `BUCKET_LIST.md`, `CAMPAIGN_REPORT.md`, and the bug report's "Speculative Attack Paths" section.

---

## When splitting is not possible

If a candidate bucket genuinely cannot be split (all traces analysed share the same root cause and same constraints), Criterion 4 passes trivially. But Criterion 1 still applies: the difference must be specific, not generic. A bucket of 4 traces with a single root cause is fine; a bucket of 4 traces with `KnowledgeDiffC(...)` alone is not, even if all 4 share a root cause — the condition must encode it.

If a candidate bucket cannot be tied to any root cause, it is **not** benign by default (Criterion 5): name it `*_unexplained` and treat it as an audit pile. Only if non-determinism is **demonstrated** — re-executing the same traces gives different outcomes — tag `[BENIGN]` with a `flaky` or `non_deterministic` suffix, record the re-execution evidence in the comment, and keep the condition minimal.

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
