# Investigation Prompt Template

Use this template when delegating a targeted source-code investigation to a separate LLM session. The session receives the finding and the technical question but **not** your reasoning or conclusion — the goal is an independent walk.

---

## When to use this template

Delegate when all three conditions hold:
1. A finding has a speculative path you cannot structurally refute from metadata alone.
2. The path requires reading 200+ lines of vendor source not already in your context.
3. The question is answerable with a clear verdict (see verdict format below).

Do not delegate vague questions ("is this interesting?"). The question must be specific enough that the investigator can answer YES / NO / NEEDS MORE EVIDENCE with a line-of-code citation.

---

## Template

Copy the block below into the investigation session. Fill in all `<placeholder>` fields.

```
## Investigation task: <short title>

### Context

We have identified a <RFC violation / implementation defect / speculative attack path> in
<PUT name and version> at:
  - Affected source: <file:line in vendor/>
  - Affected function: <function name>

The defect is documented at: <campaign>/BUGS/<root_name>.md

### Technical question

Does <specific mechanism X> prevent <specific attack Y>?

More precisely:
  - The attacker's position: <what the attacker controls / injects>
  - The conjectured effect: <what state the target PUT reaches>
  - The specific question: does <function/check at file:line> block the path at <step>?

### What to investigate

1. Read <file1:line_range> and <file2:line_range> in `vendor/<lib>/src/vendor/`.
2. For each gate the attacker must bypass on the conjectured path:
   a. Name the specific line of code.
   b. Name the exact byte-level value the attacker must produce.
   c. Trace that value's source. If it derives from a secret the attacker doesn't have,
      name the gate as REFUTED.
3. Check whether the same check exists in the comparator PUT at <comparator_file:line>.

### Verdict format

Report your conclusion as exactly one of:

  NOT A BUG — <mechanism X> provably prevents <attack Y>. Key evidence: <file:line>.
  CONFIRMED — <attack Y> is plausible. Gates walked; no refutation found. Next step: <what>.
  NEEDS MORE EVIDENCE — gate <N> is ambiguous; resolving it requires <specific evidence>.

Do not optimize for agreement with any prior analysis. If a gate refutes the path, name
the gate and the line. If a gate is genuinely uncertain, say so.
```

---

## On return: recording the verdict

| Verdict | Action |
|---|---|
| `NOT A BUG` | Add an appendix to the bug report (see `libressl_record_overflow_bypass.md` for example). Apply the stale-claim audit sweep per `ORCHESTRATOR.md`. |
| `CONFIRMED` | Promote the finding per the CVE-candidate track in `SECURITY_GATE.md`. Update `SUMMARY_BUCKETS.md` §2. |
| `NEEDS MORE EVIDENCE` | Add to the bug report's speculative-paths section with explicit "what is missing to verify" language. |

---

## Worked example

The fragmentation-reassembly investigation from this campaign used the following structure:

- **Technical question:** Does LibreSSL's handshake-message fragment reassembly allocate up to 16 MB based on the raw 24-bit length field, or is it capped before allocation?
- **Source targets:** `vendor/libressl421/src/vendor/ssl/ssl_both.c:320` and `vendor/libressl421/src/vendor/ssl/tls13_handshake_msg.c:148`
- **Verdict received:** `NOT A BUG — TLS 1.2 path capped at s->max_cert_list (100 KB default) at ssl_both.c:328; TLS 1.3 path capped at 256 KB at tls13_handshake_msg.c:148.`
- **Action taken:** Added appendix to `libressl_record_overflow_bypass.md`; updated `CAMPAIGN_REPORT.md` §7.2 Deep Payload Smuggling rejection reason.
