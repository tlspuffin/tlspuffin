# Security Gate — Discipline for the `[VULN]` Tag and CVE Candidates

This checklist is a discipline for **tagging**, not for **thinking**. Its purpose is to prevent inflating CVSS scores by demanding evidence for every claimed impact. It is not meant to suppress creative analysis — see "Speculative attack paths" at the bottom of this file for where unverified-but-interesting ideas live.

## Three tracks for findings

Findings now live on one of three tracks:

1. **`[VULN]` track (strict)** — the original 5-gate discipline below. Findings that pass all 5 gates get the `[VULN]` tag and an unconditional CVSS ≥ 4.0 attached.
2. **CVE-candidate track (new, broader)** — findings that fail one or more strict gates but nevertheless have (i) empirical end-to-end PoC verification, (ii) a defensible CVSS framing with non-zero score under at least one scenario (e.g., compounded with another peer-side bug, or under specific deployment conditions), and (iii) a documented upstream filing path. These go in §1 of `SUMMARY_BUCKETS.md` as **CVE candidates** even without an assigned CVE number.
3. **Speculative track** — unverified-but-interesting ideas, lives in "Speculative attack paths" sections, never scored, never aggregated.

The distinction between (1) and (2) is whether the bug is independently exploitable in isolation. `[VULN]` requires it; CVE candidate does not — Path α with a second peer-side bug, or a non-zero CVSS only under a specific framing (e.g., `SSL_OP_ALL` developer-trap impact), is sufficient.

## What the strict (`[VULN]`) gate does and does not do

**The strict gate is strict about:**
- Assigning the `[VULN]` tag (requires all 5 gates pass with evidence)
- Attaching an *unconditional* CVSS > 0.0 (same requirement)
- Writing a bug report that *claims* independent exploitability

**The strict gate does NOT constrain:**
- How you think about a finding
- Whether you document attack ideas you cannot yet verify
- Whether you investigate creative combinations, deployment-specific scenarios, or side-channel angles
- Whether you write a research note about a speculative path
- **Whether the finding is a CVE candidate**. CVE-candidate inclusion (Track 2 above) has its own criteria — see `SUMMARY_BUCKETS_TEMPLATE.md` §1 Legend. A finding can fail Gate 1 (no Finished claim in the corpus) and still be a CVE candidate if criteria (i)–(iii) are met.

A finding that fails the strict gates in isolation is **not necessarily uninteresting** — it just is not (yet) a demonstrated independent exploit. The right home for partially-verified findings is Track 2 (CVE candidate) if the empirical/CVSS/disclosure-path criteria are met, or Track 3 (Speculative) if not.

**Rules for the strict (`[VULN]`-tagging) track:**
- Answering "probably yes" without evidence is not acceptable for a `[VULN]` tag.
- If any gate fails, the finding does not get `[VULN]`. Consider whether it qualifies as a CVE candidate (Track 2) before defaulting to `[RFC]` CVSS 0.0.
- A failed gate is conclusive for the *current evidence*, not for *all time*. If new evidence emerges later (e.g., a specific deployed application is found that has the vulnerable pattern), the gate can be re-run.

**Rules for the CVE-candidate track (Track 2):**
- Promotion to §1 requires explicit evidence of all three criteria (i) empirical PoC, (ii) non-zero CVSS framing, (iii) disclosure path.
- The bug report's §6 must state which strict gates the finding fails and why CVE-candidacy is still warranted.
- Multi-framing CVSS is encouraged (e.g., "0.0 in isolation; X.X compounded with peer bug Y"). Always state the framing alongside the number — never present a single number without naming the scenario.
- Disclosure path = identified upstream contact + drafted email or filing plan committed to the repo.

**Rules for the speculative (research-notes) track:**
- Encouraged whenever a finding seems exploitable "with effort" but the evidence is not yet there.
- Must be clearly labeled "Speculative — not a CVE claim."
- Must state what would need to be true (new evidence, new combinations, specific deployment) for the finding to escalate to Track 1 or Track 2.
- Lives in a separate section of the bug report (`## Speculative attack paths`) or in `CAMPAIGN_REPORT.md` under "Research notes."
- Never aggregated into the CVE-candidate / RFC totals. Never assigned a CVSS score.

---

## Gate 0 — Upstream-build verification  *(mandatory for Track 1 and Track 2)*

**Question:** Does the finding reproduce against the stock upstream source, or is it a DDYF / fuzz-fork artefact?

**Why this gate exists:** The PUTs in `vendor/` are not stock upstream tarballs — they are fuzz-instrumented forks (e.g., `github.com/tlspuffin/libressl` branch `fuzz-v4.2.1`, not `github.com/libressl/portable` v4.2.1). Most patches are RNG-determinism and secret-extraction work, but in principle a patch could touch the affected file. Before promoting a finding to `[VULN]` or CVE-candidate, confirm the upstream is affected.

**How to check** (in order; stop at the first failure):

1. **Identify the vendor source.** Read `puffin-build/vendors/<lib>/presets.toml` (or the campaign's equivalent build manifest). Note the upstream repo, branch/tag, and version.
2. **List DDYF patches.** Look at:
   - `puffin-build/vendors/<lib>/*.cmake` (build-time patches)
   - `vendor/<lib>/src/vendor/patches/` (in-tree patches)
   - `vendor/<lib>/src/vendor-stamp/patch-*.txt` (CMake patch step log)

   Confirm none of the patches touch the file(s) named in the bug report's "Root cause" section. If any do, the finding may be a DDYF artefact — escalate before promoting.
3. **Cross-check the affected line(s) against canonical upstream.** Use `gh api repos/<org>/<repo>/contents/<path>?ref=<tag> --jq '.download_url'` then `WebFetch` of the resulting `raw.githubusercontent.com` URL. Quote the upstream line number(s) in the bug report — they will differ from the vendor line numbers but the surrounding code must match.
4. **Cross-check against current upstream `master`/`main`.** A finding fixed since the vendored snapshot is a non-issue. The upstream changelog is the cheapest place to check first.
5. **For defaults / config-default findings, also cross-check the comparator implementation.** OpenSSL ⇄ LibreSSL, BoringSSL ⇄ OpenSSL, etc. — what is their default, and when did it last change? An old comparator-fix is a strong piece of evidence; an old comparator-divergence is the bug report's most compelling argument.
6. **Maintainer-history check** *(mandatory for defaults / config-default findings being promoted to CVE candidate)*. The goal is to pre-empt the "we knew it, it's documented, we accept the trade-off" maintainer pushback before sending the disclosure. Run:
   - **Commit history search** — `gh api -X GET "search/commits" -f q="repo:<org>/<repo> <option-name>"` for the affected option and related options. Read the commit messages chronologically; identify whether the team has actively considered the option, audited the macro it lives in, or made deliberate choices about defaults.
   - **Mailing-list / issue-tracker search** — for OpenBSD-tree projects, `marc.info` for `openbsd-tech@`/`libressl@`; for GitHub-tree projects, `gh api -X GET "search/issues" -f q="repo:<org>/<repo> <term>"`.
   - **Documentation acknowledgement check** — does the affected function's man page already flag the security implications? If yes, the team has known about it for years.

   **What to do with the findings:** record them in the bug report under a new "Maintainer history" subsection (§5c-bis of `BUG_REPORT_TEMPLATE.md`). Frame the ask in the disclosure email as "revisit the trade-off given new evidence X/Y" rather than "you missed this." Cite specific commits with SHAs and dates so the maintainers can see you did your homework.

   **If the team has explicitly considered and rejected the change in a public thread,** the disclosure email must acknowledge that thread by URL and explain what new evidence justifies a re-examination (e.g., a new variant that wasn't foreseeable at the time of the original decision, comparator-implementation precedent, real-world impact survey). Reports that ignore prior deliberation invite a one-line "see thread X, we settled this in 20XX" dismissal.

**What to put in the bug report:**

- A short "Upstream-build confirmation" subsection in §4 (Root cause) or §2 (Security Gate Results) with a table of `Site / Vendor build / Upstream OPENBSD_X_Y (or equivalent tag) / Upstream master / Status`. The renegotiation bug report's §4 is the worked example.
- If the comparator implementation has the analogous code, a "Counter-evidence from [Comparator]" subsection citing the relevant fix commit and version.
- A "Documentation acknowledgement" subsection if the affected function's man page / API doc already flags the issue. (E.g., the renegotiation report cites `man.openbsd.org/SSL_CTX_set_options.3` self-acknowledging the security implications of the default.)

**Outcomes:**

| Outcome | Track 1 (`[VULN]`) | Track 2 (CVE candidate) |
|---|---|---|
| Upstream confirmed affected | proceed | proceed |
| Upstream affected, fixed in newer release | downgrade to a "fixed upstream" note; consider Track 3 only | downgrade similarly |
| Upstream NOT affected (DDYF patch is the cause) | NOT a VULN | NOT a CVE candidate; demote to "DDYF research artefact" |
| Comparator has the same code (no divergence) | does not change Track 1; still investigate the protocol-level issue | weakens Framing B (developer trap) considerably; reconsider promotion |
| Comparator has fixed it (clear divergence) | does not change Track 1 | **strengthens** the case for Track 2 promotion considerably |
| Maintainers have explicitly considered & rejected the change | does not change Track 1 (security claim stands regardless of policy) | does not block Track 2, but the disclosure email MUST cite the prior thread and explain what *new* evidence justifies revisiting. Without that, the report risks a one-line "we settled this in 20XX" dismissal. |
| Maintainers have not (visibly) discussed the option, but have recently maintained related code | as above | the bug report and disclosure email should cite the recent activity (commits adding *new* options without flipping this one) — frames the ask as "you had the chance recently and chose not to; here is why we think the trade-off has shifted" |

**This gate runs FIRST**, before Gates 1–5. The Security Gates as a whole are about *what the attacker can do*; Gate 0 is about *whether the defect even exists in the build you're claiming to attack*. A finding that fails Gate 0 cannot fail or pass Gates 1–5 in a meaningful way.

---

## Gate 1 — Did a handshake complete in the vulnerable PUT?

**Question:** Does the target PUT emit a `Finished` claim on the traces in this bucket?

**How to check (exhaustive — do not sample):**
```bash
for T in objective/<bucket>/*.trace; do
  ./target/release/tlspuffin --put <PUT> display-execute $T -tckp 2>/dev/null \
    | grep -c "Finished {"
done
```
Or read the pre-generated `metadata_<PUT>_T.log` files from Phase 0.

| Answer | Action |
|---|---|
| **No Finished claim in any trace** | The finding does not get `[VULN]` based on current evidence. Tag `[RFC]` CVSS 0.0. If you suspect a path to exploitation (specific deployment, chained with another finding, side channel), capture it under "Speculative attack paths" — but do not score it. |
| **Finished claim present in at least one trace** | Record the exact claim text. Continue to Gate 2. |

---

## Gate 2 — Is the Finished claim from the agent that processed attacker input?

**Question:** Did the agent that received the attacker's crafted term emit the Finished claim — or was it a separate legitimate agent?

A trace may have two or more agents. A Finished claim from agent.1 (legitimate server running a normal handshake) is irrelevant to a claimed attack on agent.0 (the target processing attacker input).

**How to check:**
- Read the trace term structure: which `AgentName(N)` received the attacker's malicious term?
- In the Finished claim: does `client_random` match the ClientHello that carried the attacker's payload? Does `outbound: true` come from the correct agent?
- Check `server_random`: a value of `[1,1,1,...,1]` (all ones) is the tlspuffin stub value, indicating no real server participated — the "Finished" is an artifact of the state machine advancing, not a genuine completed handshake.

| Answer | Action |
|---|---|
| **Finished is from a separate legitimate agent** | The attacker did not cause this Finished. No `[VULN]` based on current evidence; tag `[RFC]` CVSS 0.0. Speculative attack paths can still be noted if you see a route to making the attacker cause it. |
| **Finished is from the agent processing attacker input, with a real server_random** | Continue to Gate 3. |

---

## Gate 3 — Are the derived keys non-zero?

**Question:** Are `handshake_secret`, `master_secret`, or equivalent key fields in the Finished claim non-zero?

**How to check:**
Look at the Finished claim output:
```
Finished {
    handshake_secret: [X, X, X, ...],   ← must be non-zero
    master_secret:    [X, X, X, ...],   ← must be non-zero
    ...
}
```

**Known traps:**
- TLS 1.3 key fields (`early_secret`, `handshake_secret`, `master_secret`) are **always zero on TLS 1.2 code paths** regardless of session outcome — this is structural, not a security signal.
- A Finished claim with all-zero key fields means the key schedule was never properly initialised (e.g., the TLS 1.3 cipher was selected but the TLS 1.2 key exchange ran, producing nothing). This is an RFC violation, not an exploitable session.
- `authenticate_peer: false` confirms the peer was never authenticated; combined with zero keys this is a conclusive Gate 3 failure.

| Answer | Action |
|---|---|
| **All key fields are zero** | No real key derivation; no `[VULN]` based on current evidence. Tag `[RFC]` CVSS 0.0. (If the zero-key state itself is the security claim — e.g., it bypasses an application-level check that mistakes "Finished claim emitted" for "session established" — that is a Speculative attack path worth noting.) |
| **Keys are non-zero** | Continue to Gate 4. |

---

## Gate 4 — Are all independent defense layers absent?

**Question:** Are there source-code checks elsewhere in the target PUT that would independently prevent the attack, even if the specific missing check you found is absent?

This gate is the most common source of premature VULN tags. A missing check A does not constitute a vulnerability if check B or C blocks the same attack.

**How to check:**
1. Identify the precise vulnerable code path (file, function, line).
2. Trace the data flow from attacker input to the point of claimed impact.
3. For **every** function called along that path, read the source to confirm it does not independently validate the input.

**Common TLS defense layers to check:**
| Layer | Location | What it checks |
|---|---|---|
| EC point on-curve | `ec_lib.c: EC_POINT_set_affine_coordinates` | Rejects off-curve points at parse time |
| ECDH peer point | `ecdh.c: ecdh_compute_key` | Second on-curve check before `EC_POINT_mul` |
| AEAD/MAC verification | Record layer | Attacker-modified ciphertext fails decryption |
| Certificate chain | `ssl_cert.c`, `x509_vfy.c` | Untrusted cert → handshake aborted at verify |
| Finished MAC | Handshake layer | Wrong keys → Finished MAC verification fails |
| Key confirmation | Session layer | Data exchange only begins after Finished verifies |

Document each layer checked and whether it was found to be present or absent.

| Answer | Action |
|---|---|
| **A defense layer is present** | Document which layer and why. No `[VULN]` based on current evidence. Tag `[RFC]` CVSS 0.0. If the defense layer can plausibly be circumvented under specific conditions (deployment misconfiguration, side channel, combined with another finding), record it as a Speculative attack path. |
| **All layers confirmed absent after full source audit** | Continue to Gate 5. |

---

## Gate 5 — Is the attack end-to-end exploitable?

**Question:** Can you write a concrete attack scenario with specific inputs and a specific harmful outcome?

Required elements:
1. What exactly does the attacker send? (specific message types, contents)
2. What state does the target PUT reach after receiving it? (cite the claim/log)
3. What does the attacker gain? (data readable, data injectable, authentication bypassed)
4. Does the attack require capabilities the attacker is unlikely to have (e.g., a trusted CA cert, the server's private key)? If so, the attack requires preconditions that are stronger than the vulnerability itself.

**Disqualifying conditions:**
- "The attacker would also need to forge the server's certificate" → not exploitable without the private key
- "The handshake fails at certificate verification regardless" → no session established
- "The attacker gets a Finished claim but with zero keys" → no real session (Gate 3 failure, re-check)

| Answer | Action |
|---|---|
| **Cannot write a concrete end-to-end scenario** | No `[VULN]` based on current evidence. Tag `[RFC]` CVSS 0.0. Write down the scenario sketch you considered (even if incomplete) as a Speculative attack path — it is exactly the kind of note that future work can revisit. |
| **Concrete scenario constructed** | Tag `[VULN]`. Score with `CVSS_TLS.md`. Write report with `BUG_REPORT_TEMPLATE.md`. |

---

## Gate summary

| Gate | Question | Fail action |
|---|---|---|
| 0 | Defect reproduces against stock upstream (not just the DDYF fuzz-fork)? | Demote to "DDYF research artefact"; not a Track 1/2 finding |
| 1 | Finished claim present? | No `[VULN]`; tag `[RFC]` CVSS 0.0; consider Speculative note or Track 2 (CVE candidate) |
| 2 | Finished from agent processing attacker input, with real server_random? | No `[VULN]`; tag `[RFC]` CVSS 0.0; consider Speculative note |
| 3 | Key fields non-zero? | No `[VULN]`; tag `[RFC]` CVSS 0.0; consider Speculative note |
| 4 | All defense layers absent (confirmed by source read)? | No `[VULN]`; tag `[RFC]` CVSS 0.0; consider Speculative note |
| 5 | Concrete end-to-end exploit constructible? | No `[VULN]`; tag `[RFC]` CVSS 0.0; consider Speculative note |

Gate 0 must pass for the finding to be considered at all. Gates 1–5 must all pass to assign `[VULN]` and unconditional CVSS > 0.0 (Track 1). A finding that passes Gate 0 but fails one or more of 1–5 may still qualify as a CVE candidate (Track 2) if it has empirical end-to-end PoC + non-zero CVSS under at least one framing + a drafted disclosure path.

Speculative attack paths are encouraged; they live in their own section so they don't pollute the verified findings.

---

## Chained-bug claims

Combining two or more findings to investigate an escalation is **encouraged** — it is exactly the kind of out-of-the-box thinking that turns a "boring" set of RFC violations into real attacks. Two separate tracks apply:

**Strict track (CVE tagging via chain):** if you want to assign `[VULN]` and CVSS > 0.0 to a chain, apply the Security Gate to the **chain as a whole**, exactly as for a single finding. The bar is the same:
- The chain must produce a single concrete attack with a single concrete impact (not "increases attack surface").
- Gate 4 must enumerate defense layers; if the sink is caller code, the caller must be a real, named, deployed application.
- Gate 5 must produce a runnable end-to-end scenario, not a research direction.
- Each component's Gate 4 conclusion carries through. The chain only escalates above CVSS 0.0 if it cites *new* missing defenses created by the combination.

**Speculative track (research notes via chain):** if the chain is interesting but you cannot meet the bar above, write it as a Speculative attack path. State:
- Which findings are combined
- What the conjectured impact is
- What is missing to elevate it to a verified CVE (concrete sink, deployment, side channel)
- Whether the components' defense layers can plausibly be circumvented under the conjectured conditions

A speculative chain is valuable scientific output for an academic paper — reviewers reading future work / discussion sections will appreciate it. It is not valuable when laundered as a "Critical RCE" without evidence.

---

## Speculative attack paths — guidance

This is where unverified-but-interesting analysis lives. Use it whenever the strict gate fails but you have a hypothesis worth recording.

### When to write a speculative note

- A finding fails one or more gates, but you can sketch a path to exploitation under specific conditions.
- Two or more findings, none individually `[VULN]`, look like they might compose into something useful.
- A defense layer is present today but its assumption is fragile (e.g., depends on a configuration default that some deployments override).
- You see a side-channel angle (timing, error-message content, allocation pattern) that the gate doesn't directly evaluate.
- Future protocol versions, future API uses, or future deployments would change the gate's answer.

### How to write one

In the bug report add a section:

```markdown
## Speculative attack paths

> **Status:** Speculative — not a CVE claim. No CVSS score assigned.

### Path 1: [short title]

**Conjectured impact:** [what the attacker would achieve]

**Mechanism:** [step-by-step sketch of what the attacker does]

**What is missing to verify:**
- [specific evidence that would close Gate N]
- [specific deployment / configuration that would need to exist]
- [specific other finding that would need to combine with this one]

**Reason this is not the strict-track CVE:**
[which gate(s) fail and why current evidence is insufficient]
```

For the campaign-level view, the same section can appear in `CAMPAIGN_REPORT.md` under "Research notes / speculative attack paths." Group related speculations together if they share a sink or a deployment assumption.

### What speculative notes are NOT

- Not a substitute for the strict-track CVE process. Speculative notes do not assign CVSS, do not appear in CVE-count totals, do not get tagged `[VULN]` in the triaging script.
- Not a place to write "RCE potential" without sketching the mechanism. If you cannot describe what the attacker does step-by-step, the note isn't ready — leave it out until it is.
- Not a free pass for hand-waving. "Host applications often do X" is still hand-waving in a speculative note. Name a real deployment pattern, even if you cannot name a specific deployed application.

### Speculative notes and the Auditor

The Auditor reviews speculative notes for:
- Honest labeling (the note must not read as a CVE claim)
- Falsifiability (the "what is missing to verify" section names specific evidence, not vague gestures)
- Reasonable mechanism (the step-by-step is technically coherent, even if unproven)

The Auditor does not reject a speculative note simply because the gates would fail on the current evidence — that is the whole point of having a speculative track. The Auditor rejects a speculative note only if it is mislabeled, unfalsifiable, or technically incoherent.

---

## Path-refutation discipline  *(mandatory before writing up any "high-priority" speculative path)*

Before writing up a speculative attack path as a "high-priority unverified lead" — anything longer than 10 lines, anything claiming a path likely escalates to `[VULN]` "with verification" — first attempt to refute it structurally. This is the single most-time-saving discipline added to v3 after the Path-4 lesson (`BUGS/libressl_wrong_cipher_acceptance.md` §"Speculative Attack Paths"), where ~200 lines of speculative writeup were refuted in minutes by a separate auditor checking one byte-level property.

### The refutation walk

For each state-machine gate the attacker must pass on the conjectured path:

1. **Name the line of code** (`<file>:<line>`) the attacker must bypass.
2. **Name the exact byte-level value on the wire** the attacker must produce to bypass it. Be concrete: not "a value the server expects" but "a 32-byte value equal to `SHA-256(<specific source>)`" or "a 2-byte cipher_suite field equal to `0xc02f`".
3. **Check the value's source.** Walk back to where that value comes from in the protocol. If it's any of the following, the path is **structurally bounded → refuted**:
   - Derived from a secret the third-party attacker does not have (encrypted payload, post-handshake material, server-side state, ticket-derived value, an HMAC the attacker can't compute).
   - Computed from the attacker's own choices in a way that is observable to the legitimate peer and would cause a separate check to fail.
   - Constrained to a small set the implementation enumerates and the attacker's preferred value isn't in.

### When the walk completes

A path is only worth writing up under the speculative track if every gate has been walked and **at least one remains genuinely uncertain** (e.g., depends on a deployment configuration, a side-channel, a missing source-code audit). Otherwise:

- All gates walked, all refuted → record as **REFUTED** (one-line entry in `SUMMARY_BUCKETS.md` §5 with strikethrough on the original claim and a one-sentence structural reason, plus the file:line citation).
- All gates walked, none refuted → not yet falsifiable; this is genuine speculative material. Write it up per the template above.
- Walk incomplete → finish the walk before writing up. Half-walked paths are the source of stale claims that other auditors then refute.

### Worked example — Path 4 of `libressl_wrong_cipher_acceptance.md`

The original speculation: a TLS 1.3-cached session, reused in a TLS 1.2 resumption attempt, would have `master_key = zero` and therefore let an attacker derive predictable keys via `tls1_PRF`.

The refutation walk, gate-by-gate:

| Gate | Bypass requirement | Source of the value | Refuted? |
|---|---|---|---|
| `ssl_clnt.c:660` "drop session if version mismatch" | Cached `sess->ssl_version` must equal `s->version` at ClientHello construction | `s->version = max_version` (TLS 1.3 if client supports it); cached version is TLS 1.3 → match | Pass |
| `ssl_clnt.c:858` `ssl_check_version_from_server` | Server version in range | Attacker chooses TLS 1.2 (in range) | Pass |
| `ssl_clnt.c:955` session_id memcmp | Server's `legacy_session_id_echo` must equal cached `s->session->session_id` (32 bytes) | **Cached value is `SHA-256(ticket)` from `tls13_lib.c:441`. The ticket is sent inside the encrypted post-handshake `NewSessionTicket`. A third-party MITM cannot observe the ticket and cannot compute the hash.** | **REFUTED** |

The refutation took ~10 minutes. The original speculation took ~200 lines and several rounds of bug-report drafting to write up. The lesson is to do the refutation walk *first*.

### Multi-LLM cross-check  *(see `AUDITOR.md` cross-LLM section)*

For compound-attack paths that survive the refutation walk above, the next-best discipline is to have a separate LLM or auditor walk the same gates with no exposure to your reasoning. If the second walk agrees with yours, the path is genuinely speculative and worth writing up. If the second walk refutes a gate you missed, that's the cheapest refutation you'll ever get.
