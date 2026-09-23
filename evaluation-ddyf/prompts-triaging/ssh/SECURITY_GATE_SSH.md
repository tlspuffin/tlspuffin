# Security Gate (SSH) — Discipline for the `[VULN]` Tag and CVE Candidates

> **This file is self-contained for an SSH campaign — you do not need to open any TLS file.**
> Concrete names are the SSH pair `libssh0114` (libssh 0.11.4) vs `wolfssh150` (wolfSSH 1.5.0),
> driven by `sshpuffin`; the normative reference is RFC 4251–4254 (+ 8308/8332/5647/8709).
> *(Maintainer note, not a read instruction: this is the SSH counterpart of the per-protocol
> `tls/SECURITY_GATE_TLS.md`; keep the two structurally in sync when the methodology changes.)*

This checklist is a discipline for **tagging**, not for **thinking**. Its purpose is to prevent inflating CVSS scores by demanding evidence for every claimed impact. It does not suppress creative analysis — see "Speculative attack paths" below for where unverified-but-interesting ideas live.

## Three tracks for findings

Every finding lands on exactly one track:

1. **`[VULN]` track (strict)** — passes all of Gate 0–5 below → `[VULN]` tag + unconditional CVSS ≥ 4.0.
2. **CVE-candidate track (broader)** — fails one or more strict gates but has (i) an empirical end-to-end PoC, (ii) a defensible CVSS framing with non-zero score under at least one scenario, and (iii) a documented upstream filing path (libssh: `bugs.libssh.org` / `git.libssh.org`; wolfSSH: `github.com/wolfSSL/wolfssh` issues / `security@wolfssl.com`). Lands in §1 of `SUMMARY_BUCKETS.md`.
3. **Speculative track** — unverified-but-interesting ideas; lives in "Speculative attack paths" sections; never scored, never aggregated.

The distinction between (1) and (2) is whether the bug is independently exploitable in isolation. `[VULN]` requires it; CVE candidate does not.

## What the strict (`[VULN]`) gate does and does not do

**Strict about:** assigning `[VULN]`; attaching an *unconditional* CVSS > 0.0; writing a report that *claims* independent exploitability.

**Does NOT constrain:** how you think; whether you document attack ideas you cannot yet verify; whether you investigate chained/deployment-specific/side-channel angles; whether the finding is a CVE candidate (Track 2 has its own criteria).

An SSH finding that fails the strict gates in isolation is **not necessarily uninteresting** — most SSH differential findings are RFC-conformance divergences (CVSS 0.0) that are still worth reporting as `[RFC]`. The point of writing this gate is to make the "is this actually an authentication/confidentiality/integrity break?" question **answerable with evidence** instead of skipped.

---

## Gate 0 — Upstream-build verification  *(mandatory for Track 1 and Track 2)*

**Question:** Does the finding reproduce against stock upstream libssh / wolfSSH, or is it a DDYF fuzz-fork / harness artefact?

**Why:** the PUTs in `vendor/` are fuzz-instrumented forks, not stock tarballs. Confirm the upstream is affected before promoting.

**How to check** (stop at the first failure):

1. **Identify the vendor source and pin.** Read `puffin-build/vendors/<lib>/presets.toml` (or the campaign's build manifest). libssh is pinned to **0.11.4**, wolfSSH to **v1.5.0-stable**. Note the upstream repo, tag, and commit.
2. **List DDYF patches.** Look at `puffin-build/vendors/<lib>/*.cmake`, `vendor/<lib>/src/vendor/patches/`, and the CMake patch-step log. Confirm none touch the file(s) named in "Root cause". Most patches are RNG-determinism / secret-extraction work — but if a patch touches the affected file, the finding may be a fork artefact; escalate.
3. **Cross-check the affected line(s) against canonical upstream.**
   - libssh: `git.libssh.org/projects/libssh.git` at tag `libssh-0.11.4` (GitLab mirror: `gitlab.com/libssh/libssh-mirror`).
   - wolfSSH: `github.com/wolfSSL/wolfssh` at tag `v1.5.0-stable` — use `gh api repos/wolfSSL/wolfssh/contents/<path>?ref=v1.5.0-stable --jq '.download_url'` then `WebFetch`.
   Quote the upstream line numbers (they differ from the vendor fork; the surrounding code must match).
4. **Cross-check current upstream `master`/`main`.** A finding already fixed since the pin is a "fixed upstream" note, not a live `[VULN]`.
5. **Cross-check the comparator PUT.** libssh ⇄ wolfSSH: what does the other stack do on the same input, and has it changed? A clear comparator divergence is the report's most compelling argument; a comparator that shares the behaviour weakens the "one stack is wrong" framing.
6. **Maintainer-history check** *(mandatory for behaviour-choice findings promoted to CVE candidate).* Search commit history and issues (`gh api -X GET search/commits`/`search/issues` for wolfSSH; `git.libssh.org` log + `bugs.libssh.org` for libssh) to pre-empt "we know, it's accepted". Record under the report's "Maintainer history" subsection; frame the disclosure ask as "revisit the trade-off given new evidence", not "you missed this".

**Committed external-oracle artifact (mandatory).** Gate 0 must leave a machine-checkable artifact in `${CAMPAIGN}/gate0/<finding>/`: (i) the exact upstream ref (repo + tag + SHA); (ii) the fetched upstream source of the affected function; (iii) a diff (or explicit "no patch touches this file") between the vendor fork and upstream; (iv) the L1+ reproducer transcript where one exists. A reader must reach the same verdict without trusting the narrative.

**Outcomes:** upstream-confirmed → proceed; fixed-in-newer → "fixed upstream" note; upstream-not-affected (fork/harness is the cause) → **not a VULN/CVE candidate; demote to DDYF research artefact**; comparator shares the code → weakens Track 2 (developer-trap framing); comparator has fixed it → strengthens Track 2.

**This gate runs FIRST.** A finding that fails Gate 0 cannot meaningfully pass or fail Gates 1–5.

### SSH-specific Gate-0 trap: harness vs library

The single most important SSH Gate-0 check. sshpuffin's oracle is **claim-based** (`check_violation` is a `None` stub; the differential signal is the `SshClaimInner` claims emitted by the C harnesses `sshpuffin/harness/{libssh,wolfssh}/src/put.c`). A claim can therefore fire from a harness callback **before** the library's own cryptographic verification runs — producing a "one stack authenticated, the other didn't" symptom that is **indistinguishable in the metadata from a real auth bypass** but is actually a defect in the measurement apparatus.

Before treating any auth/channel claim as in-library state, confirm which side emitted it and when:

1. **Locate the claim-emission call** in `sshpuffin/harness/<put>/src/put.c` (`emit_handshake_claim`, and the auth callbacks that set `agent->authenticated`).
2. **Confirm it is gated on the library's post-verification result**, not on a pre-verification callback. The **correct** reference is the libssh harness: `cb_auth_pubkey` (`harness/libssh/src/put.c`) only sets `authenticated` after libssh's `ssh_pki_signature_verify()` has set `signature_state = SSH_PUBLICKEY_STATE_VALID` (`vendor/libssh0114/.../messages.c`). The **known trap** is the wolfSSH harness emitting from `userAuthCb`, which wolfSSH invokes *before* `DoUserAuthRequestRsa()` runs the real RSA check — see `BUGS/sshpuffin_harness_wolfssh_claim_timing.md` for the worked example.
3. **Confirm on the wire.** Decrypt the s2c transcript (`differential-execute` decryption recipe). If the stack that "claimed success" actually sent `SSH_MSG_USERAUTH_FAILURE` (msg 51), the claim is a harness false-positive → **not** a library finding. Classify it as a **Bug (non-RFC) in sshpuffin itself** (see `../TEMPLATES.md` § "When the finding is in the fuzzer/harness itself"), CVSS N/A.

---

## Gate 1 — Did authentication / a channel actually succeed in the vulnerable PUT?

**Question:** Does the target PUT emit an **authentication-success or channel-established claim** on the traces in this bucket, while processing attacker input?

The SSH analogue of the TLS `Finished` claim. In sshpuffin the relevant claim carries `authenticated`, `auth_user`, `auth_method`, and `session_id` (see `emit_handshake_claim`).

**How to check (exhaustive — do not sample):**
```bash
for T in objective/<bucket>/*.trace; do
  b=$(basename "$T")
  # a claim with a non-empty auth_user / authenticated=true is the success signal
  grep -c "authenticated: true\|auth_user: \"[^\"]" "objective/<bucket>/metadata_${PUT}_${b}.log"
done | sort | uniq -c
```
Or read the pre-generated `metadata_<PUT>_T.log` (or `-tckp` display-execute) directly.

| Answer | Action |
|---|---|
| **No success claim in any trace** | No `[VULN]` on current evidence. Tag `[RFC]` CVSS 0.0 (or `[BENIGN]`). If you see a path to exploitation, note it under "Speculative attack paths" — do not score it. |
| **Success claim present in ≥1 trace** | Record the exact claim text (identity + `session_id`). Continue to Gate 2. |

---

## Gate 2 — Is the success claim from the agent that processed attacker input?

**Question:** Did the agent that received the attacker's crafted term emit the success claim — or was it a separate legitimate agent?

**How to check:**
- Read the trace term structure: which `AgentName(N)` received the attacker's substituted term (e.g., the mutated `fn_publickey_auth_data(...)` signature argument)?
- Confirm the claiming agent is that same agent, not an untouched honest peer.

| Answer | Action |
|---|---|
| **Claim is from a separate legitimate agent** | Attacker did not cause it. No `[VULN]`; tag `[RFC]` CVSS 0.0. |
| **Claim is from the agent processing attacker input** | Continue to Gate 3. |

---

## Gate 3 — Is the session actually established (non-zero session id / keys)?

**Question:** Is the `session_id` (SSH exchange hash `H`) in the success claim non-zero, i.e. did a real KEX complete and derive session keys?

**How to check:** inspect the claim's `session_id` / `session_id_len`. SSH derives all session keys from the shared secret `K` and exchange hash `H` (RFC 4253 §7.2); the harness records `H` as `session_id`.

| Answer | Action |
|---|---|
| **`session_id` all-zero / absent** | No real KEX; the "success" is a state-machine artefact (or a harness claim fired before KEX — re-check Gate 0's harness-vs-library trap). No `[VULN]`; tag `[RFC]` CVSS 0.0. |
| **`session_id` non-zero** | Real session material. Continue to Gate 4. |

---

## Gate 4 — Are all independent defense layers absent?

**Question:** Are there source-code checks elsewhere in the target PUT that would independently prevent the attack, even if the specific missing check you found is absent?

The most common source of premature VULN tags. A missing check A is not a vulnerability if check B or C blocks the same attack.

**How to check:** identify the vulnerable path (file:line), trace data flow from attacker input to claimed impact, and read the source of **every** function on that path.

**Common SSH defense layers to check:**
| Layer | Location (libssh / wolfSSH) | What it checks |
|---|---|---|
| publickey signature verify | `messages.c ssh_pki_signature_verify` / `internal.c DoUserAuthRequestRsa` | rejects a `USERAUTH_REQUEST` whose signature doesn't verify against the key |
| host-key verification (client) | `known_hosts` / callback path | server authenticity; blocks a MITM'd server key |
| KEX exchange-hash signature | transport layer (`packet.c`/`kex.c`) | the server's signature over `H` binds the negotiated keys; a tampered KEX is detected |
| AEAD tag (AES-256-GCM) | packet/crypto layer | attacker-modified ciphertext fails tag verification (RFC 5647) |
| channel-open authorization | connection layer (`channels.c`) | a channel only opens after `USERAUTH_SUCCESS` |
| **harness claim gating** | `harness/<put>/src/put.c` | *(SSH-specific)* the claim must be gated on the library's post-verification result — see Gate 0's harness-vs-library trap |

Document each layer checked and whether present or absent. **The harness-gating row is mandatory for any SSH auth/channel finding**: if the only thing "wrong" is that the harness claimed success before the library rejected on the wire, the defense layer (real signature verify) *is present* → Gate 4 fails → not a `[VULN]`, and the finding is reclassified as a Bug in sshpuffin.

| Answer | Action |
|---|---|
| **A defense layer is present** (incl. "the library rejects on the wire; only the harness claim is premature") | Document which layer. No `[VULN]`; tag `[RFC]` CVSS 0.0, or reclassify as a sshpuffin Bug if the divergence is purely a harness artefact. |
| **All layers confirmed absent after full source audit** | Continue to Gate 5. |

---

## Gate 5 — Is the attack end-to-end exploitable?

**Question:** Can you write a concrete attack scenario with specific inputs and a specific harmful outcome?

Required: (1) exactly what the attacker sends (message types + contents); (2) the state the target reaches (cite the claim/transcript); (3) what the attacker gains (data read, data injected, authentication bypassed); (4) whether it needs capabilities the attacker is unlikely to have.

**Disqualifying conditions (SSH):**
- "The attacker would also need the server's host private key" → not exploitable without it.
- "The attacker would also need an authorized client's private key" → the precondition is the authentication it claims to bypass.
- "The session id / keys are zero" → no real session (Gate 3 failure, re-check).
- "Both stacks reject on the wire; only a harness claim diverges" → not a library exploit (Gate 4 harness row).

| Answer | Action |
|---|---|
| **Cannot write a concrete end-to-end scenario** | No `[VULN]`; tag `[RFC]` CVSS 0.0. Record the sketch under "Speculative attack paths". |
| **Concrete scenario constructed** | Tag `[VULN]`. Score with `CVSS_SSH.md`. Write the report per `../TEMPLATES.md` (Bug report). |

---

## Gate summary

| Gate | Question | Fail action |
|---|---|---|
| 0 | Reproduces against stock upstream (not the fuzz-fork), and the claim is library state (not a harness artefact)? | Demote to "DDYF research artefact" / sshpuffin Bug; not a Track 1/2 finding |
| 1 | Auth-success / channel-established claim present? | No `[VULN]`; `[RFC]` CVSS 0.0 |
| 2 | Claim from the agent processing attacker input? | No `[VULN]`; `[RFC]` CVSS 0.0 |
| 3 | `session_id` (exchange hash `H`) non-zero? | No `[VULN]`; `[RFC]` CVSS 0.0 |
| 4 | All defense layers absent (incl. harness-gating row)? | No `[VULN]`; `[RFC]` CVSS 0.0 or sshpuffin Bug |
| 5 | Concrete end-to-end exploit constructible? | No `[VULN]`; `[RFC]` CVSS 0.0 |

Gate 0 must pass for the finding to be considered at all. Gates 1–5 must all pass to assign `[VULN]` + unconditional CVSS > 0.0 (Track 1). A finding that passes Gate 0 but fails 1–5 may still be a CVE candidate (Track 2) with empirical PoC + non-zero CVSS framing + drafted disclosure path.

---

## Chained-bug claims

Combining two or more findings to investigate an escalation is encouraged. To assign CVSS > 0.0 to a chain, apply the whole gate (0–5) to the chain as a single finding: it must produce one concrete attack with one concrete impact, and it only escalates above 0.0 if it cites a *new* missing defense the combination creates (demonstrated, not assumed) — each component's Gate-4 conclusion otherwise carries through. If it can't meet that bar, write it as a speculative path instead. SSH-relevant chains to think about: a KEX/negotiation laxity chained with an auth-layer laxity; a rekey-timing divergence chained with a channel-layer laxity.

---

## Speculative attack paths — guidance

This is where unverified-but-interesting analysis lives when the strict gate fails but you have a hypothesis worth recording. Use the report's `## Speculative attack paths` section with the `Conjectured impact / Mechanism / What is missing to verify / Reason this is not the strict-track CVE` structure (see `../TEMPLATES.md` § 10). Clearly label "Speculative — not a CVE claim"; never assign a CVSS; state what would need to be true to escalate.

The Auditor reviews speculative notes for honest labeling, falsifiability, and technical coherence — it does **not** reject them merely because the gates fail on current evidence.

---

## Path-refutation discipline  *(mandatory before writing up any "high-priority" speculative path)*

Before writing up a speculative path longer than ~10 lines, first try to **refute it structurally**. For each state-machine gate the attacker must pass on the conjectured path:

1. **Name the line of code** (`<file>:<line>`) the attacker must bypass.
2. **Name the exact byte-level value on the wire** the attacker must produce (e.g., "a signature that verifies against the authorized key under `ssh-rsa-sha2-256`", "an AES-256-GCM tag over the forged packet", "the server's Ed25519 signature over the exchange hash `H`").
3. **Check the value's source.** If it derives from a secret the third-party attacker does not have (the authorized client's private key, the server host key, `K`/`H` from a KEX the attacker can't influence, an AEAD tag the attacker can't compute), the path is **structurally bounded → REFUTED**.

A path is worth writing up only if every gate is walked and **at least one remains genuinely uncertain** (deployment config, side channel, missing source audit). All-refuted → record as REFUTED in `SUMMARY_BUCKETS.md` §5 with the file:line reason. Half-walked paths are the source of stale claims that other auditors then refute — finish the walk first. For paths that survive, run the cross-LLM parallel deep audit (`../AUDITOR.md` § Parallel deep audit).
