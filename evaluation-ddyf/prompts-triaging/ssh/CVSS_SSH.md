# CVSS v3.1 Scoring for SSH Differential Findings

> **This file is self-contained for an SSH campaign — you do not need to open any TLS file.**
> Principle: CVSS measures impact on the **system**, not on the protocol specification. An RFC
> MUST violation is an RFC finding regardless of CVSS; CVSS only measures whether the violation
> has a concrete security consequence.
> *(Maintainer note, not a read instruction: this is the SSH counterpart of the per-protocol
> `tls/CVSS_TLS.md`; keep the two structurally in sync.)*

---

## Metric-by-metric guidance

### Confidentiality (C)

`C:H` — Attacker can read application data (channel data, exec/shell output, forwarded-port bytes) from an established SSH session.
`C:L` — Attacker can read partial metadata (e.g., a username echoed where it should not be, a forwarded port number leaked — cf. the wolfSSH `tcpip-forward` port-echo finding).
`C:N` — No application data exposed. Covers: connection aborts before any channel data; a wrong or missing `SSH_MSG_DISCONNECT` reason code; a transport field with the wrong value but nothing leaks.

### Integrity (I)

`I:H` — Attacker can forge or inject authenticated data into an established SSH session (channel data an authenticated peer would accept), or **bypass authentication** and act as an authorized user.
`I:L` — Attacker can corrupt partial protocol state that survives into the session (e.g., a callback / claim consumes unvalidated bytes that a host application then trusts).
`I:N` — No authenticated data is modified. Covers: wrong/missing `SSH_MSG_DISCONNECT` or channel-failure reason codes (diagnostic, not application data); lenient parsing where the connection is ultimately rejected; a premature **harness** claim where the library still rejects on the wire (that is not even an in-library defect — see below).

### Availability (A)

`A:H` — Server or client crashes, or enters a state preventing further connections.
`A:L` — Degraded service: a single connection permanently hung, or a process killed and needing restart.
`A:N` — No availability impact. Covers: **both PUTs abort the connection** (no selective-DoS difference between the two stacks); a wrong disconnect reason code where both peers terminate normally.

### Attack Complexity (AC)

`AC:H` — MITM position required, specific timing needed, or partial session-state knowledge needed.
`AC:L` — Simple packet sending suffices (e.g., any client connecting to a crashing server).

For most DDYF findings the sshpuffin attacker is a Dolev-Yao MITM with full control of the wire, which in the real world requires a MITM position → `AC:H` at minimum. A pre-auth remote crash reachable by any connecting peer is `AC:L`.

Privileges Required (`PR`) is almost always `N` for a network attacker; if the "attack" actually needs an already-authorized private key, that is a disqualifier at Gate 5, not a `PR:L` score.

---

## Reference scores for common SSH finding types

### Silent abort / wrong disconnect reason (RFC 4253 §11.1, RFC 4254)

One PUT sends a `SSH_MSG_DISCONNECT` with a specific reason code; the other silently closes the TCP connection, or sends a different reason code. Both connections abort.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:N / I:N / A:N = 0.0 (None)
```
`A:N` because both connections close — no operational availability difference. The reason-code choice affects diagnostics/interop, not security.

### Over-strict / lenient banner or KEX parsing (RFC 4253 §4.2, §7)

One PUT accepts (or rejects) a banner / `KEXINIT` variant the other does not, but the session does not complete on the lenient side, or completes identically once negotiated.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:N / I:N / A:N = 0.0 (None)
```
"libssh rejects a banner wolfSSH accepts" ≠ "exploitable." If no authenticated session is established from the divergence (Gate 1/3 fail), CVSS is 0.0. (The SSH banner over-strictness and `tcpip-forward` port-echo findings are the worked `[RFC]` examples — CVSS 0.0 / metadata-only.)

### Forwarded-port / field echo leak (RFC 4254 §7.1)

A stack echoes a client-supplied value (e.g., the bound port on `tcpip-forward`) in a reply where the RFC does not require it.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:N / A:N = ~2.0 (Low)  — only if the echoed value is not already known to the attacker
```
In practice the echoed value is the attacker's *own* request, so real information exposure is negligible → treat as `C:N` → 0.0 unless a concrete confidentiality gain is shown. State the framing explicitly.

### Authentication bypass (all Security Gates pass)

Attacker establishes an authenticated session (non-zero `session_id`, `authenticated: true` from the agent processing attacker input) without holding an authorized private key.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:H / I:H / A:N = 7.4 (High)
```

### Pre-auth remote crash reachable by any peer

The server process crashes on a malformed pre-auth message from any connecting client.

```
AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:L = 5.3 (Medium)
```
`A:L` because one instance is killed per connection. **Verify on a non-sanitized build first** — a crash only in the ASan/UBSan-instrumented `vendor/` binary is not automatically a production CVE (see Trap 4).

---

## The sshpuffin-harness (non-library) finding — CVSS is Not Applicable

sshpuffin's differential oracle is **claim-based**, and the claims are emitted by the C test harnesses (`sshpuffin/harness/{libssh,wolfssh}/src/put.c`). A divergence whose root cause is in the harness — most commonly a claim fired from a pre-verification callback while the library itself still rejects on the wire — is a defect in the **measurement apparatus**, not in a network-facing implementation.

For such findings:
- **CVSS v3.1: Not applicable.** State it as "Not applicable — test-harness/oracle instrumentation defect, not a network-facing implementation." Do not invent a vector.
- **Classification: Bug (non-RFC)**, `§3` of `SUMMARY_BUCKETS.md`. Not `[RFC]`, not `[VULN]`, not `[BENIGN]` (even if the bucket is *named* `benign_*` — the SUMMARY category is canonical over the bucket name; see `../NAMING_CONVENTIONS.md`).
- **"Compared against"** = the *other harness* (e.g., "libssh 0.11.4 harness, which gates the claim correctly"), not the other library version.
- See `../TEMPLATES.md` § "When the finding is in the fuzzer/harness itself" for the report shape, and `SECURITY_GATE_SSH.md` Gate 0's harness-vs-library trap for how to confirm it.

---

## Multi-framing CVSS for compound / conditional findings

Default to a multi-framing analysis for any finding whose exploitability depends on (a) compounding with a separate peer-side bug, (b) a specific deployment configuration, or (c) a developer-trap re-introduction of an unsafe default (e.g., a host application disabling host-key checking, or trusting the harness-style claim as an auth oracle). Each framing gets its own row with its own vector and score; state the framing alongside every number — never a single number without naming the scenario. Multi-framing is **mandatory** for Track 2 (CVE-candidate) promotion.

---

## Common scoring traps

**Trap 1: "RFC MUST clause violated → must be I:L or higher."** Integrity measures whether attacker-controlled data enters an authenticated session. MUST violations about disconnect codes, KEXINIT field ordering, or diagnostic messages do not affect data integrity → `I:N`.

**Trap 2: "Auth-success claim present → exploitable."** Check Gates 2, 3, and 0. If the claim is from a separate legitimate agent, or `session_id` is zero, or the claim is a **harness** artefact while the library rejected on the wire, the claim is not a session → CVSS 0.0 (or N/A for the harness case).

**Trap 3: "Handshake/KEX proceeds past a rejection point → downgrade possible."** Proceeding past a check does not establish a session. If the connection aborts before `USERAUTH_SUCCESS` and channel-open, no session keys are usable and no downgrade is possible for that connection. Gate 1/3 catches this.

**Trap 4: "Sanitized build crashes → CVE."** The `vendor/` PUTs may be ASan/UBSan builds; a crash there may not reproduce in a production build. Verify on a non-sanitized build before scoring an availability impact. (Memory-safety objectives that *do* reproduce become genuine findings — see the ASan-verified note in the campaign's evidence.)

**Trap 5: "Both PUTs abort → A:L."** If both stacks abort, the attacker cannot selectively deny service to one while the other serves. Use `A:N`. `A:L` only if the vulnerable PUT crashes/hangs while the other keeps serving.

**Trap 6: "Wrong disconnect / channel-failure reason code → I:L."** Reason codes are diagnostic metadata → RFC violation at CVSS 0.0, not `I:L`.

**Trap 7: "Two CVSS 0.0 RFC violations chained → Critical without evidence."** About *scoring*, not thinking. Chained analysis is encouraged under "Speculative attack paths"; a chain earns CVSS > 0.0 only by citing a *new* missing defense the combination creates, demonstrated not assumed.

A speculative note is the correct home for unverified escalation ideas. CVSS is the wrong home once it floats free of evidence.
