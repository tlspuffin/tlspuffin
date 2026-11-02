# CVSS v3.1 Scoring for TLS Differential Findings

CVSS measures impact on the **system**, not on the protocol specification. An RFC MUST violation is an RFC finding regardless of CVSS score. CVSS only measures whether the violation has a concrete security consequence.

---

## Metric-by-metric guidance

### Confidentiality (C)

`C:H` — Attacker can read application data from an established session.  
`C:L` — Attacker can read partial metadata (SNI, session ticket contents, but not body).  
`C:N` — No application data exposed. Covers:
- Connection aborts before application data is exchanged
- A wrong or missing alert — alert content is not confidential data
- A handshake field has the wrong value but nothing leaks

### Integrity (I)

`I:H` — Attacker can forge or inject authenticated application data into an established session.  
`I:L` — Attacker can corrupt partial protocol state that survives into the session (e.g., a callback receives unvalidated bytes that influence application logic).  
`I:N` — No authenticated data is modified. Covers:
- **Missing or wrong alert codes** — alerts are diagnostic signals, not application data; RFC violations in alert selection are `I:N`
- **Wrong order of internal callbacks** (e.g., `msg_callback` fires before type check) — the connection is still aborted; `I:L` only if the callback output influences application security decisions
- **Protocol compliance defects** where the connection is ultimately rejected

### Availability (A)

`A:H` — Server or client crashes, or enters a state preventing further connections.  
`A:L` — Degraded service: a single connection is permanently hung, or a server process is killed and must be restarted.  
`A:N` — No availability impact. Covers:
- **Both PUTs abort the connection** — no availability difference between the two implementations; attacker cannot exploit this to selectively deny service
- A wrong alert code is sent — connection terminates normally from both peers' perspectives

### Attack Complexity (AC)

`AC:H` — MITM position required, specific timing needed, or partial knowledge of session state needed.  
`AC:L` — Simple packet sending suffices.

For most DDYF findings: the tlspuffin attacker is a Dolev-Yao MITM with full control, which in the real world requires a MITM position → `AC:H` at minimum.

---

## Reference scores for common finding types

### Silent abort — no alert sent (RFC §6.2)

One PUT sends a fatal alert; the other silently closes. Both connections abort.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:N / I:N / A:N = 0.0 (None)
```

`A:N` because both connections close — there is no operational availability difference between the two implementations.

### Wrong alert code (RFC §9.2 or similar)

Both PUTs abort. They differ only in which alert code they send.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:N / I:N / A:N = 0.0 (None)
```

The wrong code affects diagnostics and interoperability, not security.

### Lenient acceptance without session establishment

PUT accepts a malformed message and proceeds, but the connection ultimately aborts before application data is exchanged.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:N / I:N / A:N = 0.0 (None)
```

"LibreSSL does not immediately reject X" ≠ "LibreSSL is exploitable via X." If the handshake cannot complete (Gate 1 fails), CVSS is 0.0.

### Internal callback ordering defect

A registered callback receives unvalidated bytes before the message-type guard fires. The connection is subsequently aborted correctly. Application code using that callback as a security oracle could be misled.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:N / I:L / A:N = 2.7 (Low)
```

`I:L` only if the callback is documented as receiving only validated messages and application code legitimately relies on it. If the callback is purely informational, use `I:N` → 0.0.

### CLI tool crash on incoming connection (`s_server -quiet`)

The server tool crashes and must be restarted. Any connecting client triggers it.

```
AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:L = 5.3 (Medium)
```

`A:L` because one instance is killed per connection (not persistent DoS of the library). Applies to `openssl s_server -quiet` + TLS 1.3 input crashing the sanitized 3.4.0 binary.

### Authentication bypass (all Security Gates pass)

Attacker establishes a session with keys derived from attacker-controlled material; application data exchanged.

```
AV:N / AC:H / PR:N / UI:N / S:U / C:H / I:H / A:N = 7.4 (High)
```

---

## Multi-framing CVSS for compound-attack findings

**Default to a multi-framing analysis** for any finding whose exploitability depends on (a) compounding with a separate peer-side bug, (b) a specific deployment configuration, or (c) a developer-trap re-introduction of an unsafe default. Single-number CVSS is honest only when the exploitability is unconditional.

Each framing gets its own row with its own vector and score:

| Framing | When to use | Vector hint |
|---|---|---|
| **A — Defect alone** | The defect in isolation, with no peer-side bug and no developer error | Typically `C:N/I:N/A:N`, score 0.0 |
| **B — Developer / API trap** | The defect compounded with a common but mistaken developer action (e.g., `SSL_CTX_set_options(ctx, SSL_OP_ALL)` re-asserting a bypass on LibreSSL where the same code is safe on OpenSSL 3.x) | Same vector as A in pure CVSS terms (loss of defence-in-depth ≠ direct C/I/A impact); the value of this framing is the **narrative**, not the number |
| **C — Full compound** | The defect chained with a second peer-side bug or with a concrete deployment pattern that turns it into an exploit | Genuine `C:L+/I:L+` etc. |
| **(optional) D — Concrete scenario** | A specific real-world deployment (named software, named server class, named network position) where the impact rises measurably above C | `S:C/I:H` etc. plausible |

**Reporting rule:** for compound-attack findings, ALWAYS state framings A, B, and C (when applicable) explicitly. Quote the vector for each. The `SUMMARY_BUCKETS.md` §2 row carries the strongest framing in bold (typically C) plus the others in plain text:

```
0.0 / 0.0 / **4.8 Medium** (Framing A / B / C — see §6.2)
```

**Why this matters:** single-number CVSS lets reviewers anchor on either the floor ("0.0 — not a real issue") or the ceiling ("4.8 — actively exploitable today"). Multi-framing forces the reader to engage with the precondition. The renegotiation report's §6.2 is the worked example.

The **multi-framing analysis is mandatory** for any finding being considered for Track 2 (CVE candidate) promotion per `SECURITY_GATE.md` Track 2 criteria. Track 1 (strict `[VULN]`) findings have unconditional exploitability by definition and may give a single CVSS.

---

## Common scoring traps

**Trap 1: "RFC MUST clause violated → must be I:L or higher"**  
CVSS Integrity measures whether attacker-controlled data enters an authenticated session. RFC MUST violations about alert codes, extension ordering, or diagnostic messages do not affect data integrity → `I:N`.

**Trap 2: "Finished claim present → exploitable"**  
Check Gates 2 and 3. If the Finished claim is from a separate legitimate agent (not the one processing attacker input), or if all key fields are zero, the claim is an artifact. CVSS 0.0.

**Trap 3: "Handshake proceeds past rejection point → downgrade possible"**  
Proceeding past a check does not establish a session. If the connection aborts at certificate verification or key exchange, no session keys are derived, and no downgrade is possible for that connection. Gate 1 catches this.

**Trap 4: "Both PUTs abort → A:L"**  
If both PUTs abort the connection, the attacker cannot selectively deny service to one while the other continues. Use `A:N`. `A:L` only if the vulnerable PUT crashes its process or permanently hangs while the other continues serving requests.

**Trap 5: "OpenSSL sends wrong alert / LibreSSL sends wrong alert → I:L"**  
Alert codes are diagnostic metadata. Wrong alert code = RFC violation at CVSS 0.0, not `I:L`.

**Trap 6: "Sanitized build crashes → CVE"**  
The project's `vendor/openssl340/bin/openssl` is a UBSan/ASan debug binary. Crashes in it may not reproduce in production non-sanitized builds. Always verify with the system binary (`/usr/bin/openssl`) before assigning a security score to a crash finding.

**Trap 7: "Two CVSS 0.0 RFC violations chained → Critical CVSS without evidence"**  
This trap is about **scoring**, not about thinking. Chained-bug analysis is encouraged — record it under "Speculative attack paths" (see `SECURITY_GATE.md`). The trap is only about assigning a CVSS *score* to a chain.

Chained-bug claims that get a CVSS > 0.0 must clear the same evidence bar as single findings. Each component's Gate 4 conclusion (defense layers present) carries through. The chain only escalates above 0.0 if it cites a *new* missing defense layer that the combination creates — and that layer must be demonstrated, not assumed.

Do not assign a CVSS score in these cases (move them to a speculative note instead):
- "Host applications often allocate fixed-size buffers based on RFC limits" — name a real, deployed application with source line, or write as speculative.
- "Bypassing the transport limit lets the attacker hunt for deeper bugs" — name a specific failing sink, or write as speculative.
- "Stealth DoS via missing alert telemetry" — name a real WAF/IDS that uses the signal as primary detection AND demonstrate ≥10× resource consumption, or write as speculative.

A speculative note is the correct home for these ideas. CVSS is the wrong home, because CVSS becomes lossy and misleading once it floats free of evidence.
