# tlspuffin Output Reference Card

Reference card for interpreting `tlspuffin` outputs in `metadata_*.log` files. Read once before Phase 1; refer back as needed.

---

## `differential-execute -S` output

```bash
./target/release/tlspuffin differential-execute openssl340 libressl421 <TRACE> -S
```

Three top-level result types:

### 1. No difference observed

```
Differences between the PUTs:

```
*(empty body)*

→ The trace ran identically on both PUTs. Goes to bucket `no_errors/` (flaky / non-deterministic execution).

### 2. Execution status difference

```
Differences between the PUTs:

Execution status difference
    first put : (step 5/5) Success
    second put : (step 2/5) SSL_ERROR_SSL (1): error:1402542E:SSL routines:ACCEPT_SR_CLNT_HELLO:tlsv1 alert protocol version
```

→ One PUT errored at a specific step; the other went further or succeeded. **Use `StatusC(..., first_to_fail=True)`** in the bucket condition.

Step notation: `(step f/total)` where `f` is the step at which this PUT first failed, and `total` is the trace length.

### 3. Knowledge difference

```
Differences in knowledges: knowledge[0]
  (tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload, agent:0) :
  [Description(Different(HandshakeFailure, MissingExtension))]
```

→ Both PUTs ran all steps. They produced different content at the same knowledge index. **Use `StatusC(..., first_to_fail=False)`** in the bucket condition (the `Status` field in the diff record is `None` for these traces).

Common patterns:
- `Different(AlertA, AlertB)` — both PUTs sent an alert; the codes differ.
- `Different(<Type>, ())` — first PUT produced something; second PUT produced nothing (silent abort).
- `Different((), <Type>)` — first PUT produced nothing; second produced something.

### 4. Claim difference

```
Differences in claims: claim[2]
  (Finished, agent:0) : [Different(Finished {...}, ())]
```

→ Both PUTs ran. One emitted a claim (e.g., Finished) where the other emitted nothing. **Use `DifferentClaimC(in_first_type, in_second_type)`** in the bucket condition.

---

## `display-execute -tckp` output (per-PUT)

```bash
./target/release/tlspuffin --put openssl340 display-execute <TRACE> -tckp
```

Flags: `-t` terms, `-c` claims, `-k` knowledges, `-p` payloads.

Output structure (one block per step):

```
==== Executing step #N ====
Action: Input (attacker -> agent.X)         ← step type
Term: fn_<symbol>(...)                       ← what was sent (Input) or output (Output)
>>> OpaqueMessageFlight { messages: [...] } ← raw bytes returned BY the agent
>>> MessageFlight { messages: [...] }        ← decoded version of the same
+++ TranscriptServerHello(...)               ← claim emitted at this step
```

Final lines:
```
Extra knowledges :
Error : error in PUT : SSL_ERROR_SSL (1): ... :file.c:line:
```

### Reading direction conventions

| Action type | What `>>>` shows |
|---|---|
| `Input (attacker -> agent.X)` | The PUT's **response** to the attacker's input (often an Alert if the input was rejected) |
| `Output (agent.X -> attacker)` | What the agent **sent out** (the term being captured) |

The bytes the attacker sent **into** the agent are computed at runtime from the `Term:` line; they are not directly displayed in `-p` output.

### Pitfall: "Finished" in metadata logs ≠ Finished claim  *(Gate 1 common mistake)*

The `display-execute -tckp` log contains **two distinct places** where the word "Finished" appears. Confusing them leads to incorrect Gate 1 assessments.

**1. Decryption-attempt section** — these are attempted lookups by the fuzzer, NOT extracted facts:
```
(Some(Agent(AgentName(1))), 0)[None]/Finished     ← [None] = NOT FOUND
```
`grep -l "Finished" metadata_libressl421_*.log` will match here and produce false positives. All 107 traces in `ossl_record_failure_libre_accepts` matched this grep yet had **zero actual Finished claims**.

**2. Extra knowledges section** — the only authoritative source. Located at the bottom of each log:
```
Extra knowledges :
+++ Finished { outbound: true, ... }   ← this is a real claim
```
An empty `Extra knowledges :` section (next line is `Success` or `Error`) means **no claims were extracted**.

**Correct Gate 1 command:**
```bash
grep -A200 "Extra knowledges" metadata_libressl421_T.log | grep -c "Finished {"
```
Not `grep -c "Finished"` — that includes the decryption-attempt section.

---

### Finished claim format

```
+++ Finished {
    outbound: true,
    client_random: [...],
    server_random: [...],
    session_id: [...],
    authenticate_peer: false,
    peer_certificate: [],
    early_secret:     [0, 0, 0, ...],
    handshake_secret: [0, 0, 0, ...],
    master_secret:    [0, 0, 0, ...],
    tls_version: CLAIM_TLS_VERSION_V1_2,
    chosen_cipher: 4865,
    available_ciphers: [...],
    signature_algorithm: 0,
    peer_signature_algorithm: 0
}
```

**Security Gate red flags in this output:**

| Field | Meaning if zero/false | Gate |
|---|---|---|
| `early_secret`, `handshake_secret`, `master_secret` all 64 zeros | Key schedule never initialized — Finished is a state-machine artifact, not a real session | **Gate 3 fails** |
| `authenticate_peer: false` | Peer was never authenticated | Confirms Gate 3 failure |
| `server_random: [1, 1, 1, ..., 1]` (all ones) | tlspuffin stub value — no real server participated | **Gate 2 fails** |
| `tls_version: CLAIM_TLS_VERSION_V1_2` + `chosen_cipher: 4865` (TLS 1.3 cipher) | Version-cipher mismatch; key schedule guaranteed zero | RFC violation, Gate 3 fails |

---

## Common error string patterns

Useful as `StatusC(..., "<substring>", ...)` matchers:

| Substring | Meaning |
|---|---|
| `unexpected message` | OpenSSL `ossl_statem_*_read_transition` rejecting an out-of-order message |
| `wrong cipher returned` | Client received a cipher it did not offer |
| `record layer failure` | TLS record decryption or MAC verification failed |
| `unsafe legacy renegotiation disabled` | Server lacks `renegotiation_info`; OpenSSL refuses |
| `final_key_share` / `no key share` | TLS 1.3 server has no matching group |
| `tls_parse_stoc_key_share` | OpenSSL parsing an HRR's key_share |
| `bad key share` | OpenSSL: HRR selected_group not offered |
| `length mismatch` | OpenSSL: extension parser found extra bytes |
| `no shared cipher` / `no shared signature algorithms` | Server cannot pick a cipher/sigalg |
| `tls13_lib.c` (LibreSSL) | LibreSSL TLS 1.3 path |
| `ssl_pkt.c` (LibreSSL) | LibreSSL record layer |
| `tlsv1 alert <name>` | A fatal alert was sent (the alert text is on the line) |

---

## Trace file layout

```
objective/
  <bucket_name>/                           ← named after triaging script bucket
    20260428-XXX-YYY.trace                 ← the trace file (binary serialised)
    metadata_diff_20260428-XXX-YYY.trace.log         ← Phase 0
    metadata_openssl340_20260428-XXX-YYY.trace.log   ← Phase 0
    metadata_libressl421_20260428-XXX-YYY.trace.log  ← Phase 0
```

Phase 0 produces the three `metadata_*.log` files; Phases 1–4 read them.
