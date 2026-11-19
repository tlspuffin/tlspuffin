# A reusable SSH entity-authentication oracle (P1/P2/P3) + a trace-based cross-check

Status: implemented on branch `cves/CVE-2025-14942-entity-auth` (wolfSSH side), evaluated below.
This complements — does not replace — the CVE-2025-14942 `auth_while_keying` oracle.

## What it asserts

SSH authenticates in two directions, so a complete entity-auth oracle has three parts:

- **P1 — user authentication (server side):** a server ends "user *X* authenticated via key *K*" only if the library verified *K*'s signature **and** (*X*,*K*) is an authorized pairing. Violation = a completed server handshake whose publickey login had **no verified signature** (`had_signature == false`) or an **unauthorized** (*X*,*K*) pairing.
- **P2 — host authentication (client side):** a client ends "session established" only if it verified a server host-key signature over *H* during key exchange. Violation = a completed client handshake with `host_authenticated == false` (no host key ever verified).
- **P3 — matching conversation (two-party):** when a trace runs a real client *and* a real server (relayed by the DY attacker), they must share the exchange hash *H* (RFC 4253 §7.2) — a transcript desync (Terrapin) breaks it. Violation = a client and a server completion claim with different `session_id`.

## How the data is gathered (claim-based)

We read the **library's verdict**, observed at a callback, never re-deriving crypto:

- **P1 `had_signature`:** wolfSSH sets `authData->sf.publicKey.hasSignature` only after it cryptographically verified the signature; the harness records it. (libssh: a publickey request carrying a signature.)
- **P2 `host_authenticated`:** wolfSSH calls the client's public-key-check callback with the server host key, and only reaches the keyed state if the host-key signature over *H* verified; the harness records that the callback fired. Pure observation — the client still accepts any key; the **oracle** enforces that a completed client handshake must have gotten here.
- **P3 `session_id` (H) + `role`:** both peers emit *H*; the oracle compares the client's and server's.

**Gate.** A new `entity_auth_checked` flag is set only by a harness that populates these fields. The oracle applies P1/P2/P3 **only** to claims with it set, so an un-instrumented harness (fields default to 0) is never misread as a bypass. **The wolfSSH harness is instrumented; libssh is a required follow-on.**

## Honest evaluation (coverage, soundness, cost)

- **Soundness / no-false-fire:** validated on the honest corpus (see Validation). Ordered so CVE-2025-14942's `auth_while_keying` → `"Authentication bypass"` is returned first on its witness (the entity-auth checks target the **phase-3 completion** claim; the CVE claim is phase 0, disjoint), so the catalogue test stays green.
- **P2 vs the CVE:** for CVE-2025-14942's *mechanism* these **coincide** — host authentication *is* the KEX host-key signature, and KEX-complete ⟺ `isKeying` cleared, so "reached established with no host key" and "reached auth-accepted while keying" are the same event. On this base (`wolfssh1421`) P2 therefore does not fire *independently*; its independent trigger is a client host-auth bug — **CVE-2025-11625** (line 2 of `vulns_list.txt`).
- **P1 on a correct library:** does not trigger (wolfSSH rejects unauthorized pairings before completing, and reaches done only via a verified-signature call). The logic is in place for a **server auth-bypass** CVE (the wolfSSL/TLS CVE-2022-25640 analog).
- **P3:** inert on single-PUT traces (only one role present). Exercising it needs **two-party relay witnesses**; the finer anti-Terrapin check (crosswise `secure_tx/rx_digest`) needs the wolfSSH harness to emit those digests (libssh already does) — deferred.

**Cost of what remains:** libssh instrumentation (~1 day); two-party P3 witnesses + wolfSSH digest instrument (~2–3 days); a P1 trigger needs a buggy-server CVE; a P2 trigger is CVE-2025-11625.

## Validation (branch `cves/CVE-2025-14942-entity-auth`)

Built in an isolated target dir so the running 12 h campaigns' binary was never touched.

- **Tier-1 intact:** catalogue test **7 passed, 0 failed** — the CVE-2025-14942 witness still returns `"Authentication bypass"` on `wolfssh1421(-asan)-only-CVE-2025-14942`, is patched on `-fix-all`, and produces **no objective** on the unaffected `wolfssh160-asan`.
- **No false-fire on honest traces:** `seed_server_attacker_session_aesgcm`, `seed_client_attacker_pubkey_aesgcm` (exercises P1: a publickey login, `had_signature` + authorized), `seed_client_attacker_pubkey_b`, `seed_client_attacker_full_aesgcm` → outcome `none` on `wolfssh1421`; the same honest seeds on `libssh0122-asan` (un-instrumented, gated) → `none`.
- **Oracle logic proven:** 9 unit tests in `violation.rs` — P1 (no-signature, unauthorized pairing) fires; authorized login clean; P2 (no host auth) fires, host-auth clean; P3 (two-party H mismatch) fires, matching H clean; un-instrumented harness never false-fires.

## The trace + attacker-terms cross-check (proposed, not yet built)

The claim-based oracle trusts the stack's self-report: a library that **mis-reports** the very quantity being checked (claims `hasSignature`/`host_authenticated` wrongly) fools it. A second oracle derived from the **wire trace + the DY attacker's symbolic knowledge** is independent, and is the genuine Dolev–Yao property.

| Property | Trace+terms reconstruction (library-independent) |
| --- | --- |
| Host auth (P2) | Client emitted post-KEX traffic ⟹ the attacker's inputs must contain a `KEX_ECDH_REPLY` with a host-key signature verifying over the client's *H*; none on the wire → bypass. |
| User auth (P1) | Server emitted `USERAUTH_SUCCESS` ⟹ the attacker's input carried a valid signature for an identity whose private key it holds (check `KnowledgeStore`); authenticated as A with no A-key → impersonation. |
| **Password leak** | Scan the attacker's `KnowledgeStore` for the client's password bytes — **no claim needed**, and it realizes the CVE-2025-14942 impact the claim oracle can't. |
| Matching conversation | Already trace-based (`transcript.rs`, `AlignedTranscript`, `secure_tx/rx_digest`). |

**Feasibility / cost.** `SecurityViolationPolicy::check_violation` sees only claims. A single-PUT trace/knowledge oracle needs **either** (a) a `puffin/` hook that passes the `TraceContext`/`KnowledgeStore` to the policy — flagged, not landed without approval; (b) placement in the **differential/relay layer**, which already reconstructs transcripts — no puffin change; or (c) a post-execution analysis pass. `KnowledgeStore::knowledges()` is accessible, so the data exists. Two caveats: the wire shows the belief only once it **manifests** (⇒ the minimal CVE witness, which emits no post-auth traffic, needs a longer witness), and the strongest statement needs a **withheld-key model** (the attacker currently holds the embedded server key via `fn_sign_exchange_hash`).

**Recommendation.** Use the two as a **cross-check**: agreement is strong evidence; **disagreement is itself a finding** (the library is lying about its own security state). Build the **password-leak** trace oracle first (clean win), then a host-auth wire check in the relay layer (no puffin change); the single-PUT trace hook and the withheld-key model are puffin/seed-model changes to flag.
