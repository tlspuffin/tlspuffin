# Entity-authentication oracle, approach 2: from the trace (plan)

Status: **plan, to implement after approach 1** (`hunt/ENTITY-AUTH-ORACLE.md`). Stage A needs no `puffin/`
change. Stage B adds a small hook to shared `puffin/` code and Stage C changes the attacker model;
both are **flagged for approval**, not landed. This plan supersedes "follow-on 3" of the first
version and `hunt/TASK3-CREDENTIAL-LEAK-ORACLE-PLAN.md` (whose credential-leak check becomes
property S below).

## Why a second approach

Approach 1 trusts the honest PUT twice:

1. for its **belief**: what it thinks it authenticated, read by an instrument accessor or a claim;
2. for the **evidence** that the check preceding that belief happened, recorded by the harness at
   a callback.

A library that misreports the check, or a code path the harness does not observe, defeats approach
1. Approach 2 keeps the belief, which only the PUT knows, but derives the evidence from what the
trace delivered to the PUT and from what the Dolev–Yao attacker knows. That is library-independent:
the genuine DY authentication and secrecy properties.

## The properties

For every honest PUT agent *X* and every authentication belief *X* holds at step *i* — "I
authenticated user *U* with key *K* (or password *P*) in session *H*" (server), or "I am keyed
with a server whose host key is *K_H*, in session *H*" (client):

- **J1 — justified.** Before step *i*, the trace delivered to *X* a proof bound to *X*'s own session:
  - userauth: a signature that verifies under *K* over the RFC 4252 §7 data for *H*, or the
    password of *U*;
  - host auth: a KEX reply whose signature verifies under *K_H* over *X*'s exchange hash.
- **J2 — agreement.** The proven identity is the believed one: username, key fingerprint, host key.
- **J3 — provenance** (withheld-key model only, Stage C). The proof came from an honest agent of the
  trace (it is forwarded output, i.e. knowledge with `Source::Agent`), or the attacker owns that
  identity's secret.
- **S — secrecy.** An honest client's password never reaches the attacker's knowledge:
  - in a cleartext packet;
  - in a session whose host authentication fails J1;
  - with Stage C, outside a session with a server identity the attacker does not own.

| violation (suggested) | property | catches, from the trace alone |
|---|---|---|
| "Host authentication unjustified" | J1/J2, client | CVE-2025-11625 (no KEX reply delivered at all) |
| "Authentication out of order" | J1, client: user-auth accepted with no completed KEX before it in the trace | CVE-2025-14942 |
| "User authentication unjustified" | J1/J2(/J3), server | the S1 class of approach 1, without trusting the callback record |
| "Credential leak" | S | CVE-2025-14942's cleartext-password impact |

## What the oracle reads

- **Beliefs** come from claims, per agent: the claim's identity fields and `session_id`.
  - The server side exists already: `auth_method`, `auth_user`, `auth_key_fp`.
  - The client side needs new *belief* fields, recorded where the library reaches the state (pure
    observation, not evidence):
    - the accepted host-key fingerprint;
    - "keyed";
    - "user-auth accepted";
    - `phase`, which is already in the C `Claim`, decoded into Rust.
- **Evidence** is the executed prefix of the trace: each input to *X* before step *i* is evaluated to
  the message *X* received and parsed with sshpuffin's codec.
  - This works for structured and for bit-mutated (opaque) inputs alike.
  - Sealed inputs are decrypted with keys the attacker can derive. For its own KEXs these come from
    `fn_client_ecdh_privkey` and `fn_derive_*`, as the seeds do. A relayed honest stream the
    attacker cannot decrypt is, by construction, provenance from the honest peer.
  - Signatures are verified with the `rsa` crate (already used in `fn_crypto.rs` tests), over the
    data `sign_userauth_with` / `fn_kex_exchange_hash` build.
- **Attacker knowledge** comes from `ctx.knowledge_store.knowledges()`: each item has a `Source`,
  the `step` that produced it, and its term. It is used for J3 and S.
- **Identity model**: users, key fingerprints, passwords, and whether the attacker owns each secret.
  - Today the signature gives the attacker every secret: `fn_sign_exchange_hash` and
    `fn_sign_userauth` sign with key A (= the host key); `fn_sign_userauth_b` / `_c`; all three
    passwords.
  - The table is generated from, or checked against, `sshpuffin/include/puffin/ssh_authorized_creds.h`,
    so there is one source of truth.

## Stages

**Stage A: prototype, no `puffin/` change.**

1. Module `sshpuffin/src/trace_oracle.rs`: `check(trace, ctx) -> Verdict`, where the verdict is a
   violation, none, or *inconclusive*.
2. Integration tests in the style of `tests/traces.rs`: `trace.execute(&mut ctx, …)`, then the
   oracle on beliefs (`ctx.find_claim`), evidence (the trace) and knowledge (`ctx.knowledge_store`).
3. Add the credential-leak fixture of the Task-3 plan: a server-attacker seed that refuses `none`, so
   the client sends its password.
4. Validation:
   - the CVE-2025-11625 and -14942 witnesses fire their violations;
   - every `with-divergent` seed, on both vendors and both roles, stays silent or inconclusive,
     never a violation;
   - an agreement matrix with approach 1 on every witness and seed.

**Stage B: a fuzzing objective. Touches `puffin/`, flag and ask first.**

1. Add a defaulted method `SecurityViolationPolicy::check_violation_with_trace(claims, knowledge,
   steps)` that calls `check_violation` by default, so every existing policy is unchanged.
2. `execute_until_step_wrap_inner` already holds `&self.steps[..=i]` and `ctx` where it calls
   `ctx.verify_security_violations()`; pass them through (about 10 lines).
3. sshpuffin runs approach 1, then approach 2.
4. If the hook is declined, fall back to a post-execution analysis pass for triage only, or to the
   relay layer (two-party runs only).

**Stage C: withheld-key model. Changes the attacker model, flag separately.**

1. Honest identities: host key and user A, and user B. Attacker-owned: C, plus a new attacker host key D.
2. Campaigns in this mode drop the honest signing symbols from the signature.
3. Harness clients pin the honest host key, so a MITM becomes a real violation. This also gives the
   first version's dropped P3 (matching conversation) a sound footing.
4. This enables J3 and the full statement of S.

## Soundness risks and how the plan handles them

- **Parse failures** (of opaque inputs, or codec gaps) must not become violations. Report a
  violation only when a belief exists and *no* input to the agent can be a valid proof. If an input
  could not be parsed, the verdict is *inconclusive* and is counted. Validate the parser on the honest
  corpus first.
- **Session binding**: use each agent's own `session_id` from its claim. A client that keyed without
  any H (CVE-2025-11625) received no proof at all, which is itself a violation of J1.
- **Rekeys**: Stage A checks the initial KEX. Rekey host proofs sign each KEX's own exchange hash,
  which the oracle would recompute from the transcript (as the seeds do with `fn_kex_exchange_hash`).
  This is listed as a limitation until done.
- **Per-step checking**: a belief is checked against the prefix delivered before it, so evidence
  that arrives later cannot justify it.

## Cross-check with approach 1

Run both and keep the verdicts apart. The triage tooling runs each separately; the fuzzing objective
returns the first one that fires.

- Both fire: strong evidence.
- Only approach 1 fires: an evidence-extraction gap, or a false positive of approach 1.
- Only approach 2 fires: the library or the harness misreported a check, e.g. a broken signature
  verification behind a callback that still fires. That is a finding in itself.

## Open questions (for when it is implemented)

1. Shape of the Stage-B hook: the executed steps plus `&KnowledgeStore` (recommended, minimal), or
   the whole `&TraceContext`.
2. Whether violation strings stay distinct from approach 1's (recommended, for the agreement matrix)
   or match them, so catalogue entries accept either.
3. Stage-C identity split, and the attacker host key D: new key material, or reuse key C.
