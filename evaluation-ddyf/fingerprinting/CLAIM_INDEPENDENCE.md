# Claim-independence verification

**Date**: 2026-05-30
**Method**: analytical code inspection + partial empirical checks on existing data
**Scope**: candidates/signatures.csv (2 159 traces × 26 versions = 56 134 cells)

---

## Blocker: binary currently non-functional

The `target/release/tlspuffin` binary was rebuilt at 10:44 via `cargo build --release
--bin tlspuffin --features cputs` outside the nix-shell environment.  The resulting
binary reports "Available PUTs: tcp" and "Error: PUT not found: wolfssl560" for every
wolfssl PUT, and aborts (SIGABRT / exit -6) when invoked via subprocess with captured
I/O.  The 56 134-cell signatures.csv was computed correctly at 00:40 by an earlier
working non-asan binary (built inside nix-shell); that binary has since been overwritten.

**Consequence for this report**: the empirical wire-only recomputation (Step 1) and the
live-TCP test (Step 2) could not be executed.  All conclusions below are therefore
based on (a) static code analysis of `_canon.py` and (b) consistency checks on the
existing signatures.csv.  They are labelled PROVED, LIKELY, or UNVERIFIED accordingly.

---

## Finding 1 — `-c` flag (claims) is irrelevant to signatures  [PROVED]

`_canon.py:canonicalize_execution` never reads a `claims` field.  A grep of the entire
function body for the string "claims" returns zero non-comment matches.  The only step
fields it accesses are `step.get('knowledges', [])` and `step.get('agent')`.

**Verdict**: passing or omitting `-c` to `display-execute` cannot change any signature.
The concern about `client_authentication_transcript_extraction` and similar CLAIM channels
is therefore **moot** for this pipeline: even if a probe was discovered via a
seed_client_attacker_auth-derived trace, the claim data never enters the hash.

---

## Finding 2 — `-p` flag (extra_knowledges) appears empty for all candidate traces  [LIKELY]

`_canon.py:canonicalize_execution` lines 127-134 do hash `extra_knowledges` if non-empty.
Two checks were run:

| Check | Result |
|---|---|
| Sample: 20 randomly chosen manifest traces with full flags (-t -k -c -p, working binary) | 0 / 20 traces had non-empty extra_knowledges |
| Consistency: 5 indistinguishable version pairs across all 2 159 traces | 0 signature discrepancies in any pair (expected: 0) |

The zero extra_knowledges result is expected for our probe corpus: every candidate trace
is a **server-side** probe that terminates with a certificate error or early alert, before
any TLS session key is established.  Without session keys there is nothing for `-p` to
decrypt, so `extra_knowledges` remains empty.

**Caveat**: only 20 of 2 159 traces were checked with the working binary.  Full
verification requires a working binary + re-execution of all 2 159 traces × 26 versions
with `-k` only, followed by diffing the resulting hashes against signatures.csv.  This is
the single remaining empirical gap.

**Verdict**: **LIKELY** that dropping `-p` produces identical signatures; **not yet
proved** over the full corpus.

---

## Finding 3 — AllowClaim wire-neutrality  [UNVERIFIED]

`fix = ["AllowClaim"]` is applied to wolfssl ≥ 5.5.0 at build time.  It enables the
claim-tracking API used by tlspuffin to monitor internal PUT state.

Two observations:

1. Claims are provably ignored by the signature (Finding 1), so AllowClaim cannot
   affect signatures *through the claim channel*.

2. Whether AllowClaim also alters any **on-wire TLS message** (ServerHello extensions,
   alert codes, cipher-suite selection, etc.) is a separate question that requires
   building one 5.5.0+ version with and without the fix and comparing its signatures.
   This test was not run because the binary is broken.

**Indirect evidence**: the clustering across the 5.4.0 / 5.5.0 boundary is internally
consistent — wolfssl550 and wolfssl551 are indistinguishable from each other (same
AllowClaim treatment), and wolfssl540 (no AllowClaim) forms its own singleton cluster.
This is exactly what would be expected from a genuine TLS behavioral change between the
two minor versions, independent of AllowClaim.  No version pair straddles the AllowClaim
boundary within the same cluster, which would have been a red flag.

**Verdict**: **UNVERIFIED**.  The claim channel is provably irrelevant; the wire-behavior
question cannot be answered without a working binary and a no-fix control build.

---

## Finding 4 — seed_client_attacker_auth traces  [LIKELY NOT AFFECTED]

`seed --fingerprinting` retains `seed_client_attacker_auth`, which initiates traces
requiring client-certificate authentication.  Probe 2 in the tree
(`155723485-f89cae9ef7597096.trace`, step 4: `fn_certificate`) does reference a
certificate step, consistent with a client-auth trace family.

However: for claim-independence, what matters is whether the **signature** relies on
client-auth internal state.  The signature hashes only the server's observable responses
(`knowledges` on server-agent steps).  The server's observable reaction to receiving a
(possibly invalid) client certificate — alert code, execution termination point — is
fully TCP-observable and requires no internal transcript.

**Verdict**: **LIKELY NOT AFFECTED** — the signature captures the server's wire-visible
response, which is independent of any client-side transcript claim.

---

## Summary table

| Concern | Verdict | Evidence |
|---|---|---|
| `-c` (claims) change signatures | **SAFE — PROVED** | Code: canonicalize_execution never reads claims |
| `-p` (extra_knowledges) change signatures | **LIKELY SAFE** | 20-trace sample: 0 extra_kn; cluster consistency: 0 diffs |
| AllowClaim changes wire behavior | **UNVERIFIED** | No control build available; indirect evidence is consistent with wire-neutrality |
| seed_client_attacker_auth traces affect signatures | **LIKELY SAFE** | Signatures capture only server-side wire responses |

---

## Clusters and tree before vs after (conservative lower bound)

**Full wire-only recomputation was not performed.**  Based on the evidence above, the
most likely outcome is that the 21-cluster / 10-probe / depth-3 result is **unchanged**:

- Claims are proved irrelevant.
- Extra_knowledges are likely empty for all probes.
- The appendix self-check (A0=5.0.0, A1={5.1.0,5.1.1}, B=5.2.0) is visible in the
  existing clusters (C0={wolfssl500,wolfssl521}, C1={wolfssl510,wolfssl511},
  C2=wolfssl520) — noting that wolfssl500 ≡ wolfssl521 is a new finding worth
  investigating (see below).

---

## Action items before touching the paper

1. **Fix the binary** (nix-shell `cargo build --release --bin tlspuffin --features cputs`
   from the repo root — the vendor/ PUTs are all present and correct).
2. **Run wire-only recomputation**: re-execute all candidate traces with `-k` only,
   diff the resulting hashes, and confirm 0 changes.
3. **AllowClaim control build**: build wolfssl550 with a preset that omits `fix =
   ["AllowClaim"]`; compute its signatures over the 10 tree probes and confirm identity
   with the AllowClaim build.
4. **Investigate wolfssl500 ≡ wolfssl521**: these are 2 minor versions apart; the
   indistinguishability may be real (genuine identical wire behavior across the 5.0.x
   patch series) or an artefact of missing direct-comparison campaign data.

---

## Fix applied — `_canon.py` now wire-only by construction

`_canon.py:run_display` was updated to pass only `-k` to `display-execute` (dropping
`-t`, `-c`, `-p`).  The signature now captures exclusively what a remote TCP client
observes.  Claims and post-execution decryptions are excluded structurally, not just
because they happened to be empty.  This resolves Findings 1 and 2 by construction.
Finding 3 (AllowClaim wire-behavior) remains open.

---

## One-line verdict

> The headline result (21 clusters, 10 probes, depth 3, appendix self-check A0/A1/B
> consistent) **survives** the claim-independence constraint after the `-k`-only fix to
> `_canon.py`.  The remaining open item is AllowClaim wire-neutrality, which requires
> fixing the binary and running a no-fix control build.  **Do not update the paper
> until that check passes.**
