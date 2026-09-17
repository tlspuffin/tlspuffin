# Protocol-agnostic claim-trajectory coverage (DY feedback)

A new fuzzer feedback for DY/puffin that creates a gradient toward relational
security violations (matching conversation, downgrade, Terrapin-class) **without
any protocol-specific logic in the feedback itself**. All protocol knowledge
enters through one clean interface on the claim layer.

## 1. Problem

Edge coverage is the wrong signal for relational, two-party properties: on mature
libraries it saturates (the handshake is already covered), it gives no partial
credit across the crypto all-or-nothing cliff, and it is blind to *how deep the
joint conversation got* and *how close the two parties are to diverging while both
stay alive*. We want a feedback that rewards reaching new **conversation states**,
expressed generically.

## 2. Core idea: coverage over the claim trajectory

During one execution the PUTs emit a time-ordered sequence of **claims**
(structured belief snapshots). Treat that sequence as the observable trajectory of
the joint protocol state machine, and apply **coverage** to it exactly as LibAFL
applies edge coverage to basic blocks:

- a new **claim-state** (a canonical claim never seen before) is interesting;
- a new **claim-transition** (an adjacent canonical claim pair never seen) is interesting.

This is the relational analogue of edge coverage: "did the *conversation* reach a
new joint state / take a new step?" instead of "did the *code* take a new branch?"

Crucially the feedback never inspects protocol fields. It only sees an opaque,
hashable **coverage key** per claim, produced by the protocol.

## 3. The interface boundary (the whole protocol contract)

```rust
// puffin core — generic
pub type ClaimKey = u64;

trait Claim {
    /// Canonical projection of this claim for coverage. `None` = ignore.
    /// MUST omit per-execution-random fields (nonces, ephemeral keys, session
    /// ids, MAC tags, timestamps) so semantically-equal states collapse to the
    /// same key — otherwise every run is "novel" and the feedback degenerates to
    /// always-true. The induced equivalence (a == b  iff  keys equal) is the
    /// protocol's "comparison function over claims".
    fn coverage_key(&self) -> Option<ClaimKey> { None }   // opt-in
}
```

That is the *entire* protocol-facing surface. Everything below is protocol-blind.
Protocols may additionally emit **intermediate-state claims** (per phase) carrying
**counters/state data** — these enrich the trajectory but require no feedback
changes (they are just more claims with their own `coverage_key`).

## 4. Generic mechanism (protocol-blind)

- `ClaimCoverageObserver` (LibAFL `Observer`): after each execution, read the
  per-run claim list (the same ordered `GlobalClaimList` the security oracle
  already consumes), and fill a fixed-size byte map `M`:
  - for each claim `c_i` with `k_i = c_i.coverage_key()`: `M[h(k_i) % N] = 1`   // state coverage
  - for each adjacent pair: `M[h(k_i, k_{i+1}) % N] = 1`                         // transition coverage
- `MaxMapFeedback<ClaimCoverageObserver>`: reused verbatim from LibAFL — input is
  "interesting" iff it sets a previously-unset map cell. OR-combined with the
  existing edge-coverage feedback; the objective stays the security oracle.

Reuses LibAFL's proven coverage machinery (corpus scheduling, minimization, map
novelty) on a synthetic map whose indices are DY conversation states.

Requirement: **deterministic claim emission order** (holds — the sequential trace
executor drives a fixed relay; with seeded PUT RNG runs are reproducible). Order
jitter would manufacture false novelty.

## 5. Avoiding the always-true degeneracy (correctness contract)

- `coverage_key` omits all randomized fields (protocol responsibility).
- Counters in claims must be **bounded or bucketed** by the protocol (e.g. message
  index, phase ordinal, log-scale byte counts), never free-running, or the key
  space explodes and every run is novel.
- **Saturation test** (the correctness oracle for the abstraction): replaying the
  same honest seed twice must add **zero** claim-coverage. If it adds coverage, the
  projection still leaks a random field — fail the build/test.

## 6. SSH instantiation (the only SSH-specific code)

- **Intermediate claims**: emit a thin claim at each phase transition
  (`kexinit / kex / newkeys / ext-info / service / auth / channel / done`) for each
  agent, plus the existing completion claim. Source: the libssh instrumentation
  hooks already added (`packet_process`/`packet_send`); each can fire a phase claim.
- **Counters/state**: per-direction post-NEWKEYS message count, current phase
  ordinal, per-direction message-type sequence (already partly present as the
  secure-channel digest — for coverage expose it as a short bounded vector, not a
  hash).
- **`coverage_key`**: hash of `(role, phase, canon(kex/cipher/mac), auth_method,
  auth_key_class, per-direction msg-type sequence/counts)`; **omit** `session_id`,
  ephemeral keys, MAC tags, raw bytes. (Reuses the same field set already marked
  `#[comparable_ignore]` for the differential oracle — randomized-for-differential
  == randomized-for-novelty.)

Then a Terrapin-class run surfaces as a **new claim-state**: a `done` claim whose
s2c received-message-type sequence is the honest one minus EXT_INFO (count 2 vs 3)
— a map cell no honest run produces — so it is retained as corpus, and the generic
security oracle fires on it. Liveness depth and "alive-but-diverging" both become
ordinary new cells, giving the gradient edge coverage cannot.

## 7. Implementation plan

**P0 — generic core (puffin), no behaviour change**
1. Add `Claim::coverage_key` (default `None`).
2. `ClaimCoverageObserver` over the existing per-run claim list; fixed map (e.g. 2^16).
3. Register observer + `MaxMapFeedback` in `libafl_setup` (feature-gated
   `claim_coverage`, OR-combined with edge coverage). No protocol code touched.

**P1 — SSH projection**
4. Implement `coverage_key` for `SshClaim` (omit random fields).
5. Expose the s2c/c2s post-NEWKEYS type sequence as a bounded vector in the claim.

**P2 — SSH intermediate claims**
6. Emit per-phase claims from the libssh hooks (counters + phase ordinal).
7. Saturation test: honest seed ×2 ⇒ 0 new claim coverage.

**P3 — tune**
8. Map size / bucketing; optional power schedule weighting by claim-coverage.

Each phase is independently testable; P0 is inert until a protocol opts in.

## 8. Evaluation plan

- **A/B campaigns** (libssh0104, two-party substrate, equal budget, N seeds):
  - A = edge coverage only (baseline); B = edge + claim coverage.
  - Primary: time-to-first matching-conversation objective; # distinct violation
    classes; whether B finds the **version-differential Terrapin signature** (fires
    on 0.10.4, strict-kex-mitigated on 0.11.4) within budget while A does not.
- **DY-state occupancy** (leading indicator, before any objective): instrument the
  claim map; show B reaches "both-complete" and "both-complete-and-diverging"
  joint states markedly faster / more often than A.
- **Correctness**: saturation test (honest ×2 ⇒ 0 coverage); confirm map does not
  explode (occupancy plateaus on honest traffic).
- **Ablations**: states-only vs states+transitions; with/without intermediate
  claims; with/without counters; map-size and bucketing sensitivity.
- **Guardrail**: every objective found must replay and pass the
  version-differential check — the feedback guided search, the *oracle* (generic
  matching conversation) judged; no Terrapin signature in either.
- **Overhead**: exec/sec delta from the observer (expect <5%: a few hashes/run).
- **Generality**: implement `coverage_key` for one tlspuffin claim and show the
  *same* observer/feedback drives TLS with zero feedback-side changes — proving the
  mechanism is protocol-agnostic.

## 9. Risks & mitigations

- *Always-true / map explosion* → strict canonicalization + bounded counters +
  saturation test (§5).
- *Order nondeterminism* → deterministic sequential executor + seeded RNG (§4).
- *Coverage dilution* (claim map drowns edge map) → separate maps, separate
  novelty, OR-combined; optionally weight scheduling.
- *Bridging the seqno cliff* → this feedback makes the landscape climbable and the
  violation neighbourhood a retained corpus region, but the exact balanced edit is
  still easier *with* an invariant-preserving mutator; the two are complementary
  (see `GRADIENT_ANALYSIS_DDYF.md §3A`). Feedback is the protocol-agnostic half.

## 10. Summary

Generic feedback = **"has this canonical series of claims been seen before?"**,
realised as coverage over a synthetic map of claim-states and claim-transitions,
reusing LibAFL's coverage machinery. The only protocol input is one projection
function `coverage_key` that omits randomized fields (the comparison/equivalence
over claims). Protocols may add intermediate-state claims and counters freely. No
SSH/Terrapin knowledge lives in the feedback.
