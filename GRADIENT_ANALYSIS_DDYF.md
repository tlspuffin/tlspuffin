# Improving the gradient problem in DY fuzzing (SSH / Terrapin as the lens)

## 1. The problem, stated precisely

Coverage-guided fuzzing is hill-climbing: it keeps inputs that reach *new*
behaviour and builds on them. This needs a **gradient** — partially-right inputs
must look measurably "closer" than wrong ones.

Cryptographic transports are *designed to destroy that gradient*. SSH binds a
per-direction sequence number into every AEAD tag / MAC. So any structural edit to
the encrypted stream (drop / insert / reorder a packet) desynchronises the
sequence number and the **very next packet fails its tag** → the PUT aborts
immediately. Two consequences:

- A "1-edit-away" attack and a "totally broken" input produce the **same**
  observable: early abort, identical coverage. No partial credit.
- The only edits that keep the transport alive are the ones whose sequence-number
  effects **cancel** (Terrapin = insert one IGNORE pre-NEWKEYS [+1] *and* drop one
  packet post-NEWKEYS [−1]). That is a *coordinated combination* with no valid
  intermediate state — an isolated needle, not a slope.

This is why a byte-level or naive DY mutator will essentially never *discover*
Terrapin, even though our oracle *detects* it once the trace is hand-built.

## 2. Why DY fuzzing has leverage that byte-level fuzzing does not

Key structural facts we can exploit:

1. **The trace is symbolic and typed** (term algebra over messages), not a flat
   byte buffer. Mutations are tree edits with known semantics.
2. **The mapper computes the wire bytes** — including the crypto — from the
   symbolic trace. Sequence numbers, keys, tags are *our* code (`fn_encrypt_packet*`),
   not opaque. We can make that computation *invariant-aware*.
3. **The PUT executes faithfully and emits structured claims.** We get rich,
   typed post-state (negotiated algs, auth identity, transcripts), not just a
   crash bit — a natural source of graded signals.
4. **Security is judged by a generic property** (matching conversation), separate
   from how we search. So we may bias *search* with attack structure without
   compromising *detection*.

The gradient problem is fundamentally that *semantic intent* (drop a message) is
coupled to *crypto bookkeeping* (sequence numbers must stay consistent). DY
structure lets us **decouple** the two.

## 3. Approaches, ranked

### A. Invariant-preserving semantic mutators  (recommended)
Add DY mutators that perform a semantically meaningful edit **and** restore the
transport invariant in the *same atomic step*, so the result is always a
transport-valid trace whose oracle outcome is observable.

- `TruncateWithCompensation`: drop the relayed packet at position *i* in a
  direction, and insert a protocol-valid filler (`SSH_MSG_IGNORE`) earlier in the
  same direction during the cleartext phase. The filler's +1 cancels the drop's
  −1, so downstream tags stay valid **by construction**. This is *exactly* the
  Terrapin pattern, expressed as **one** mutation → the all-or-nothing barrier is
  gone; the violation is now reachable in a single hop with a normal gradient.
- Companion patterns: `InjectWithCompensation` (insert a message + drop a filler),
  `ReorderWithinDirection`, `DowngradeOffer` (rewrite a KEXINIT list and keep the
  exchange hash consistent).

Why it's the best fit: it is realistic (the filler is a real message the PUT
processes — the attacker really can do this when strict-kex is absent), it
generalises to any counter-based transport, and crucially it keeps **detection**
generic — the mutator only encodes *attacker capability*, the oracle still decides
whether matching conversation was violated. (Methodologically the same as
grammar-based fuzzing: structure guides the search, the property is the judge.)

### B. Constraint-repair pass in the mapper
Make the encryption layer *trace-position-aware*: each emitted packet derives its
sequence number from its actual position in the (possibly mutated) trace, and a
**repair pass** inserts the minimal in-band fillers needed to satisfy the
transport invariant after an arbitrary structural mutation. This decouples intent
from bookkeeping globally, so *any* structural mutator (Skip, Swap, Repeat)
yields a transport-valid trace.

Caution — realism boundary: repair must only use operations a real attacker can
perform in-band (insert/forward/drop of messages the PUT accepts), never "magic
renumbering". Pure renumbering would model an attacker stronger than reality and
manufacture false positives (SSH's seqno-in-MAC is *meant* to make naked
truncation impossible; only the strict-kex gap allows the IGNORE trick). So B is A
generalised, with the same guardrail.

### C. Graded fitness from claims / the oracle
Turn the binary oracle into a continuous distance and feed it to the scheduler:
- per-party **liveness depth** (how far each agent advanced before aborting),
- **transcript divergence** size (how many messages the two views differ by),
- "tag-valid but transcripts differ" as a strong intermediate reward.
This restores a gradient *for the search* even without changing mutators: inputs
that keep both parties alive *and* start to diverge score higher. Pairs naturally
with A/B.

### D. Concolic / constraint solving over symbolic sequence numbers
The trace is symbolic, so the seqno-balance constraint ("inserts − drops = 0 per
direction at the truncation point") is expressible. A solver can find the
insert/drop multiset that satisfies both the semantic goal and the invariant.
Most general, heaviest to build; worth it only if A/B/C plateau.

## 4. Methodological guardrail (the "no cheating" line)
Encoding attack *structure in the mutators* (A/B/D) or attack-shaped *fitness*
(C) is legitimate — it is search guidance. The invariant we must keep: the
**detector stays a generic security property** (matching conversation /
authentication), never a Terrapin-specific signature. Then "the fuzzer found a
matching-conversation violation" remains a true, transferable result, even though
we helped it search. This is the same discipline used throughout this project.

## 5. Recommendation
Implement **A: an invariant-preserving `TruncateWithCompensation` mutator**, seeded
from `seed_handshake_two_party_packet_complete`. It converts Terrapin from an
unreachable coordinated combination into a single gradient-friendly mutation,
generalises to a family of transcript/truncation attacks, and keeps detection
generic. Add **C** (graded transcript/liveness fitness) as cheap reinforcement.
Reserve **B/D** for if we later want this to work for arbitrary structural edits
or other counter-based protocols (TLS record seq, QUIC).
