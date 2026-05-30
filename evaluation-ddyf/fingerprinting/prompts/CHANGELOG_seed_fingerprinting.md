# Heads-up for all agents: new `seed --fingerprinting` CLI flag

A new CLI flag was added to tlspuffin. If you generate seeds for the fingerprinting
pipeline, use it instead of `--differential`.

## What changed (puffin/src/cli.rs)

- New flag: `tlspuffin seed --fingerprinting`.
- It behaves exactly like `seed --differential` (same uniformised PUT descriptors)
  **except it skips all server-attacker seeds** — any corpus seed whose name contains
  `server_attacker` (the 4 `seed_server_attacker*` traces) is not written.
- Everything else is kept: client-attacker seeds, the honest two-party handshake seeds
  (`seed_successful*`), and session-resumption seeds.
- Implementation detail: `--fingerprinting` implies `--differential` semantics (it sets
  `is_differential = true` internally), then filters by seed name in `fn seed(...)`.

## Why

Deploy-time goal = fingerprint a remote **server**. In that setting the attacker can
only act as a **client**, so server-attacker seeds (where the PUT plays the client)
yield distinguishers that are **not replayable** against a remote server. Excluding
them improves validity and focuses the 1h fuzzing budget on deployable, client-driven
traces.

Note: there is **no MiM seed in the differential corpus** to begin with
(`seed_successful_mitm` exists as a function but is not in `create_corpus`), so nothing
MiM-related is added or removed — only `seed_server_attacker*` is dropped.

## What you must do

- When seeding for fingerprinting campaigns, run:
  `./target/release/tlspuffin seed --fingerprinting`
  (was: `seed --differential`).
- The discovery campaign command (`differential-experiment ...`) is unchanged.
- This flag is additive; `seed --differential` and plain `seed` are unaffected, so the
  bug-finding RQs are not impacted.
