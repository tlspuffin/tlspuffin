# OpenSSL fingerprinting fix — objective oracle made wire-observable

## Root cause (confirmed)
The OpenSSL "non-determinism" that made fingerprinting fail (a probe respond ~50% of the
time over TCP, identification ≤2/12) was **not an OpenSSL property**. It is the
**differential objective oracle flagging tlspuffin-internal `Fn`/Crypto errors**:

- A fuzzer-mutated trace feeds OpenSSL's fresh per-connection crypto-random bytes
  (ServerHello.random / ephemeral ECDH key) into a length-prefixed decoder
  (`fn_decode_client_ecdh_pubkey`). The first random byte is read as a length `L`;
  ~50% of the time `L` overruns the buffer → rustls `Reader` fails →
  `FnError::Codec("Failed to parse client ecdh public key")` → trace aborts
  (`executed_until=0`). (Diagnosis: AGY. Independently corroborated — the exact Codec
  error appears in the flaky runs; a **stock, non-sancov `openssl 3.0.20` is equally
  flaky**, so it is not a build/sancov/harness artifact.)
- A branch change to `DifferentialRunner::execute_config` (`puffin/src/execution.rs`)
  had broadened the status-diff oracle from matching only `Error::Put` to `is_exec_failure`
  (= any error incl. `Fn`/Crypto) **and** added `e1.to_string() != e2.to_string()`. So a
  non-deterministic `Fn` outcome became an objective. The `EMPTY` then conflated
  "tlspuffin parse-failure" with "server sent nothing".

## The fix (DONE in this commit, `puffin/src/execution.rs`)
Status objectives are now **wire-observable only**: only PUT-level outcomes count, and
only the **step reached** is observable (never the internal error string):

```
both PUT errors             -> objective iff DIFFERENT executed_until (step)
exactly one PUT error       -> always an objective (other side Ok or non-PUT error)
no PUT error on either side -> no status objective  (Fn/Crypto/Ok handled elsewhere)
```
`Fn`/`Crypto`/`Term`/`IO`/`Agent`/`Stream`/`Extraction` never create objectives;
same-step PUT/PUT differences (error-string only) are no longer flagged; the
content/flight diff and SecurityClaim diff are unchanged and orthogonal.

**NOT build-verified** (AGY is running; building would touch `target/` and contend).
Build + `cargo test` to confirm before relying on it. `puffin/src/cli.rs` (AGY's
display-execute fix) was intentionally left untouched/uncommitted.

## Remaining plan (do when AGY is done)
1. **Re-triage existing objectives** against the new rule: the ~55k objectives were
   generated with the broadened oracle, so drop any whose `StatusDiff` is (a) `Fn`/Crypto
   based or (b) same-step (string-only). Avoids re-fuzzing. When re-triaging/dedup, do NOT
   key on the `Fn` status string (use PUT side + steps) so non-determinism can't sneak back.
2. **Determinism safety-net filter** (LLM-free): replay each retained candidate K≥10×
   against a reference server; keep only those whose execution is stable.
3. **Re-fingerprint OpenSSL** on the cleaned pool: `mine_traces.py` → `build_live_matrix.py`
   (`--server-cmd openssl`, repeat 11) → `build_tree.py` → `robust_validate.py`. Expect
   WolfSSL-like reproducibility (re-probe ~dist 0).
4. **Re-fuzz** later with the fixed oracle for a clean pool if the re-triaged pool is thin.
5. **Unify + re-audit WolfSSL** through the same oracle; **correct `FINDINGS_2026-06-05.md`**
   (OpenSSL’s apparent non-determinism = oracle flagging `Fn`/Crypto errors, not OpenSSL).

## Make-or-break check
After excluding `Fn`/Crypto and same-step diffs, confirm enough **PUT-error + step +
content + security-claim** signal remains to separate the 61 versions. The re-triage
count answers this immediately. Since OpenSSL's *deterministic* responses do differ by
version, this is now likely.

Constraint: trace selection stays a deterministic script (pipeline LLM-free at runtime).
