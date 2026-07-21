# Adapting the DDYF triaging pipeline (TLS → sshpuffin/SSH)

This `evaluation-ddyf/` tree was copied from tlspuffin
`origin/pr/ddyf/triaging-prompts`. The **workflow is protocol-agnostic** (Phase 0
metadata → survey → buckets → granularity → security gate → reports), but every
file is wired for TLS PUTs. This note lists the **verified** deltas you must apply
for sshpuffin. Read `prompts-triaging/ORCHESTRATOR.md` for the workflow itself;
read this for the SSH wiring.

## Environment (sshpuffin needs this; tlspuffin did not)
Every binary invocation needs:
```bash
export LD_LIBRARY_PATH="/nix/store/k0rqiflg1vkn1kj96br5pfxj40p3srz4-zstd-1.5.7/lib:$LD_LIBRARY_PATH"
export ASAN_OPTIONS="verify_asan_link_order=1:detect_leaks=0:abort_on_error=1"
```
The binary is an ASAN build. A deployed copy `./sshpuffin_diff` exists at repo
root (= `target/release/sshpuffin`, built with `--features asan,claims`). Use it
directly (no `nix-shell` needed once `LD_LIBRARY_PATH` is set, verified).

## Binary + PUTs
| TLS (original) | SSH (use this) |
|---|---|
| `target/release/tlspuffin` | `./sshpuffin_diff` (or `target/release/sshpuffin`) |
| `openssl340`, `libressl421`, `wolfssl580` | `libssh0104-asan`, `libssh0114-asan`, `wolfssh-asan` |

Two campaigns are in scope (clean baselines, see `DIFFERENTIAL_FUZZING_PLAN.md`):
- **version**: `libssh0104-asan` vs `libssh0114-asan` (full seed set)
- **xvendor**: `libssh0114-asan` vs `wolfssh-asan` (AES-GCM seeds only)

## CLI compatibility (VERIFIED — the subcommands are defined in shared `puffin/src/cli.rs`, so they are IDENTICAL to tlspuffin)
- `differential-execute --json <first> <second> <trace>` — WORKS (stdout is clean
  JSON; warnings go to stderr — capture stdout only). `diff_analyzer.py::get_diff`
  works as-is after the `PUFFIN_PATH` change.
- `differential-execute ... -S` (security oracle) — WORKS.
- **`display-execute <trace> -tckp` — WORKS** (combinable bare flags, exactly as
  tlspuffin uses). Verified exit 0, emits the term/claim/knowledge sections. (The
  `value_parser!(bool)` in the arg defs does NOT make them value-taking — they are
  `SetTrue` flags; `-t true` actually FAILS with "unexpected argument 'true'".)
  No change needed to the flag form in `phase0_produce_metadata.sh` or
  `diff_analyzer.py` — only the binary path / PUT names / env (below).

## Files to rewrite
1. **`phase0_produce_metadata.sh`** — set `BINARY=./sshpuffin_diff`; export the env
   vars above; replace the two PUT names; change the three `metadata_*` log
   prefixes (`metadata_libssh0104_`, `metadata_libssh0114_` / `_wolfssh_`); fix the
   `display-execute` flags per above. Keep the parallelism + skip-existing logic.
2. **`diff_analyzer.py`** — `PUFFIN_PATH = Path("sshpuffin_diff")`; ensure the
   subprocess inherits `LD_LIBRARY_PATH`/`ASAN_OPTIONS` (set in `os.environ` at top,
   or wrap). The `BucketCondition` engine (`StatusC`, `TermContainsC`,
   `ClaimContainsC`, `CheckAgentC`, `StepC`, `KnowledgeDiffC`, …) is
   protocol-agnostic and reusable unchanged.
3. **Create `sort_objectives_libssh_libssh.py` and `sort_objectives_libssh_wolfssh.py`**
   from `sort_objectives_ossl_wolf.py` as templates. Set `FIRST_PUT`/`SECOND_PUT`.
   The bucket *conditions* are all TLS — REPLACE them with SSH ones (below).

## SSH-specific classification facts (for writing buckets)
- **No `tls_version`.** SSH config is `SshDescriptorConfig { typ: Client|Server,
  try_reuse }`. `CheckAgentC(["protocol_config","tls_version"],…)` has no SSH
  analogue — drop it; key on `typ` if needed.
- **Claims** (`SshClaimInner`): fields `is_server, kex, cipher_in/out,
  hmac_in/out, auth_method, auth_user, auth_key_fingerprint, session_id,
  secure_tx/rx_digest, phase (0=init,1=kex,2=auth,3=done), rx/tx_count`. Use
  `ClaimContainsC` / `DifferentClaimC` on these. NOTE only `phase==3` (DONE)
  claims carry final security state; `phase<3` are coverage-only (distinct
  TypeShape `SshProgressClaim`, already excluded from differential comparison).
- **Term names** are `fn_*` SSH builders (`fn_packet`, `fn_kex_algos`,
  `fn_encrypt_packet_*`, `fn_banner`, …) — see `sshpuffin/src/ssh/fn_*.rs`. Use
  `TermContainsC`/`TermContainsReC` with these.
- **Knowledge types**: `RawSshMessage`, `OnWireData`, `SshMessage`,
  `RawSshMessageFlight` (not TLS records/alerts).
- **The conservative `filter_diff` already runs in-engine**: kept diffs are
  `SecurityClaim` (always), `Claims` (always), `Status` only on acceptance
  disagreement (one `Success`, other a PUT rejection); `Knowledges` dropped. So
  surviving objectives are already meaningful — see the pre-triaged classes below.

## Pre-triaged class distribution (from the 2026-06-28 v1 campaigns — seed the buckets)
**xvendor (libssh0114 vs wolfSSH), reproduces reliably:**
- ~45% `lib=[No version of SSH protocol usable] wolf=Success` (wolfSSH version-string leniency)
- ~30% `lib=[too large banner] wolf=Success` (wolfSSH accepts >255B banner — RFC 4253 §4.2)
- ~9% `lib=[Socket error: File exists] wolf=Success` (libssh's own error — ambiguous, keep)
- ~7% CLAIM-PRESENCE (one completes, other doesn't)
- ~5% `lib=Success wolf=[Unknown error code]` (libssh leniency)

**version (libssh0104 vs libssh0114):**
- ~55% NON-REPRODUCING (RNG non-determinism — OpenSSL 3.x ignores legacy
  RAND_METHOD for X25519; flag these as a flakiness bucket, not findings)
- ~25% CLAIM-PRESENCE
- remainder: `AUTH/SESSION_ERROR: Invalid padding` (strict-kex), `Packet filter` (0.11.4)
- 0 SecurityClaim, 0 crashes.

## TLS reference files to REINTERPRET (not delete — adapt)
- `prompts-triaging/CVSS_TLS.md` — CVSS methodology is reusable; TLS examples are
  not. Score SSH findings with the same method, SSH context.
- `prompts-triaging/DIFF_OUTPUT_REFERENCE.md` — TLS output-type reference; rewrite
  for SSH message/knowledge/claim types.
- `count_tls_*.yml` — TLS field catalogues; not needed unless you do field-count
  ablations.
- SSH RFCs for the security gate: 4251 (arch), 4252 (auth), 4253 (transport),
  4254 (connection), 8308 (ext-info), 8332 (rsa-sha2), terrapin-attack.com.

## Trace input
The pipeline reads `./objective/`. The v1 campaign objectives are under:
- version: `experiments/2026-06-28--*v1-version-0104-0114*/objective/`
- xvendor: `diff_xvendor/experiments/2026-06-28--*v1-xvendor*/objective/`
Run ONE pair at a time: copy (or symlink) that campaign's `objective/*.trace`
into `./objective/`, run the whole pipeline, then swap for the other pair.
(There are ~1.3K version + ~17K xvendor objectives — "Medium"/"Large" size bands
per ORCHESTRATOR.md. Consider sampling the xvendor set first.)
