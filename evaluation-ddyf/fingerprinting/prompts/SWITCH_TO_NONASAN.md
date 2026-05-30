# BROADCAST to all agent sessions — switch the fingerprinting pipeline to NON-ASan

**Decision (human, 2026-05-29): the fingerprinting evaluation switches from ASan to
non-ASan builds — full switch now.** Everything currently built/run with ASan
(`wolfsslXYZ-asan`, `--features cputs,asan`) is being discarded for this experiment.

Read your role section. TL;DR for everyone first.

## Why
Fingerprinting keeps only benign, TCP-observable differences and discards crashes, so
ASan's memory-error detection is unused here. Non-ASan builds (a) match real-world
deployed servers, so signatures are representative; (b) are ~2× faster → more candidates
per 1h campaign; (c) can surface benign-in-production behaviors that ASan would abort on.
This matches the project convention (`DDYF_README.md` uses `--features cputs`, no asan).
NOTE: ASan does not change benign on-the-wire behavior, so the resulting tree should be
the same — we switch for validity, throughput, and clean paper claims.

## TL;DR — everyone, right now
1. **STOP** whatever you are running. All in-flight discovery campaigns, triage runs,
   and signature passes are on ASan PUTs and are now invalid. Do not start new ASan work.
2. Wait until the archive step (below) is done before any new build/run.

## Step 1 — ARCHIVE (owner: Antigravity / "agy")
Stop all `tlspuffin` processes and the background launcher, then move the ASan-era
outputs aside (do not delete — keep for reference / comparison):
```
pkill -f 'target/release/tlspuffin' ; pkill -f launch_parallel_campaigns.sh
mkdir -p archive_asan
mv experiments                                   archive_asan/experiments
mv evaluation-ddyf/fingerprinting/candidates     archive_asan/candidates      2>/dev/null || true
mv evaluation-ddyf/fingerprinting/build_results.md archive_asan/build_results_asan.md 2>/dev/null || true
# also move any signatures.csv / clusters.json / tree.* already produced
mv evaluation-ddyf/fingerprinting/{signatures.csv,clusters.json,tree.json,tree.dot,report.md} archive_asan/ 2>/dev/null || true
mkdir -p experiments
```

## Step 2 — ADAPT SCRIPTS (owner: Claude Sonnet) — EDIT ONLY, DO NOT RUN
Convert every fingerprinting script from `-asan` PUTs to plain non-ASan PUTs. Antigravity
will run them afterwards. Concretely:

- `presets_gen.py`: emit non-ASan blocks named `[wolfsslXYZ]` (NO `-asan` suffix) and
  **remove the `asan = true` line**; keep `sancov = true` and `fix = ["AllowClaim"]`.
  Idempotent (skip blocks already present). The full 26-tag list is unchanged.
- `build_all.sh`: build `./tools/mk_vendor make "wolfssl:wolfssl${NAME_VER}"` (no `-asan`)
  and build the harness with `cargo build --release --bin tlspuffin --features cputs`
  (DROP `,asan`). Keep the per-version PUT/harness result table and the STOP-on-harness-
  failure behavior. Note 5.2.1 already fails at the C level — keep it excluded.
- `discover.sh`: PUT names `wolfssl${v//./}` (no `-asan`). Nothing else changes.
- `launch_parallel_campaigns.sh` (repo root): same — non-ASan PUT names.
- `signatures.py`: replace the hardcoded `-asan` PUT list with non-ASan names. PREFER to
  derive the list from `build_results.md` (Included? == YES) or the `vendor/` dir rather
  than hardcoding, so it can't drift again. Keep 5.2.1 excluded.
- `build_tree.py`, `run_all.sh`, `triage.py`: remove any `-asan` / `cputs,asan`
  assumptions.
- Use `seed --fingerprinting` (NOT `seed --differential`) — see the dedicated section
  below. This flag is orthogonal to the ASan switch but is mandatory for these campaigns.
- Self-check when done: `grep -rn "asan" evaluation-ddyf/fingerprinting --include=*.py
  --include=*.sh` should return only intentional mentions (comments / archive paths).
- Do NOT run builds or campaigns. Hand back to Antigravity.

## Seed generation: use `seed --fingerprinting` (NOT `seed --differential`)

A new CLI flag was added (`puffin/src/cli.rs`). For these campaigns, seeds MUST be
generated with it.

- **What it does:** behaves exactly like `seed --differential` (same uniformised PUT
  descriptors) **except it drops the 4 server-attacker seeds** (`seed_server_attacker*`).
  Client-attacker seeds, the honest two-party `seed_successful*` handshakes, and
  session-resumption seeds are all kept.
- **Why:** the deploy-time goal is to fingerprint a remote **server**. In that setting
  the attacker can only act as a **client**. Server-attacker seeds put the PUT in the
  *client* role — distinguishers found from them are **not replayable** against a real
  remote server, so they would pollute the candidate set with undeployable traces.
  Excluding them improves validity and concentrates the 1h fuzzing budget on
  client-driven traces (which is exactly what the two appendix distinguishers are).
- **Effect:** after `seed --fingerprinting`, `./seeds/` contains **no
  `*server_attacker*` traces**; every discovery campaign therefore starts from a corpus
  of only client-driven + honest-handshake seeds, and every harvested candidate is
  replayable against a real server. (There is no MiM seed in the corpus to begin with —
  `seed_successful_mitm` is not in `create_corpus` — so nothing MiM-related changes.)
- **Quick check:** `ls seeds/ | grep -c server_attacker` should print `0`.
- **Requires the rebuilt binary:** the flag only exists after `build_all.sh` rebuilds
  `tlspuffin` (Step 3 does this). Detail: `--fingerprinting` implies `--differential`
  internally. It is additive — plain `seed` and `seed --differential` are unaffected, so
  the bug-finding RQs are not impacted.

## Step 3 — REBUILD & RELAUNCH (owner: Antigravity / "agy") — only after Step 2
Inside `nix-shell ./shell.nix`, `export LIBAFL_EDGES_MAP_SIZE=262144`, then:
```
python evaluation-ddyf/fingerprinting/presets_gen.py     # review diff
bash   evaluation-ddyf/fingerprinting/build_all.sh        # non-ASan; 5.2.1 excluded
./target/release/tlspuffin seed --fingerprinting          # client+honest seeds only
bash   launch_parallel_campaigns.sh                       # 24 adjacent pairs, non-ASan
```
Same parallelism as before (batches, dedicated cores per campaign, distinct ports). When
campaigns finish, the downstream pipeline (triage → signatures → tree) is re-run by the
Claude session on the non-ASan data.

## Notes
- Non-ASan harness will build cleanly: the ASan run had zero Rust API drift, so expect
  25/26 versions again (only 5.2.1 fails, at the C level, independent of ASan).
- It is fine if `vendor/` ends up containing both `-asan` and non-ASan builds; the scripts
  now reference only the non-ASan names.
