# Fingerprinting prompts — orchestration index

All prompts live in `evaluation-ddyf/fingerprinting/prompts/`. `cat` and paste into the named
agent. Owners: **agy** = Antigravity/Gemini (build/run, mechanical, saves Claude quota);
**Sonnet/Claude** = reasoning (canonicalization, methodology, paper); **shell** = no AI.

Global invariants for every step: run in `nix-shell ./shell.nix`; `LIBAFL_EDGES_MAP_SIZE=262144`
before fuzzing; **non-ASan** builds; **AI-free at runtime** (replay + canonical hash + tree walk,
no LLM/ML/fuzzer at deploy); reuse `_canon.py` as the single canonicalization; never fabricate
numbers; STOP at the marked checkpoints; don't tune to preserve results (falsification, not
confirmation).

## Status / order

DONE (WolfSSL, ASan->non-ASan, 26 versions): build -> discover -> triage -> signatures ->
build_tree -> paper. Result: 21 clusters, depth-3 tree, 10 probes (pre no-decryption change).

### Open work, in dependency order
1. **H — claim independence** (`H_sonnet_claim_independence.txt`, Sonnet). Verify the WolfSSL
   tree/clusters are reproducible from the wire channel only. NOTE: largely SUPERSEDED by the
   no-decryption methodology now baked into step 2 — if you run K's Step 3, you get the same
   answer. Keep H only if you want the standalone offline check.
2. **K — OpenSSL no-claims spike** (`K_agy_openssl_noclaims_spike.txt`, agy). GATE: one upstream
   OpenSSL 3.4.0 builds no-claims + yields a signature; updates `_canon.py` for the
   no-decryption (opaque-record) signature; re-validates WolfSSL clusters (21 -> N, honestly).
   => Human reviews the gate AND the WolfSSL re-validation before anything downstream.
3. **Paper update (WolfSSL)** — if K's Step 3 changes the WolfSSL cluster count, a Claude session
   updates RQ5 + appendix to the corrected no-decryption numbers (see D-style task).
4. **L — OpenSSL full 26-version run** (`L_agy_openssl_full_run.txt`, agy). Fires only after K's
   gate passes. Vendor-parametric; outputs to `candidates_openssl/`. STOP at build table + clusters.
5. **G — live TCP probe tool** (`G_agy_live_probe_tool.txt`, agy). Build the deployable
   tree-walking prober; needs the `tcp -j --json` path (already in cli.rs). Run on the VERIFIED
   WolfSSL tree (post step 2/3), then OpenSSL. Part C hash-agreement is the live backstop.
6. **M — combined cross-vendor tree** (`M_combined_cross_vendor_tree.md`, agy). After both
   per-vendor models exist. Option 2 (one binary, same build_tree over 52 versions) recommended.
7. **D — paper write-up** (`D_paper_writeup.txt`, Claude/Gemini). Fold OpenSSL + combined +
   live-probe results into the paper. Only measured numbers.

## Reference prompts (already used / context)
- `A_claude_core.txt` — WolfSSL reasoning core (triage/signatures/build_tree). DONE.
- `B_gemini_boilerplate.txt` — mechanical scripts. DONE.
- `C_server_shell.sh` — no-AI build/campaign/pipeline driver.
- `CHANGELOG_seed_fingerprinting.md` — the `seed --fingerprinting` flag (client+honest seeds only).
- `SWITCH_TO_NONASAN.md` — the ASan -> non-ASan switch broadcast. DONE.

## The one decision gate to watch
Step 2 (K) changes the signature methodology (no decryption) and may lower the WolfSSL headline
from 21 clusters. That is the correct, more defensible result (a remote prober needs no keys),
but it revises already-written paper numbers — so K reports back to a human/Claude BEFORE the
paper or any downstream (L, G, M) proceeds.
