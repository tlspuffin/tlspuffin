# M — Combined cross-vendor fingerprinting tree (spec)

PREREQUISITE: per-vendor models exist for WolfSSL (`candidates/`) and OpenSSL
(`candidates_openssl/`), both under the same no-decryption `_canon.py`. Goal: one model that
identifies BOTH the vendor and the version, reusing the SAME `build_tree`.

## Key fact
`build_tree.py` and `_canon.py` are vendor-agnostic — they operate on a signature matrix
(versions x probes) and version names. So a combined tree needs only a combined signature
matrix over all versions and all candidate probes. Two ways to get there:

## Option 2 (principled — "same build_tree, more versions") — RECOMMENDED
1. Build ONE tlspuffin binary containing BOTH vendors' PUTs (all built WolfSSL + OpenSSL
   versions). Build all PUTs for both vendors, then a single
   `cargo build --release --features cputs` (do NOT cargo clean between — we want both sets
   linked). Probe traces are protocol-level TLS and replay on any TLS server, so any probe can
   be evaluated on any version.
2. Compute one signature matrix over the UNION of all candidate probes (WolfSSL's + OpenSSL's)
   x the UNION of all versions (52), using the existing signatures.py (vendor-parametric, point
   it at the union). Cross-vendor signatures differ trivially, so the vendor split emerges by
   itself.
3. Run the unchanged build_tree.py on that matrix -> combined_tree.json. The root split(s) will
   separate vendors; deeper splits separate versions within a vendor. Emit
   candidates_combined/{signatures.csv,clusters.json,tree.json,tree.dot,report.md}.
Cost: a larger binary + a bigger signature matrix (52 versions x all probes). No new algorithm.

## Option 1 (cheap compose) — fallback if the 52-PUT binary is unwieldy
Keep the two per-vendor trees as-is and prepend a tiny VENDOR-DISCRIMINATOR root:
1. Pick a handful of probes; compute their signatures across a few versions of EACH vendor
   (needs a binary with at least those versions of both vendors). Choose 1-2 probes whose
   signature cleanly partitions versions by vendor.
2. Build combined_tree.json = {root vendor-probe -> {wolfssl-branch: <candidates/tree.json>,
   openssl-branch: <candidates_openssl/tree.json>}}. The live tool (G) already walks this shape.
Cost: minimal; reuses both per-vendor trees verbatim.

## Notes
- Cross-vendor distinction is trivially easy (stacks differ wildly); the scientific value is the
  intra-vendor version clustering already done per vendor. The combined tree is mostly a
  packaging/deployment convenience + a nice "one probe tells the stack, two more tell the
  version" figure.
- AI-free at runtime; reuse `_canon.py`; nix-shell; report measured numbers only.
- Deliver `candidates_combined/report.md`: total versions, #clusters, vendor-split depth, total
  tree depth/#probes, and how many probes distinguish vendor vs version.
