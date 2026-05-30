#!/usr/bin/env python3
"""
Phase 4: Signatures & clustering.

For every candidate trace (from candidates/manifest.csv) and every included
wolfssl version, runs display-execute and computes a canonical structural
signature of the TCP-observable response.  Emits:

  candidates/signatures.csv   — rows=traces, cols=versions, cells=sig hash
  candidates/clusters.json    — groups of versions that are indistinguishable

Also cross-validates a sample of (trace, version-pair) results against
differential-execute to catch canonicalization bugs.

Run from repo root: python3 evaluation-ddyf/fingerprinting/signatures.py
"""
import csv
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ─── Configurable constants ───────────────────────────────────────────────────
MAX_WORKERS = 16   # Thread-pool width for binary invocations (tune for the server)

# VERSIONS is intentionally left empty so the list is derived automatically.
# Detection order:
#   1. vendor/ directories matching wolfssl[0-9]+ (no -asan suffix) — reflects
#      what mk_vendor actually built, so it can never drift from the real state.
#   2. build_results.md rows where Included? == YES — useful before vendor/ is
#      populated (e.g. dry-run/preview runs).
#   3. Last resort: union of put1/put2 from the manifest — only covers the
#      versions that appear in some discovery pair.
# Override by setting this list explicitly if you ever need a fixed subset.
VERSIONS: list[str] = []

# Cross-validation sample: fraction of (trace, pair) combinations to validate.
# 1.0 = every pair; lower for speed.  At 25 versions and ~200 traces, 1.0 would
# be ~60 000 subprocess calls (~1 hour); 0.1 gives ~6 000 calls (~6 min at 16 workers).
XVAL_SAMPLE = 0.1
# ──────────────────────────────────────────────────────────────────────────────

_HERE      = Path(__file__).resolve().parent
_EVAL_DIR  = _HERE.parent
_REPO_ROOT = _EVAL_DIR.parent
sys.path.insert(0, str(_EVAL_DIR))
sys.path.insert(0, str(_HERE))

from diff_analyzer import get_diff   # noqa: E402
from _canon import get_signature     # noqa: E402

CANDIDATES   = _HERE / "candidates"
MANIFEST     = CANDIDATES / "manifest.csv"
SIG_CSV      = CANDIDATES / "signatures.csv"
CLUSTERS_JSON = CANDIDATES / "clusters.json"
PUFFIN       = _REPO_ROOT / "target" / "release" / "tlspuffin"

# Sentinel for execution failure (keeps it distinct from any real SHA-256 hash)
_ERR = "ERROR"

# ─────────────────────────────────────────────────────────────────────────────


def _check_prerequisites() -> None:
    if not PUFFIN.exists():
        print(f"ERROR: {PUFFIN} not found — run build_all.sh first.", file=sys.stderr)
        sys.exit(1)
    if not MANIFEST.exists():
        print(f"ERROR: {MANIFEST} not found — run triage.py first.", file=sys.stderr)
        sys.exit(1)


def _read_manifest() -> list[dict]:
    with open(MANIFEST, newline='') as f:
        return list(csv.DictReader(f))


def _detect_versions() -> list[str]:
    """
    Auto-detect built non-ASan PUT names.  Detection order (first wins):
      1. vendor/ dirs matching wolfssl[0-9]+ — reflects exactly what was built.
      2. build_results.md rows where Included? == YES.
    Returns a version-sorted list of PUT names.
    """
    vendor = _REPO_ROOT / "vendor"
    if vendor.exists():
        puts = sorted(
            d.name for d in vendor.iterdir()
            if d.is_dir() and re.match(r'^wolfssl\d+$', d.name)
        )
        if puts:
            return puts

    results_md = _HERE / "build_results.md"
    if results_md.exists():
        puts = []
        for line in results_md.read_text().splitlines():
            # Match rows like "| 5.0.0 | YES | YES | YES |"
            m = re.match(r'\|\s*([\d.]+)\s*\|\s*YES\s*\|\s*YES\s*\|\s*YES\s*\|', line)
            if m:
                puts.append(f"wolfssl{m.group(1).replace('.', '')}")
        if puts:
            return puts

    return []


def _collect_versions(rows: list[dict]) -> list[str]:
    """
    Return the ordered PUT-name list to evaluate against every candidate trace.
    Priority: explicit VERSIONS constant → auto-detect from vendor/build_results
    → last-resort union of discovery-pair PUT names from manifest.
    """
    if VERSIONS:
        return list(VERSIONS)

    detected = _detect_versions()
    if detected:
        print(f"  (auto-detected {len(detected)} versions from built artifacts)")
        return detected

    # Last resort: only covers versions that appear in discovery pairs
    seen: set[str] = set()
    ordered: list[str] = []
    for row in rows:
        for v in (row['put1'], row['put2']):
            if v not in seen:
                seen.add(v)
                ordered.append(v)
    return ordered


def _compute_sig(trace: str, version: str) -> str:
    """Return the canonical signature hash, or _ERR on failure."""
    s = get_signature(trace, version)
    return s if s is not None else _ERR


def _build_matrix(
    traces: list[str],
    versions: list[str],
) -> dict[str, dict[str, str]]:
    """
    Returns matrix[trace][version] = sig_hash.
    Computed in parallel.
    """
    jobs: list[tuple[str, str]] = [
        (t, v) for t in traces for v in versions
    ]
    matrix: dict[str, dict[str, str]] = {t: {} for t in traces}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_compute_sig, t, v): (t, v) for t, v in jobs}
        done = 0
        for fut in as_completed(futures):
            done += 1
            t, v = futures[fut]
            matrix[t][v] = fut.result()
            if done % max(1, len(futures) // 10) == 0 or done == len(futures):
                print(f"  computed {done}/{len(futures)} signatures …", end='\r', flush=True)

    print()
    return matrix


def _write_signatures_csv(
    traces: list[str],
    versions: list[str],
    matrix: dict[str, dict[str, str]],
) -> None:
    with open(SIG_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['trace'] + versions)
        for t in traces:
            writer.writerow([t] + [matrix[t].get(v, _ERR) for v in versions])
    print(f"Wrote {SIG_CSV}")


def _cluster_versions(
    traces: list[str],
    versions: list[str],
    matrix: dict[str, dict[str, str]],
) -> list[list[str]]:
    """
    Group versions whose signature column-vector is identical across all traces.
    Versions with at least one _ERR signature are placed in singleton clusters
    (we cannot confirm they are indistinguishable from others).
    """
    def col_vec(v: str) -> tuple[str, ...]:
        return tuple(matrix[t].get(v, _ERR) for t in traces)

    groups: dict[tuple, list[str]] = {}
    for v in versions:
        vec = col_vec(v)
        if _ERR in vec:
            # Treat ERROR versions as their own singleton group
            groups[(v,)] = [v]
        else:
            groups.setdefault(vec, []).append(v)

    # Flatten (drop tuple keys, keep version lists)
    return [vlist for vlist in groups.values()]


def _cross_validate(
    traces: list[str],
    versions: list[str],
    matrix: dict[str, dict[str, str]],
    manifest_rows: list[dict],
    sample: float,
) -> tuple[int, int]:
    """
    For a sample of (trace, v1, v2) triples:
      - sig(t,v1) != sig(t,v2)  ↔  differential-execute reports ≥1 diff
    Returns (agreements, disagreements).
    """
    # Build a quick lookup: trace → (put1, put2) from the discovery pair
    disc: dict[str, tuple[str, str]] = {
        row['trace']: (row['put1'], row['put2']) for row in manifest_rows
    }

    import random
    all_pairs: list[tuple[str, str, str]] = []
    for t in traces:
        for i, v1 in enumerate(versions):
            for v2 in versions[i + 1:]:
                all_pairs.append((t, v1, v2))

    if sample < 1.0:
        k = max(1, int(len(all_pairs) * sample))
        all_pairs = random.sample(all_pairs, k)

    agree = 0
    disagree = 0
    for t, v1, v2 in all_pairs:
        s1 = matrix[t].get(v1, _ERR)
        s2 = matrix[t].get(v2, _ERR)
        if s1 == _ERR or s2 == _ERR:
            continue
        sig_differs = (s1 != s2)
        try:
            diffs = get_diff(t, v1, v2)
            diff_exists = len(diffs) > 0
        except Exception:
            continue
        if sig_differs == diff_exists:
            agree += 1
        else:
            disagree += 1
            print(f"  XVAL DISAGREEMENT: trace={Path(t).name} "
                  f"v1={v1} v2={v2} "
                  f"sig_differs={sig_differs} diff_exists={diff_exists}")

    return agree, disagree


def main() -> None:
    _check_prerequisites()

    manifest_rows = _read_manifest()
    if not manifest_rows:
        print("Manifest is empty — nothing to do.")
        return

    traces   = [row['trace'] for row in manifest_rows]
    versions = _collect_versions(manifest_rows)

    print(f"Candidate traces : {len(traces)}")
    print(f"Versions to test : {versions}")
    print(f"Matrix cells     : {len(traces) * len(versions)}")
    print()

    # ── Build signature matrix ───────────────────────────────────────────────
    print("Computing signatures …")
    matrix = _build_matrix(traces, versions)

    # ── Report execution failures ────────────────────────────────────────────
    for v in versions:
        n_err = sum(1 for t in traces if matrix[t].get(v, _ERR) == _ERR)
        if n_err:
            print(f"  WARNING: {n_err} ERROR signatures for {v}")

    # ── Write signatures.csv ─────────────────────────────────────────────────
    _write_signatures_csv(traces, versions, matrix)

    # ── Cross-validate ───────────────────────────────────────────────────────
    print(f"\nCross-validating (sample={XVAL_SAMPLE:.0%}) …")
    agree, disagree = _cross_validate(traces, versions, matrix, manifest_rows, XVAL_SAMPLE)
    total_xval = agree + disagree
    if total_xval > 0:
        print(f"Cross-validation: {agree}/{total_xval} agreements "
              f"({100*agree/total_xval:.1f}%)  —  {disagree} disagreements")
        if disagree > 0:
            print("  *** DISAGREEMENTS DETECTED — canonicalization may have a bug ***")
    else:
        print("  (no cross-validation samples computed)")

    # ── Cluster versions ─────────────────────────────────────────────────────
    clusters = _cluster_versions(traces, versions, matrix)
    clusters.sort(key=lambda c: versions.index(c[0]))  # stable order

    print(f"\nClusters ({len(clusters)}):")
    cluster_data = []
    for i, vlist in enumerate(clusters):
        cid = f"C{i}"
        print(f"  {cid}: {vlist}")
        cluster_data.append({"id": cid, "versions": vlist})

    with open(CLUSTERS_JSON, 'w') as f:
        json.dump({"clusters": cluster_data}, f, indent=2)
    print(f"Wrote {CLUSTERS_JSON}")

    # ── Self-check against appendix (A0=5.0.0, A1={5.1.0,5.1.1}, B=5.2.0) ──
    v_set = set(versions)
    if {'wolfssl500', 'wolfssl510', 'wolfssl520'} <= v_set:
        # Build a lookup: version → cluster id
        v2c = {v: c['id'] for c in cluster_data for v in c['versions']}
        c500 = v2c.get('wolfssl500')
        c510 = v2c.get('wolfssl510')
        c520 = v2c.get('wolfssl520')
        c511 = v2c.get('wolfssl511')
        ok_500_alone = (c500 != c510 and c500 != c520)
        ok_520_alone = (c520 != c500 and c520 != c510)
        ok_510_511 = (c511 is None or c510 == c511)  # 511 not built = OK for now
        print("\nSelf-check vs appendix (A0=500, A1={510,511}, B=520):")
        print(f"  500 in its own cluster : {'PASS' if ok_500_alone else 'FAIL'}")
        print(f"  520 in its own cluster : {'PASS' if ok_520_alone else 'FAIL'}")
        if c511 is not None:
            print(f"  510 and 511 same cluster: {'PASS' if ok_510_511 else 'FAIL'}")
        else:
            print("  511 not included in this run (full validation pending)")
        if not (ok_500_alone and ok_520_alone and ok_510_511):
            print("  *** SELF-CHECK FAILED — check filter/canonicalization ***")


if __name__ == '__main__':
    main()
