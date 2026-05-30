#!/usr/bin/env python3
"""
Phase 3: Fingerprint triage.

Scans every experiment under experiments/ for objective traces, then keeps
only those that are:

  (a) benign + TCP-observable: Knowledges diffs or observable Status diffs;
      no SecurityClaim, no Claims-only, no crash/ASAN indicators.
  (b) deterministic: same canonical signature across REPEATS re-executions
      of both discovery PUTs.
  (c) deduplicated: among traces with identical observable effect (same
      canonical signature on both PUTs of the discovery pair), keep the
      one with the fewest trace steps.

Output:
  candidates/manifest.csv          — one row per surviving trace
  candidates/<name>.trace          — symlink to the original trace file

Run from repo root: python3 evaluation-ddyf/fingerprinting/triage.py
"""
import csv
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ─── Configurable constants ───────────────────────────────────────────────────
REPEATS     = 10   # Re-execution count for the determinism check (per PUT)
MAX_WORKERS = 16   # Thread-pool width for binary invocations (tune for the server)
# ──────────────────────────────────────────────────────────────────────────────

# Ensure we can import from evaluation-ddyf/ and from this directory
_HERE      = Path(__file__).resolve().parent
_EVAL_DIR  = _HERE.parent
_REPO_ROOT = _EVAL_DIR.parent
sys.path.insert(0, str(_EVAL_DIR))   # for diff_analyzer
sys.path.insert(0, str(_HERE))       # for _canon

from diff_analyzer import get_diff   # noqa: E402
from _canon import get_signature, run_display  # noqa: E402

EXPERIMENTS = _REPO_ROOT / "experiments"
CANDIDATES  = _HERE / "candidates"
MANIFEST    = CANDIDATES / "manifest.csv"
PUFFIN      = _REPO_ROOT / "target" / "release" / "tlspuffin"

MANIFEST_FIELDS = [
    'trace', 'put1', 'put2', 'diff_kinds',
    'sig_put1', 'sig_put2', 'num_steps', 'candidate_path',
]

# ─────────────────────────────────────────────────────────────────────────────


def _check_binary() -> None:
    if not PUFFIN.exists():
        print(f"ERROR: {PUFFIN} not found — run build_all.sh first.", file=sys.stderr)
        sys.exit(1)


def _parse_pair(exp_dir: Path) -> tuple[str, str] | None:
    """Extract (put1, put2) from an experiment's README.md."""
    readme = exp_dir / "README.md"
    if not readme.exists():
        return None
    text = readme.read_text()
    vals = re.findall(r'raw_vals: \[\["([^"]+)"\]\]', text)
    return (vals[0], vals[1]) if len(vals) >= 2 else None


def _find_experiments() -> list[tuple[Path, str, str, list[Path]]]:
    """Return list of (exp_dir, put1, put2, [trace_paths]) for all experiments."""
    results = []
    for exp_dir in sorted(EXPERIMENTS.iterdir()):
        if not exp_dir.is_dir():
            continue
        obj_dir = exp_dir / "objective"
        if not obj_dir.exists():
            continue
        # Exclude hidden files (leading-dot names are temp/in-progress fuzzer artefacts)
        traces = sorted(t for t in obj_dir.glob("*.trace") if not t.name.startswith('.'))
        if not traces:
            continue
        pair = _parse_pair(exp_dir)
        if pair is None:
            print(f"  WARNING: could not parse pair from {exp_dir.name}", file=sys.stderr)
            continue
        results.append((exp_dir, pair[0], pair[1], traces))
    return results


_CRASH_WORDS = frozenset([
    'asan', 'sanitizer', 'crash', 'abort', 'segfault',
    'heap-buffer-overflow', 'use-after-free', 'stack-buffer-overflow',
])


def is_benign_observable(diffs: list[dict]) -> bool:
    """
    Return True iff the diff list represents a benign, TCP-observable difference.

    KEEP iff: ≥1 Knowledges diff, OR ≥1 Status diff where the two PUTs
    executed a different number of steps (one terminated early, observable as
    a different number of TCP messages / an alert).

    DROP if: any SecurityClaim diff (ASAN / security violation); all diffs are
    Claims-only (internal, not TCP-observable); any Status diff shows a
    crash/ASAN status string.
    """
    if not diffs:
        return False

    has_observable = False
    for diff in diffs:
        if 'SecurityClaim' in diff:
            return False
        if 'Status' in diff:
            s = diff['Status']
            s1 = s.get('first_status', '')
            s2 = s.get('second_status', '')
            if any(w in s1.lower() for w in _CRASH_WORDS):
                return False
            if any(w in s2.lower() for w in _CRASH_WORDS):
                return False
            if s.get('first_executed_steps', 0) != s.get('second_executed_steps', 0):
                has_observable = True
        if 'Knowledges' in diff:
            has_observable = True

    if not has_observable:
        return False

    # Drop if every diff is Claims-only (internal state, not visible over TCP)
    if all('Claims' in d and 'Knowledges' not in d and 'Status' not in d
           for d in diffs):
        return False

    return True


def _diff_kinds(diffs: list[dict]) -> str:
    kinds: set[str] = set()
    for d in diffs:
        if 'Knowledges' in d:
            kinds.add('Knowledges')
        elif 'Status' in d:
            kinds.add('Status')
    return '+'.join(sorted(kinds))


def _triage_one(trace: Path, put1: str, put2: str) -> tuple[str, dict | None]:
    """
    Triage a single trace.

    Returns (status, result_dict_or_None) where status is one of:
      'kept'               — trace passed all filters
      'dropped_benign'     — failed the benign/observable filter
      'dropped_det'        — failed the determinism filter
      'dropped_client_only'— all agents are Client-role (no Server to fingerprint)
      'error'              — binary invocation error
    """
    # ── Step 1: benign / observable filter ───────────────────────────────────
    try:
        diffs = get_diff(str(trace), put1, put2)
    except BaseException:
        return 'error', None

    if not is_benign_observable(diffs):
        return 'dropped_benign', None

    # ── Step 2: determinism filter ───────────────────────────────────────────
    # Run display-execute REPEATS times on each PUT; if the canonical signature
    # varies across runs, the trace is non-deterministic and dropped.
    sigs: dict[str, list[str]] = {put1: [], put2: []}
    for put in (put1, put2):
        for _ in range(REPEATS):
            s = get_signature(trace, put)
            if s is None:
                return 'error', None
            sigs[put].append(s)
        if len(set(sigs[put])) > 1:
            return 'dropped_det', None

    sig_put1 = sigs[put1][0]
    sig_put2 = sigs[put2][0]

    # ── Step 3: agent-type check + step count for dedup ──────────────────────
    # We need display-execute output for step count anyway; reuse it to check
    # whether the trace has a Server-role agent.  Client-only traces (wolfssl
    # acting entirely as TLS client) cannot fingerprint a remote server.
    data = run_display(trace, put1)
    if data is None:
        return 'error', None
    agents = data['execution'].get('agents', [])
    has_server = any(a.get('protocol_config', {}).get('typ') == 'Server' for a in agents)
    has_client = any(a.get('protocol_config', {}).get('typ') == 'Client' for a in agents)
    if has_client and not has_server:
        return 'dropped_client_only', None
    num_steps = data['execution']['number_of_steps']

    return 'kept', {
        'trace':      str(trace),
        'put1':       put1,
        'put2':       put2,
        'diff_kinds': _diff_kinds(diffs),
        'sig_put1':   sig_put1,
        'sig_put2':   sig_put2,
        'num_steps':  num_steps,
        'dedup_key':  sig_put1 + sig_put2,
    }


def main() -> None:
    _check_binary()

    experiments = _find_experiments()
    if not experiments:
        print(f"No experiments with objective traces found under {EXPERIMENTS}")
        return

    total_input = sum(len(traces) for _, _, _, traces in experiments)
    print(f"Experiments found : {len(experiments)}")
    print(f"Objective traces  : {total_input}")
    print(f"Determinism repeats: {REPEATS}  (per PUT,  {REPEATS * 2} total per trace)")
    print(f"Parallelism       : {MAX_WORKERS} threads\n")

    # ── Triage (parallel) ────────────────────────────────────────────────────
    jobs = [
        (trace, put1, put2)
        for _, put1, put2, traces in experiments
        for trace in traces
    ]

    counts: dict[str, int] = {
        'kept': 0, 'dropped_benign': 0, 'dropped_det': 0,
        'dropped_client_only': 0, 'error': 0,
    }
    kept_raw: list[dict] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_triage_one, t, p1, p2): i
                   for i, (t, p1, p2) in enumerate(jobs)}
        done = 0
        for fut in as_completed(futures):
            done += 1
            status, result = fut.result()
            counts[status] += 1
            if result is not None:
                kept_raw.append(result)
            if done % max(1, len(futures) // 10) == 0 or done == len(futures):
                print(f"  triaged {done}/{len(futures)} traces …", end='\r', flush=True)

    print()
    after_benign = total_input - counts['dropped_benign'] - counts['error']
    after_det    = after_benign - counts['dropped_det']
    after_co     = after_det - counts['dropped_client_only']
    print(f"\nBenign/observable filter : {after_benign}/{total_input} kept  (dropped {counts['dropped_benign']} non-benign, {counts['error']} errors)")
    print(f"Determinism filter       : {after_det}/{after_benign} kept  (dropped {counts['dropped_det']} non-det)")
    print(f"Client-only filter       : {after_co}/{after_det} kept  (dropped {counts['dropped_client_only']} client-only traces)")
    print(f"After all filters        : {counts['kept']} traces")

    # ── Deduplication ────────────────────────────────────────────────────────
    groups: dict[str, list[dict]] = {}
    for r in kept_raw:
        groups.setdefault(r['dedup_key'], []).append(r)

    final: list[dict] = []
    for group in groups.values():
        best = min(group, key=lambda x: (x['num_steps'], x['trace']))
        final.append(best)

    print(f"After deduplication      : {len(final)} candidates "
          f"(removed {counts['kept'] - len(final)} duplicates)")

    # ── Write output ─────────────────────────────────────────────────────────
    CANDIDATES.mkdir(parents=True, exist_ok=True)
    for f in CANDIDATES.glob("*.trace"):
        f.unlink(missing_ok=True)

    rows: list[dict] = []
    for r in sorted(final, key=lambda x: x['trace']):
        src = Path(r['trace']).resolve()
        dst = CANDIDATES / src.name
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        os.symlink(src, dst)
        rows.append({
            'trace':          r['trace'],
            'put1':           r['put1'],
            'put2':           r['put2'],
            'diff_kinds':     r['diff_kinds'],
            'sig_put1':       r['sig_put1'],
            'sig_put2':       r['sig_put2'],
            'num_steps':      r['num_steps'],
            'candidate_path': str(dst),
        })

    with open(MANIFEST, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} candidates → {CANDIDATES}")
    print(f"Manifest → {MANIFEST}")


if __name__ == '__main__':
    main()
