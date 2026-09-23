"""Non-destructive bucket-coverage analyzer for the SSH differential triage.

Companion to `sort_objectives_libssh_wolfssh.py`. Where that script *moves* each
objective into its bucket subfolder, this one only *measures*: it re-executes a
sample of objectives with the CURRENT fuzzer binary (`PUFFIN_PATH`) and reports,
without touching any files, four categories:

  NO-DIFF     the trace no longer diverges under the current oracle (it was an
              objective of some older campaign but the current filter/shadow layer
              now suppresses it) -> it is NOT part of the tail to reduce.
  <bucket>    classified by the FIRST matching bucket in sort_objectives_libssh_wolfssh.
  UNBUCKETED  still diverges but matches no bucket -> the real "unbucketed tail".
              Grouped by diff signature so the recurring shapes to bucket next are visible.
  SKIPPED     execution could not be parsed (timeout / sanitizer abort / no JSON).

The headline metric is the bucketed vs unbucketed split *among the traces that still
diverge* (NO-DIFF and SKIPPED are excluded from the denominator) -- that is the honest
"how much of the current objective stream is named" number.

Usage:
  ASAN_OPTIONS=detect_leaks=0 PUFFIN_PATH=target/release/sshpuffin \\
  SSHPUFFIN_FIRST_PUT=libssh0114-asan SSHPUFFIN_SECOND_PUT=wolfssh150-asan \\
    python -m evaluation_ddyf.ssh.analyze_buckets <objective_dir> [sample_N] [parallelism]

`sample_N` = 0 (default) scans every trace; otherwise a deterministic random sample
(seed 0) of that size. Reads recursively.
"""
import os
import sys
import random
from collections import Counter
from multiprocessing.pool import ThreadPool as Pool

from ..diff_analyzer import ExecutionStatus, get_error, VALID
from .sort_objectives_libssh_wolfssh import buckets, FIRST_PUT, SECOND_PUT


def classify(path):
    es = ExecutionStatus(path, FIRST_PUT, SECOND_PUT)
    if es.errors is None:
        return ("SKIPPED", None)
    if len(es.errors) == 0:
        return ("NODIFF", None)
    for name, cond in buckets.items():
        try:
            if cond.check_condition(es):
                return ("BUCKET", name)
        except Exception:
            # a malformed status/diff should not abort the whole run
            continue
    return ("UNBUCKETED", get_error(es.errors))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    root = sys.argv[1]
    sample = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    par = int(sys.argv[3]) if len(sys.argv) > 3 else 24

    files = []
    for dp, _dirs, fns in os.walk(root):
        for f in fns:
            if VALID.search(f):
                files.append(os.path.join(dp, f))
    random.seed(0)
    random.shuffle(files)
    if sample:
        files = files[:sample]

    with Pool(par) as p:
        res = p.map(classify, files)

    cat = Counter(r[0] for r in res)
    bucket_counts = Counter(r[1] for r in res if r[0] == "BUCKET")
    unb = Counter(r[1] for r in res if r[0] == "UNBUCKETED")
    n = len(res)
    diverge = cat["BUCKET"] + cat["UNBUCKETED"]  # traces that still diverge

    print(f"PUTs: {FIRST_PUT} vs {SECOND_PUT}")
    print(f"scanned={n}  NO-DIFF={cat['NODIFF']}  SKIPPED={cat['SKIPPED']}  still-diverge={diverge}")
    if diverge:
        print(f"  bucketed   = {cat['BUCKET']:6d}  ({100*cat['BUCKET']/diverge:5.1f}% of diverging)")
        print(f"  UNBUCKETED = {cat['UNBUCKETED']:6d}  ({100*cat['UNBUCKETED']/diverge:5.1f}% of diverging)")
    print("\n=== per-bucket (of diverging) ===")
    for k, v in bucket_counts.most_common():
        print(f"  {v:6d}  {k}")
    print("\n=== UNBUCKETED diff signatures (top 40) ===")
    for sig, v in unb.most_common(40):
        s = (sig or "").replace("\n", " ")
        print(f"  {v:6d}  {s[:180]}")


if __name__ == "__main__":
    main()
