#!/usr/bin/env python3
"""Stage 1 -- mine + confirm distinguishing probes from differential-fuzzing objectives.

Differential campaigns (one per adjacent version pair) emit *objective* traces: client-driven
traces on which the two PUTs diverged in-process. Most do NOT reproduce as a wire difference on a
real server, so this stage filters them down to a set of robust, confirmed probes:

  A1 (screen)  -- for each origin pair (A,B), one cheap K-connection batch of every objective
                  trace against live A and B; keep traces giving DISTINCT signatures (both respond).
  A' (dedup)   -- collapse A1 survivors to representatives by their (sigA,sigB) mechanism, capped.
  A2 (confirm) -- re-test each representative with the strict 10x / >=7-of-10 pooled filter on its
                  own pair; keep only those still distinct+stable.
  B  (cross-apply) -- (optional, --cross-apply) replay every confirmed probe against ALL versions
                  and print the wildcard cluster count as a quick sanity check.

The confirmed probe TRACES (full paths) are written to reference/<put>/probes_full/reps.txt and the
trace files copied into probes_full/, which is the gitignored input for build_matrix.py. Run on a
QUIET machine (after campaigns finish) so reads are not starved.
"""
import argparse
import glob
import os
import shutil
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import probe
import puts


def origin_versions(put, tag):
    """'3.0.0-3.0.1' -> ('openssl300','openssl301') using the PUT's naming."""
    line = puts.PUTS[put]["line"]
    out = []
    for part in tag.split("-"):
        comps = part.split(".")
        if len(comps) == 3 and comps[0] == line:
            out.append(f"{put}{line}{comps[1]}{comps[2]}")
    return out if len(out) == 2 else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap)
    puts.add_common_args(ap)
    ap.add_argument("--a1-cap", type=int, default=100000, help="per-pair A1 input cap (speed)")
    ap.add_argument("--rep-cap", type=int, default=4, help="representatives kept per (sigA,sigB) mechanism")
    ap.add_argument("--pair-jobs", type=int, default=1,
                    help="adjacent pairs to screen IN PARALLEL, each on its own port pair. Raises core "
                         "use: per-pair throughput is capped by the single-connection example server, "
                         "so N pairs in flight ~= N x the rate. Default 1 (sequential).")
    ap.add_argument("--cross-apply", action="store_true", help="also cross-apply + print cluster count")
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)
    cfg.prober(put)

    # Locate this PUT's objective traces, grouped by origin pair, via the configured glob.
    exp_glob = cfg.experiments_glob(put)
    print(f"[mine] PUT={put}  objective glob={exp_glob}", flush=True)
    pairs = {}
    for tracef in glob.glob(exp_glob):
        d = os.path.dirname(os.path.dirname(tracef))          # .../<campaign>/objective/x.trace -> campaign
        tag = os.path.basename(d).split("fpp-")[-1].split("--")[0]
        vv = origin_versions(put, tag)
        if not vv:
            continue
        pairs.setdefault(tag, (vv[0], vv[1], []))[2].append(tracef)
    ntot = sum(len(t) for _, _, t in pairs.values())
    print(f"[mine] origin pairs={len(pairs)}  total objective traces={ntot}  jobs={cfg.jobs}", flush=True)
    if not pairs:
        raise SystemExit("no objective traces found; set --experiments-glob / FP_EXPERIMENTS_GLOB")

    # Screen each pair on its OWN port pair (cfg.base_port + 2*idx), so up to --pair-jobs pairs run
    # at once. The single-connection example server caps per-pair throughput, so pair-level
    # parallelism (not bigger --jobs) is what raises core utilisation. Within a pair, A1 screen and
    # A2 confirm stay threaded at cfg.jobs.
    confirmed = []
    pair_list = list(enumerate(pairs.items()))   # (idx, (tag, (A, B, ts)))

    def do_pair(item):
        idx, (tag, (A, B, ts)) = item
        pA, pB = cfg.base_port + 2 * idx, cfg.base_port + 2 * idx + 1
        sA, sB = probe.launch(cfg, put, A, pA), probe.launch(cfg, put, B, pB)
        if not (probe.wait_listen(pA) and probe.wait_listen(pB)):
            probe.kill(sA, sB)
            print(f"  {tag}: SERVER-FAIL", flush=True)
            return []
        # A1: cheap screen of every trace (threaded; servers reused).
        def screen(t):
            a, b = probe.batch(cfg, t, pA), probe.batch(cfg, t, pB)
            return (t, a, b) if (a and b and a != b) else None
        surv = []
        with ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
            for r in ex.map(screen, ts[:args.a1_cap]):
                if r:
                    surv.append(r)
        # A': dedup to representatives by (sigA,sigB) mechanism.
        buckets = defaultdict(list)
        for t, a, b in surv:
            buckets[(a, b)].append(t)
        reps_pair = [t for v in buckets.values() for t in v[:args.rep_cap]]
        # A2: strict confirm with the 10x/>=7 pooled filter.
        def confirm(t):
            a, b = probe.pooled_sig(cfg, t, pA), probe.pooled_sig(cfg, t, pB)
            return t if (a != probe.UNSTABLE and b != probe.UNSTABLE and a != b) else None
        kept = []
        with ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
            for r in ex.map(confirm, reps_pair):
                if r:
                    kept.append(r)
        probe.kill(sA, sB)
        print(f"  {tag:16s} A1={len(surv):5d}/{len(ts):<5d}  mechanisms={len(buckets):3d}  confirmed={len(kept)}",
              flush=True)
        return kept

    with ThreadPoolExecutor(max_workers=args.pair_jobs) as pex:
        for kept in pex.map(do_pair, pair_list):
            confirmed.extend(kept)

    print(f"[mine] confirmed distinguishing probes (no dedup): {len(confirmed)} of {ntot}", flush=True)

    # Persist the full confirmed probe set into probes_full/ (committed input for build_matrix),
    # writing reps.txt with bare filenames so the set is portable / committed-by-default.
    full_dir = cfg.probes_full_dir(put)
    full_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    for t in confirmed:
        bn = os.path.basename(t)
        try:
            shutil.copy2(t, full_dir / bn)
        except Exception:
            pass
        saved.append(bn)
    cfg.reps_file(put).write_text("\n".join(saved) + "\n")
    print(f"[mine] wrote {len(saved)} probe traces -> {full_dir} ; list -> {cfg.reps_file(put)}", flush=True)

    if args.cross_apply:
        from itertools import combinations
        versions = cfg.versions(put)
        sig_len = puts.PUTS[put]["sig_len"]
        print(f"[mine] cross-applying {len(confirmed)} probes to {len(versions)} versions...", flush=True)
        M, p = {}, cfg.base_port + 200
        for vi, v in enumerate(versions):
            s = probe.launch(cfg, put, v, p)
            M[v] = ([probe.sigkey(probe.pooled_sig(cfg, t, p), sig_len) for t in confirmed]
                    if probe.wait_listen(p) else [probe.SRVFAIL] * len(confirmed))
            probe.kill(s)
            p += 1
            if vi % 10 == 0:
                print(f"    cross-apply {vi + 1}/{len(versions)}", flush=True)

        def compat(u, v):
            for x, y in zip(M[u], M[v]):
                if x in probe.MISSING or y in probe.MISSING:
                    continue
                if x != y:
                    return False
            return True
        clusters = []
        for v in versions:
            for cl in clusters:
                if all(compat(v, u) for u in cl):
                    cl.append(v)
                    break
            else:
                clusters.append([v])
        print(f"[mine] wildcard cluster sanity check: {len(clusters)} clusters", flush=True)


if __name__ == "__main__":
    main()
