#!/usr/bin/env python3
"""Stage 0 -- launch the differential-fuzzing campaigns that PRODUCE the objective traces.

For each adjacent version pair of a PUT this runs one DDYF differential campaign
(`tlspuffin ... differential-experiment <verA> <verB> -t fpp-<dotA>-<dotB>`), which writes the
objective traces (client-driven traces on which the two versions diverged) under `experiments/`.
`mine_probes.py` then distils those into the confirmed probe set. This closes the loop so the whole
pipeline -- campaigns -> mine -> matrix -> tree -> validate -> report -- is reproducible end to end.

The campaign binary is the same `tlspuffin` used as the prober (it has both the `tcp` and
`differential-experiment` subcommands); it must be built with the PUTs compiled in:

    VENDOR_DIR=<repo>/vendor cargo build --release -p tlspuffin --features cputs

Campaigns run from the repo root so traces land in `<repo>/experiments/` where mine_probes looks.
Each pair is time-boxed (`--timeout`) and `--jobs` pairs run in parallel on the given `--cores`.

Example:
    python3 run_campaigns.py --put openssl --timeout 1h --jobs 20 --cores 0-19
    python3 run_campaigns.py --put wolfssl --timeout 12h --jobs 12
"""
import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import puts


def parse_duration(s):
    """'90' -> 90s, '30m' -> 1800, '12h' -> 43200."""
    s = str(s).strip()
    if s.endswith("h"):
        return int(float(s[:-1]) * 3600)
    if s.endswith("m"):
        return int(float(s[:-1]) * 60)
    return int(float(s.rstrip("s")))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap)
    # this script defines its own --timeout/--jobs (campaign-level), so only pull the path options
    puts.add_common_args(ap, only={"repo_root", "vendor_dir", "prober", "cores", "base_port"})
    ap.add_argument("--timeout", dest="campaign_timeout", default="1h",
                    help="wall-clock per campaign, e.g. 90, 30m, 12h (default 1h)")
    ap.add_argument("--jobs", dest="parallel", type=int, default=None,
                    help="campaigns to run in parallel (default: len(--cores) or 8)")
    ap.add_argument("--fuzz-cores", default="1",
                    help="cores PER campaign passed to tlspuffin --cores (default 1)")
    ap.add_argument("--dry-run", action="store_true", help="print the campaign commands and exit")
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)
    binary = cfg.prober(put)                      # same tlspuffin (has differential-experiment)

    versions = cfg.versions(put)
    pairs = list(zip(versions, versions[1:]))     # adjacent pairs in version order
    secs = parse_duration(args.campaign_timeout)
    cores = [c for c in (cfg.cores or "").replace("-", ",").split(",") if c]  # rough width hint
    par = args.parallel or (len(cores) if cores else 8)
    print(f"[campaigns] PUT={put}  pairs={len(pairs)}  timeout={secs}s/pair  parallel={par}  "
          f"binary={binary}  out={cfg.repo}/experiments/", flush=True)

    def launch(idx_pair):
        i, (a, b) = idx_pair
        title = f"fpp-{puts.dotted(put, a)}-{puts.dotted(put, b)}"
        port = cfg.base_port + (i % 1000)
        cmd = [binary, "-p", str(port), "--cores", args.fuzz_cores,
               "differential-experiment", a, b, "-t", title]
        if args.dry_run:
            print("  " + " ".join(cmd))
            return (a, b, 0)
        t0 = time.time()
        # run from repo root so experiments/ lands where mine_probes looks
        rc = subprocess.run(["timeout", str(secs)] + cmd, cwd=str(cfg.repo),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        print(f"  [{i+1}/{len(pairs)}] {title}  ({int(time.time()-t0)}s, rc={rc})", flush=True)
        return (a, b, rc)

    if args.dry_run:
        for ip in enumerate(pairs):
            launch(ip)
        return
    with ThreadPoolExecutor(max_workers=par) as ex:
        list(ex.map(launch, list(enumerate(pairs))))
    print(f"[campaigns] done. Objective traces under {cfg.repo}/experiments/*{put}*fpp*/objective/ ; "
          f"next: run_fingerprint.py --put {put} --stages mine,matrix,tree,validate,report", flush=True)


if __name__ == "__main__":
    main()
