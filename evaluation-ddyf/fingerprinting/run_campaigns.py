#!/usr/bin/env python3
"""Stage 0 -- launch the differential-fuzzing campaigns that PRODUCE the objective traces.

For each adjacent version pair of a PUT this runs one DDYF differential campaign
(`tlspuffin ... differential-experiment <verA> <verB> -t fpp-<dotA>-<dotB>`), which writes the
objective traces (client-driven traces on which the two versions diverged) under `experiments/`.
`mine_probes.py` then distils those into the confirmed probe set, closing the loop so the whole
pipeline -- campaigns -> mine -> matrix -> tree -> validate -> report -- is reproducible end to end.

Two binary modes:
  * default: one shared `tlspuffin` (built with ALL PUTs, `--features cputs`) runs every pair.
  * `--per-pair-binary`: build a SEPARATE binary per pair that links ONLY those two PUTs (a small,
    focused edge map -- the proven mechanism). For each pair it symlinks the two vendored versions
    into a temp VENDOR_DIR, touches build.rs, rebuilds (non-ASAN), and copies to /tmp/bin_<A>_<B>.

`--client-attacker-only` passes the binary's `--fingerprinting` flag so the corpus keeps only client-attacker
seeds (drops the MITM/full-handshake and server-attacker seeds -- see tls/seeds.rs::create_corpus).

Examples:
    # one binary, all pairs
    python3 run_campaigns.py --put openssl --timeout 1h --jobs 20 --cores 0-19
    # per-pair 2-PUT binaries, client-attacker only, 12h each
    python3 run_campaigns.py --put wolfssl --per-pair-binary --client-attacker-only \
        --timeout 12h --cores 0-24
"""
import argparse
import os
import shutil
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


def expand_cores(spec):
    """Expand a taskset-style core spec into a list of single cores, e.g.
    '0-24' -> ['0',...,'24'];  '0,2,4' -> ['0','2','4'];  '0-3,16-19' -> ['0'..'3','16'..'19']."""
    out = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-")
            out += list(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    return [str(c) for c in out]


def build_pair_binary(cfg, a, b, target_dir, edges, build_cores, log):
    """Build a tlspuffin binary linking ONLY PUTs `a` and `b` (non-ASAN). Returns the path to the
    copied binary (/tmp/bin_<a>_<b>) or None on failure. Symlinks the two vendored versions into a
    temp VENDOR_DIR and touches build.rs so the PUT build.rs re-links just these two."""
    vd = f"/tmp/vendor_{a}_{b}"
    shutil.rmtree(vd, ignore_errors=True)
    os.makedirs(vd)
    os.symlink(str(cfg.vendor / a), os.path.join(vd, a))
    os.symlink(str(cfg.vendor / b), os.path.join(vd, b))
    subprocess.run(["touch", str(cfg.repo / "tlspuffin" / "build.rs")])
    env = dict(os.environ, CARGO_TARGET_DIR=target_dir, VENDOR_DIR=vd,
               LIBAFL_EDGES_MAP_DEFAULT_SIZE=str(edges), LIBAFL_EDGES_MAP_SIZE=str(edges),
               LIBAFL_EDGES_MAP_ALLOCATED_SIZE=str(edges))
    cmd = ["cargo", "build", "--release", "--bin", "tlspuffin", "--features", "cputs"]
    if build_cores:
        cmd = ["taskset", "-c", build_cores] + cmd
    with open(log, "ab") as lf:
        lf.write(f"\n==== build {a}+{b} ====\n".encode())
        subprocess.run(cmd, cwd=str(cfg.repo), env=env, stdout=lf, stderr=lf)
    out = os.path.join(target_dir, "release", "tlspuffin")
    dst = f"/tmp/bin_{a}_{b}"
    ok = os.path.exists(out) and os.path.getsize(out) > 40_000_000   # a real 2-PUT build is ~90MB+
    if ok:
        shutil.copy2(out, dst)
    shutil.rmtree(vd, ignore_errors=True)
    return dst if ok else None


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
    ap.add_argument("--per-pair-binary", action="store_true",
                    help="build a separate binary per pair linking ONLY those 2 PUTs (focused edge map)")
    ap.add_argument("--client-attacker-only", action="store_true",
                    help="pass the binary's --fingerprinting flag (client-attacker-only corpus, "
                         "no PUT-config uniformisation, wire-observable objectives)")
    ap.add_argument("--edges", type=int, default=8388608,
                    help="LibAFL edge-map size for per-pair binaries (default 8388608)")
    ap.add_argument("--target-dir", default="/tmp/fp_campaign_target",
                    help="isolated cargo target dir for per-pair builds (avoids other builds' target/)")
    ap.add_argument("--dry-run", action="store_true", help="print the campaign commands and exit")
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)

    versions = cfg.versions(put)
    pairs = list(zip(versions, versions[1:]))     # adjacent pairs in version order
    secs = parse_duration(args.campaign_timeout)
    cores = expand_cores(cfg.cores)
    par = args.parallel or (len(cores) if cores else 8)
    camp_env = dict(os.environ)
    # --client-attacker-only now maps to the single `--fingerprinting` binary flag (added to `cmd`
    # below). It drives the whole fingerprinting mode: client-attacker-only corpus, no PUT-config
    # uniformisation, and wire-observable differential objectives. (Superseded the former
    # FP_CLIENT_ATTACKER_ONLY env var, which create_corpus no longer reads.)
    fp_flag = ["--fingerprinting"] if args.client_attacker_only else []

    print(f"[campaigns] PUT={put}  pairs={len(pairs)}  timeout={secs}s/pair  parallel={par}  "
          f"per_pair_binary={args.per_pair_binary}  client_attacker_only={args.client_attacker_only}  "
          f"out={cfg.repo}/experiments/", flush=True)

    # ---- phase 1: pick/build the binary for each pair ----
    pair_bin = {}
    if args.per_pair_binary:
        if not args.dry_run:
            bcores = cfg.cores or ""
            for i, (a, b) in enumerate(pairs):
                t0 = time.time()
                bp = build_pair_binary(cfg, a, b, args.target_dir, args.edges, bcores, "/tmp/fp_build.log")
                pair_bin[(a, b)] = bp
                print(f"  [build {i+1}/{len(pairs)}] {a}+{b} -> {bp or 'FAILED (see /tmp/fp_build.log)'} "
                      f"({int(time.time()-t0)}s)", flush=True)
    else:
        shared = cfg.prober(put)
        for p in pairs:
            pair_bin[p] = shared

    # ---- phase 2: launch the campaigns ----
    def launch(idx_pair):
        i, (a, b) = idx_pair
        binary = pair_bin.get((a, b))
        title = f"fpp-{puts.dotted(put, a)}-{puts.dotted(put, b)}"
        port = cfg.base_port + (i % 1000)
        core = cores[i % len(cores)] if cores else None
        cmd = [binary, "-p", str(port), "--cores", (core or args.fuzz_cores)] + fp_flag + [
               "differential-experiment", a, b, "-t", title]
        if core:
            cmd = ["taskset", "-c", core] + cmd
        if args.dry_run:
            print("  " + (binary or "<no-binary>")
                  + " %s differential-experiment %s %s -t %s" % (" ".join(fp_flag), a, b, title))
            return (a, b, 0)
        if not binary:
            print(f"  [{i+1}/{len(pairs)}] {title}  SKIP (no binary)", flush=True)
            return (a, b, -1)
        t0 = time.time()
        rc = subprocess.run(["timeout", str(secs)] + cmd, cwd=str(cfg.repo), env=camp_env,
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
