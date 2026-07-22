#!/usr/bin/env python3
"""Audit -- quantify attacker-side NON-reproducibility in a committed probe set.

Some probe traces are not self-consistent: replaying the same trace against the same server yields a
different signature run-to-run. The dominant cause is ATTACKER-SIDE term-evaluation nondeterminism
-- ring's P-curve crypto (computing DY terms like fn_ecdsa_sign_server / fn_decode_server_ecdh_pubkey)
blinds with system entropy regardless of tlspuffin's FixedByteRandom, so the same probe sometimes
builds a ClientHello and sometimes errors out (-> EMPTY). Because that flip is version-INDEPENDENT,
one reference server is enough to detect it.

For each probe in reference/<put>/probes_full/reps.txt, this replays it K times (probe.self_consistent)
against ONE vendored server and reports how many flip. These are exactly the probes the strengthened
mine_probes A2 (--consistency-k) now rejects.

Usage: check_consistency.py --put wolfssl [--ref-version wolfssl540] [--consistency-k 3]
"""
import argparse
import time
from concurrent.futures import ThreadPoolExecutor

import probe
import puts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap)
    puts.add_common_args(ap)
    ap.add_argument("--ref-version", action="append",
                    help="vendored version(s) to probe against; repeatable. A probe must be "
                         "self-consistent on ALL of them to survive (cuts the ~25%% single-server "
                         "lucky-pass of a 50/50 flipper). Default: low/mid/high spread.")
    ap.add_argument("--consistency-k", type=int, default=3, help="independent pooled measurements (default 3)")
    ap.add_argument("--list", action="store_true", help="print each flaky probe basename")
    ap.add_argument("--write-reps", help="write the SURVIVING (self-consistent) basenames to this file")
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)
    cfg.prober(put)

    import os
    reps = cfg.read_reps(put)
    versions = cfg.versions(put)
    if args.ref_version:
        refs = args.ref_version
    else:
        refs = sorted({versions[0], versions[len(versions) // 2], versions[-1]}, key=lambda v: puts.vkey(put, v))
    bad = [r for r in refs if r not in versions]
    if bad:
        raise SystemExit(f"--ref-version {bad} not vendored; have {versions}")
    print(f"[check] PUT={put}  probes={len(reps)}  ref-servers={[puts.dotted(put, r) for r in refs]}  "
          f"K={args.consistency_k}  pool={cfg.n_pool}/{cfg.dom} timeout={cfg.timeout}", flush=True)

    t0 = time.time()
    # Staged screen: full set on ref #1; only survivors re-checked on each further ref. A probe is
    # kept iff it is self-consistent (all K pooled sigs agree, incl. EMPTY) on EVERY ref server.
    #
    # CRITICAL (controlled load, see build_matrix/DEVELOPER.md): the stock example server is
    # single-connection. Probing ONE server with many parallel threads truncates its flights and
    # makes even stable probes look flaky -- the heavy-load corruption bug. So we parallelise the
    # build_matrix way: launch `jobs` INSTANCES of the ref version on distinct ports, give each
    # worker its OWN server, and have each worker probe ITS server SEQUENTIALLY. Per-server
    # concurrency stays 1; the measurement is faithful.
    W = max(1, cfg.jobs)

    def screen_on(ref, cand):
        ports = [cfg.base_port + i for i in range(W)]
        servers = [probe.launch(cfg, put, ref, p) for p in ports]
        up = [probe.wait_listen(p) for p in ports]
        if not any(up):
            probe.kill(*servers)
            raise SystemExit(f"ref server {ref} did not come up on any of {ports}")
        live = [p for p, u in zip(ports, up) if u]
        chunks = [cand[i::len(live)] for i in range(len(live))]   # round-robin split across servers

        def worker(arg):
            port, probes_here = arg
            kept_here = []
            for t in probes_here:                                  # SEQUENTIAL on this server
                if probe.self_consistent(cfg, t, port, k=args.consistency_k) is not None:
                    kept_here.append(t)
            return kept_here

        kept = []
        with ThreadPoolExecutor(max_workers=len(live)) as ex:
            for part in ex.map(worker, zip(live, chunks)):
                kept.extend(part)
        probe.kill(*servers)
        return kept

    survivors = list(reps)
    for ref in refs:
        kept = screen_on(ref, survivors)
        print(f"  [{puts.dotted(put, ref)}] survivors {len(kept)}/{len(survivors)} "
              f"({int(time.time()-t0)}s)", flush=True)
        survivors = kept

    flaky = [t for t in reps if t not in set(survivors)]
    print(f"\n[check] === {len(flaky)}/{len(reps)} probes NON-self-consistent across "
          f"{len(refs)} server(s); {len(survivors)}/{len(reps)} survive (k={args.consistency_k}) "
          f"({int(time.time()-t0)}s) ===")
    if args.list:
        for t in flaky:
            print("  flaky " + os.path.basename(t))
    if args.write_reps:
        with open(args.write_reps, "w") as f:
            f.write("\n".join(os.path.basename(t) for t in survivors) + "\n")
        print(f"[check] wrote {len(survivors)} surviving probe names -> {args.write_reps}", flush=True)


if __name__ == "__main__":
    main()
