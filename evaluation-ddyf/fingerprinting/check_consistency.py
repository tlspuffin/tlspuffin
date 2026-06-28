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
    ap.add_argument("--ref-version", help="vendored version to probe against (default: a mid version)")
    ap.add_argument("--consistency-k", type=int, default=3, help="independent pooled measurements (default 3)")
    ap.add_argument("--list", action="store_true", help="print each flaky probe basename")
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)
    cfg.prober(put)
    sig_len = puts.PUTS[put]["sig_len"]

    reps = cfg.read_reps(put)
    versions = cfg.versions(put)
    ref = args.ref_version or versions[len(versions) // 2]
    if ref not in versions:
        raise SystemExit(f"--ref-version {ref} not vendored; have {versions}")
    print(f"[check] PUT={put}  probes={len(reps)}  ref-server={puts.dotted(put, ref)}  "
          f"K={args.consistency_k}  pool={cfg.n_pool}/{cfg.dom} timeout={cfg.timeout}", flush=True)

    port = cfg.base_port
    srv = probe.launch(cfg, put, ref, port)
    if not probe.wait_listen(port):
        probe.kill(srv)
        raise SystemExit(f"ref server {ref} did not come up")

    flaky, t0 = [], time.time()

    def check(t):
        s = probe.self_consistent(cfg, t, port, k=args.consistency_k)
        return (t, s)   # s is None iff it flipped (or never stabilised)

    with ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        for n, (t, s) in enumerate(ex.map(check, reps), 1):
            if s is None:
                flaky.append(t)
            if n % 100 == 0:
                print(f"  checked {n}/{len(reps)}  flaky={len(flaky)}  ({int(time.time()-t0)}s)", flush=True)
    probe.kill(srv)

    import os
    print(f"\n[check] === {len(flaky)}/{len(reps)} probes are NON-self-consistent on "
          f"{puts.dotted(put, ref)} (would be rejected by mine A2 k={args.consistency_k}) "
          f"({int(time.time()-t0)}s) ===")
    if args.list:
        for t in flaky:
            print("  " + os.path.basename(t))


if __name__ == "__main__":
    main()
