#!/usr/bin/env python3
"""Stage 2 -- build the cross-apply signature matrix CLEANLY, under controlled load.

For every confirmed probe (rows) x every vendored version (cols) we record the version's stable
live-TCP response signature. The critical correctness property (see DEVELOPER.md) is that each
server is probed SEQUENTIALLY, one connection at a time: probing a server with many parallel
connections under heavy load truncates its flights and corrupts the cells -- the bug that once made
a tree mis-route 42/61 live servers (only ~6% of a heavy-load matrix reproduced on clean
re-probing). So we run at most `--jobs` servers in parallel, each probed sequentially, on a pinned
core list, retry UNSTABLE cells, and re-check any stragglers single-threaded at the end.

Input : reference/<put>/probes_full/reps.txt   (full confirmed-probe trace paths, from mine_probes)
Output: reference/<put>/signatures.csv         (rows=probe basename, cols=version, cell=sig key)
        reference/<put>/clusters.json          (wildcard compatibility clusters, for reference)

Signatures are stored truncated to the PUT's `sig_len` (OpenSSL: 10-char prefix; WolfSSL: full),
so a tree built from this matrix matches what the live prober produces (after the same truncation).
"""
import argparse
import csv
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

import probe
import puts
from probe import MISSING, SRVFAIL, UNSTABLE


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap)
    puts.add_common_args(ap)
    ap.add_argument("--retry", type=int, default=3, help="re-probe an UNSTABLE cell this many times")
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)
    sig_len = puts.PUTS[put]["sig_len"]
    cfg.prober(put)  # fail fast if the binary is missing

    reps_file = cfg.reps_file(put)
    if not reps_file.exists():
        raise SystemExit(f"no probe list at {reps_file}; run mine_probes.py --put {put} first "
                         f"(or point --reference-dir at an existing reference tree)")
    reps = [t for t in reps_file.read_text().split() if t]
    versions = cfg.versions(put)
    print(f"[build_matrix] PUT={put}  probes={len(reps)}  versions={len(versions)}  "
          f"servers in parallel={cfg.jobs} (each probed SEQUENTIALLY)  cores={cfg.cores or 'unpinned'}",
          flush=True)

    matrix, flagged, done, t0 = {}, {}, [0], time.time()

    def do_version(args_):
        """Probe ALL reps against one server, sequentially. Returns (ver, column, unstable_idxs)."""
        vi, v = args_
        port = cfg.base_port + vi
        srv = probe.launch(cfg, put, v, port)
        if not probe.wait_listen(port):
            srv.terminate()
            return v, [SRVFAIL] * len(reps), list(range(len(reps)))
        col, uns = [], []
        for pi, t in enumerate(reps):
            s = probe.sigkey(probe.stable_sig(cfg, t, port, retry=args.retry), sig_len)
            col.append(s)
            if s == UNSTABLE:
                uns.append(pi)
        srv.terminate()
        return v, col, uns

    with ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        for v, col, uns in ex.map(do_version, list(enumerate(versions))):
            matrix[v], flagged[v] = col, uns
            done[0] += 1
            print(f"  [{done[0]:2d}/{len(versions)}] {puts.dotted(put, v):7s} "
                  f"{len(uns):3d} UNSTABLE  ({int(time.time() - t0)}s)", flush=True)

    # Re-check any still-UNSTABLE cells single-threaded (ultra-light load) -- last line of defence.
    tot = sum(len(u) for u in flagged.values())
    print(f"[build_matrix] re-checking {tot} flagged-UNSTABLE cells single-threaded...", flush=True)
    for vi, v in enumerate(versions):
        if not flagged[v]:
            continue
        port = cfg.base_port + 1000 + vi
        srv = probe.launch(cfg, put, v, port)
        if probe.wait_listen(port):
            for pi in flagged[v]:
                s = probe.sigkey(probe.stable_sig(cfg, reps[pi], port, retry=args.retry), sig_len)
                if s not in MISSING:
                    matrix[v][pi] = s
        srv.terminate()
    still = sum(1 for v in versions for c in matrix[v] if c in MISSING)
    print(f"[build_matrix] still UNSTABLE after re-check: {still}/{len(reps) * len(versions)} cells",
          flush=True)

    # Write the matrix (rows = probe basename, cols = version).
    out = cfg.ref(put)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "signatures.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["trace"] + versions)
        for pi, t in enumerate(reps):
            w.writerow([os.path.basename(t)] + [matrix[v][pi] for v in versions])

    # Wildcard compatibility clusters (reference only; the real classifier is the tree).
    def compat(u, v):
        for x, y in zip(matrix[u], matrix[v]):
            if x in MISSING or y in MISSING:
                continue          # missing == no information, never forces a split
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
    json.dump({"clusters": [{"id": i, "versions": sorted(c, key=lambda x: puts.vkey(put, x))}
                            for i, c in enumerate(clusters)]},
              open(out / "clusters.json", "w"), indent=2)
    print(f"[build_matrix] wrote {out}/signatures.csv + clusters.json ; "
          f"wildcard clusters={len(clusters)} ; took {int(time.time() - t0)}s", flush=True)


if __name__ == "__main__":
    main()
