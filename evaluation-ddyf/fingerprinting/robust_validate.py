#!/usr/bin/env python3
"""
End-to-end live validation by *nearest-cluster matching* (robust).

For every version we start its real server, re-probe ALL candidate traces over
TCP (same most-complete+majority capture as build_live_matrix), and assign the
version to the matrix cluster whose signature vector is closest (Hamming). Unlike
a decision-tree walk -- whose few maximally-discriminating probes are exactly the
ones that jitter most over the wire -- nearest-cluster matching tolerates a few
per-connection flips, so it measures whether the *clustering* reproduces live.

Usage:
  PUFFIN_BIN=/tmp/tlspuffin_fast200 python3 robust_validate.py \
      --candidates candidates_ossl_live2 --server-cmd openssl \
      --repeat 5 --jobs 12 --first-core 0 --cpus-per-job 2 --base-port 24000
"""
import argparse, csv, io, json, os, socket, subprocess, sys, threading, time, contextlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
from _canon import canonicalize_execution
from build_live_matrix import server_argv, wait_listen, port_free, VENDOR

EMPTY = __import__("hashlib").sha256(b"").hexdigest()


def cell_sig(binary, trace, port, cpus, repeat, timeout):
    caps, best = [], -1
    for _ in range(repeat):
        cmd = (["taskset", "-c", cpus] if cpus else []) + \
              [binary, "tcp", trace, "--host", "127.0.0.1", "--port", str(port), "--json"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            continue
        i = r.stdout.find("{")
        if i < 0:
            continue
        try:
            d = json.loads(r.stdout[i:])
        except json.JSONDecodeError:
            continue
        depth = (d.get("execution") or {}).get("executed_until", 0) or 0
        with contextlib.redirect_stdout(io.StringIO()):
            s = canonicalize_execution(d, tcp_mode=True, live_mode=True)
        caps.append((depth, s)); best = max(best, depth)
    if not caps:
        return EMPTY
    return Counter(s for de, s in caps if de == best).most_common(1)[0][0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True, type=Path, help="dir with signatures_tcp.csv + clusters_tcp.json")
    ap.add_argument("--server-cmd", choices=["openssl", "wolfssl"], default="openssl")
    ap.add_argument("--binary", default=os.environ.get("PUFFIN_BIN", "/tmp/tlspuffin_fast200"))
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--first-core", type=int, default=0)
    ap.add_argument("--cpus-per-job", type=int, default=2)
    ap.add_argument("--base-port", type=int, default=24000)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    cdir = args.candidates if args.candidates.is_absolute() else _HERE / args.candidates
    rows = list(csv.reader(open(cdir / "signatures_tcp.csv")))
    hdr = rows[0]; versions = hdr[1:]; data = rows[1:]
    traces = [r[0] for r in data]
    matrix = {v: [r[i + 1] for r in data] for i, v in enumerate(versions)}
    clusters = [c["versions"] for c in json.loads((cdir / "clusters_tcp.json").read_text())["clusters"]]
    cluster_of = {v: ci for ci, c in enumerate(clusters) for v in c}
    # one representative signature vector per cluster (all members are identical in the matrix)
    rep_vec = [matrix[c[0]] for c in clusters]

    total = len(versions); done = [0]; lock = threading.Lock()

    def nearest(vec):
        best_ci, best_d = None, 10 ** 9
        ties = 0
        for ci, rv in enumerate(rep_vec):
            d = sum(1 for a, b in zip(vec, rv) if a != b)
            if d < best_d:
                best_d, best_ci, ties = d, ci, 1
            elif d == best_d:
                ties += 1
        return best_ci, best_d, ties

    def one(iv):
        i, v = iv
        slot = i % args.jobs
        lo = args.first_core + slot * args.cpus_per_job
        cpus = f"{lo}-{lo + args.cpus_per_job - 1}"
        port = args.base_port + i
        for _ in range(200):
            if port_free(port):
                break
            port += total
        argv, env, cwd = server_argv(args.server_cmd, v, port)
        srv = subprocess.Popen((["taskset", "-c", cpus] if cpus else []) + argv,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=cwd)
        try:
            if not wait_listen(port):
                rec = {"version": v, "status": "server_error"}
            else:
                vec = [cell_sig(args.binary, t, port, cpus, args.repeat, args.timeout) for t in traces]
                ci, d, ties = nearest(vec)
                correct = (ci == cluster_of[v]) and ties == 1
                rec = {"version": v, "nearest_cluster": clusters[ci], "hamming": d,
                       "ties": ties, "correct": correct,
                       "own_cluster_dist": sum(1 for a, b in zip(vec, rep_vec[cluster_of[v]]) if a != b)}
        finally:
            srv.terminate()
            try: srv.wait(timeout=3)
            except subprocess.TimeoutExpired: srv.kill()
        with lock:
            done[0] += 1
            flag = "OK " if rec.get("correct") else "XX "
            print(f"[{done[0]:2d}/{total}] {v:12s} {flag} dist={rec.get('hamming')} ties={rec.get('ties')}", flush=True)
        return rec

    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for rec in pool.map(one, list(enumerate(versions))):
            results.append(rec)
    nok = sum(1 for r in results if r.get("correct"))
    print(f"\n=== nearest-cluster live validation: {nok}/{total} correct "
          f"({100*nok/total:.1f}%) over {len(traces)} traces, repeat={args.repeat} ===")
    if args.out:
        args.out.write_text(json.dumps({"correct": nok, "total": total, "results": results}, indent=2))


if __name__ == "__main__":
    main()
