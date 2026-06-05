#!/usr/bin/env python3
"""
Remote-but-lab validation of the version-fingerprinting decision tree.

For every version in the model we stand up a *real* TLS server of that exact
version --- the vendored `openssl s_server` built at vendor/<version>/bin/openssl
--- on a localhost TCP port, run the deterministic prober (fingerprint_probe.py)
against it over a real socket, and check that the recovered leaf cluster contains
the ground-truth version. This measures end-to-end live accuracy under controlled
conditions (we own the server, so the version is known) without touching the wild.

The prober keeps the most-complete capture across --repeat probes, which cancels
the tcp read-timeout truncation race (see fingerprint_probe.node_signature).

Usage:
  python3 lab_validate.py --model model_openssl3x_live --repeat 8 [--only openssl362,...]
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent  # .../DDYF-fingerprinting
VENDOR = _REPO / "vendor"
LAB = _HERE / "lab_validation"
PUFFIN = os.environ.get("PUFFIN_BIN", "/tmp/tlspuffin_o3x")


def cluster_of(meta: dict, version: str):
    for c in meta["clusters"]:
        if version in c:
            return c
    return None


def wait_listen(port: int, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.3)
            try:
                s.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.1)
    return False


def _pin(cpus: str | None):
    # On a busy shared host, pin server+client to dedicated cores so the tcp
    # read window is not starved (otherwise a slow flight is truncated, see
    # fingerprint_probe.node_signature). Children inherit the affinity.
    return ["taskset", "-c", cpus] if cpus else []


def start_server(version: str, port: int, cpus: str | None = None, server_cmd: str = "openssl"):
    # reuse the exact same server launch as the matrix builder (one definition)
    from build_live_matrix import server_argv
    argv, env, cwd = server_argv(server_cmd, version, port)
    if not Path(argv[0]).exists():
        return None, f"no vendored {server_cmd} server for {version} ({argv[0]})"
    proc = subprocess.Popen(
        _pin(cpus) + argv,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=cwd,
    )
    if not wait_listen(port):
        proc.terminate()
        return None, f"server for {version} never listened on {port}"
    return proc, None


def probe(model: Path, port: int, repeat: int, timeout: float, cpus: str | None = None):
    cmd = _pin(cpus) + [sys.executable, str(_HERE / "fingerprint_probe.py"),
           "--model", str(model), "--host", "127.0.0.1", "--port", str(port),
           "--binary", PUFFIN, "--repeat", str(repeat), "--timeout", str(timeout), "--json"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"status": "probe_crash", "stderr": r.stderr[-300:]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, type=Path)
    ap.add_argument("--repeat", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--base-port", type=int, default=15000)
    ap.add_argument("--jobs", type=int, default=8, help="versions to validate concurrently")
    ap.add_argument("--first-core", type=int, default=8, help="lowest CPU core to pin jobs to")
    ap.add_argument("--cpus-per-job", type=int, default=4, help="cores pinned per concurrent job")
    ap.add_argument("--only", help="comma-separated subset of versions")
    ap.add_argument("--server-cmd", choices=["openssl", "wolfssl"], default="openssl",
                    help="which stack's stock server to launch per version")
    ap.add_argument("--out", type=Path, help="write JSON results here")
    args = ap.parse_args()

    model = args.model if args.model.is_absolute() else _HERE / args.model
    meta = json.loads((model / "meta.json").read_text())
    versions = sorted({v for c in meta["clusters"] for v in c})
    if args.only:
        want = set(args.only.split(","))
        versions = [v for v in versions if v in want]

    total = len(versions)
    done = [0]
    lock = threading.Lock()

    def cpus_for(i):
        slot = i % args.jobs
        lo = args.first_core + slot * args.cpus_per_job
        return f"{lo}-{lo + args.cpus_per_job - 1}"

    def one(idx_v):
        i, v = idx_v
        port = args.base_port + i
        cpus = cpus_for(i)
        srv, err = start_server(v, port, cpus, args.server_cmd)
        if err:
            res = {"status": "server_error", "detail": err}
        else:
            try:
                res = probe(model, port, args.repeat, args.timeout, cpus)
            finally:
                srv.terminate()
                try:
                    srv.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    srv.kill()
        truth = cluster_of(meta, v)
        got = res.get("cluster")
        # leaf "clusters" may be nested (list of cluster-lists); flatten before membership test
        flat = []
        for x in (got or []):
            flat += x if isinstance(x, list) else [x]
        correct = res.get("status") == "identified" and v in flat
        rec = {"version": v, "status": res.get("status"), "got_cluster": got,
               "truth_cluster": truth, "correct": correct,
               "detail": {k: res.get(k) for k in ("unmatched_sig", "probe", "sigs", "depth_reached")}}
        with lock:
            done[0] += 1
            flag = "OK " if correct else "XX "
            print(f"[{done[0]:2d}/{total}] {v:12s} {flag} status={str(res.get('status')):14s} got={got}",
                  flush=True)
        return rec

    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for rec in pool.map(one, list(enumerate(versions))):
            results.append(rec)

    n_ok = sum(r["correct"] for r in results)
    n_bad = total - n_ok
    print(f"\n=== {model.name}: {n_ok}/{total} correctly identified "
          f"({100*n_ok/total:.1f}%), {n_bad} wrong ===")
    if args.out:
        args.out.write_text(json.dumps({"model": model.name, "correct": n_ok, "total": total,
                                        "results": results}, indent=2))
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
