#!/usr/bin/env python3
"""
Build a *live-TCP* signature matrix the right way (the "harder setting").

For every version we start its own real `vendor/<ver>/bin/openssl s_server` on a
localhost port and replay every candidate trace over a real socket with
`tlspuffin tcp`. Each cell is captured K times and reduced with the SAME rule the
prober uses (fingerprint_probe.node_signature): take the most-complete capture
(max executed_until), and among those the modal signature. This cancels both the
500 ms read-timeout truncation race and the genuine same-depth response jitter
that a thin 3-run majority could not (which is what contaminated the old matrix).

Server + client are pinned to dedicated cores so a busy host cannot starve the
read window. Output mirrors signatures.py: signatures_tcp.csv + clusters_tcp.json.

Usage:
  python3 build_live_matrix.py --manifest candidates_ossl_disp/manifest.csv \
      --out candidates_ossl_live2 --binary /tmp/tlspuffin_fast \
      --repeat 15 --jobs 6 --first-core 0 --cpus-per-job 4
"""
import argparse, csv, io, json, os, socket, subprocess, sys, threading, time, contextlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
VENDOR = _REPO / "vendor"
LAB = _HERE / "lab_validation"
sys.path.append(str(_HERE))
from _canon import canonicalize_execution

EMPTY_SIG = __import__("hashlib").sha256(b"").hexdigest()


def wait_listen(port, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close(); return True
        except OSError:
            time.sleep(0.1)
    return False


def server_argv(server_cmd, version, port):
    """(argv, env, cwd) to launch a real server of `version` on `port`.
    Both stacks are driven by their stock example server; the fingerprint never
    looks at cert/cipher config, so the default/throw-away cert is fine.
    The vendored-servers root honors VENDOR_DIR (set by puts.Config from --vendor-dir)
    at call time, so it is never a hardcoded absolute."""
    vendor = Path(os.environ.get("VENDOR_DIR") or VENDOR)
    if server_cmd == "openssl":
        # vendored bin/openssl is a normal non-ASAN build; OPENSSL_CONF=/dev/null
        # because it cannot find its openssl.cnf at the build prefix.
        binp = vendor / version / "bin" / "openssl"
        argv = [str(binp), "s_server", "-accept", str(port),
                "-cert", str(LAB / "server.crt"), "-key", str(LAB / "server.key"), "-quiet"]
        return argv, dict(os.environ, OPENSSL_CONF="/dev/null"), None
    if server_cmd == "wolfssl":
        # wolfssl example server (built by build_wolfssl_servers.sh): -i loops to
        # accept many connections, -d disables client-cert check, -b binds any iface.
        # Run from the wolfssl source root so ChangeToWolfRoot() finds certs/.
        binp = vendor / version / "bin" / "server"
        cwd = vendor / version / "src" / "vendor"
        # -x: keep running (print) on SSL errors instead of exiting on the first
        # malformed probe; -i loop; -d no client-cert; -b bind any iface.
        argv = [str(binp), "-p", str(port), "-x", "-d", "-i", "-b"]
        return argv, dict(os.environ), str(cwd)
    raise ValueError(f"unknown --server-cmd {server_cmd}")


def port_free(port):
    """True iff nothing is already listening (guards against an orphaned s_server
    from a previous run squatting our port and serving the wrong version)."""
    try:
        socket.create_connection(("127.0.0.1", port), 0.3).close()
        return False
    except OSError:
        return True


def canon(data):
    with contextlib.redirect_stdout(io.StringIO()):
        return canonicalize_execution(data, tcp_mode=True, live_mode=True)


def cell_sig(binary, trace, port, cpus, repeat, timeout):
    """Most-complete + modal signature across `repeat` probes."""
    caps = []
    best = -1
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
            data = json.loads(r.stdout[i:])
        except json.JSONDecodeError:
            continue
        depth = (data.get("execution") or {}).get("executed_until", 0) or 0
        caps.append((depth, canon(data)))
        best = max(best, depth)
    if not caps:
        return EMPTY_SIG
    at_best = Counter(s for d, s in caps if d == best)
    return at_best.most_common(1)[0][0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--versions-from", type=Path,
                    default=_HERE / "model_openssl3x_live" / "meta.json",
                    help="meta.json whose clusters define the full version set to test")
    ap.add_argument("--binary", default=os.environ.get("PUFFIN_BIN", "/tmp/tlspuffin_o3x"))
    ap.add_argument("--repeat", type=int, default=15)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--first-core", type=int, default=0)
    ap.add_argument("--cpus-per-job", type=int, default=4)
    ap.add_argument("--base-port", type=int, default=19000)
    ap.add_argument("--server-cmd", choices=["openssl", "wolfssl"], default="openssl",
                    help="which stack's stock server to launch per version")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.manifest)))
    traces = [r["trace"] for r in rows]
    meta = json.loads(args.versions_from.read_text())
    versions = sorted({v for c in meta["clusters"] for v in c})
    out = args.out if args.out.is_absolute() else _HERE / args.out
    out.mkdir(exist_ok=True)
    print(f"versions={len(versions)} traces={len(traces)} cells={len(versions)*len(traces)} "
          f"repeat={args.repeat} jobs={args.jobs}", flush=True)

    matrix = {v: {} for v in versions}
    done = [0]; lock = threading.Lock()

    def one(iv):
        i, v = iv
        slot = i % args.jobs
        lo = args.first_core + slot * args.cpus_per_job
        cpus = f"{lo}-{lo + args.cpus_per_job - 1}"
        # each version gets its own port; skip forward if anything is squatting it
        port = args.base_port + i
        for _ in range(200):
            if port_free(port):
                break
            port += len(versions)  # stay clear of other jobs' ports
        argv, env, cwd = server_argv(args.server_cmd, v, port)
        srv = subprocess.Popen((["taskset", "-c", cpus] if cpus else []) + argv,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=cwd)
        try:
            if not wait_listen(port):
                with lock:
                    print(f"  !! {v} server never listened", flush=True)
                return v, {t: EMPTY_SIG for t in traces}
            col = {}
            for t in traces:
                col[t] = cell_sig(args.binary, t, port, cpus, args.repeat, args.timeout)
        finally:
            srv.terminate()
            try: srv.wait(timeout=3)
            except subprocess.TimeoutExpired: srv.kill()
        with lock:
            done[0] += 1
            print(f"[{done[0]:2d}/{len(versions)}] {v} done", flush=True)
        return v, col

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for v, col in pool.map(one, list(enumerate(versions))):
            matrix[v] = col

    # write matrix
    sig_csv = out / "signatures_tcp.csv"
    with open(sig_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["trace"] + versions)
        for t in traces:
            w.writerow([t] + [matrix[v].get(t, EMPTY_SIG) for v in versions])
    # cluster: group versions with identical column vectors
    import hashlib
    groups = {}
    for v in versions:
        key = hashlib.sha1("|".join(matrix[v].get(t, EMPTY_SIG) for t in traces).encode()).hexdigest()
        groups.setdefault(key, []).append(v)
    clusters = sorted(groups.values(), key=lambda c: versions.index(c[0]))
    # clusters_tcp.json schema matches signatures.py / build_tree.py: [{id, versions}]
    (out / "clusters_tcp.json").write_text(json.dumps(
        {"clusters": [{"id": f"C{i}", "versions": c} for i, c in enumerate(clusters)]}, indent=2))
    empties = sum(1 for v in versions for t in traces if matrix[v].get(t) == EMPTY_SIG)
    print(f"\n=== live-TCP matrix: {len(versions)} versions -> {len(clusters)} clusters "
          f"({sum(1 for c in clusters if len(c)==1)} singletons); "
          f"EMPTY cells {empties}/{len(versions)*len(traces)} "
          f"({100*empties/(len(versions)*len(traces)):.1f}%) ===")
    print(f"wrote {sig_csv}")


if __name__ == "__main__":
    main()
