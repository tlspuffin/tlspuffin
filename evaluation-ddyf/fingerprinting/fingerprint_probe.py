#!/usr/bin/env python3
"""
Live TLS version fingerprinter (deterministic, AI-free).

Takes a model produced by build_tree.py (tree.json + meta.json + probes/), connects to a
live server over TCP, replays the tree's probe traces, canonicalises each response with the
SAME rules used offline, and walks the decision tree to a leaf.

Robust against real-world conditions: resolves DNS itself (the `tcp` PUT needs an IP, not a
hostname), distinguishes connection failures / no-response / divergent-stack / positive
instead of collapsing everything to "unknown", optionally re-probes to detect load-balanced
or flaky targets, and never confuses an operational failure with a true abstention.
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
try:
    from _canon import canonicalize_execution
except ImportError:
    print("ERROR: could not import _canon.py", file=sys.stderr)
    sys.exit(1)

EMPTY_SIG = hashlib.sha256(b"").hexdigest()  # signature of a response with nothing observable
_CONN_ERR_MARKERS = (
    "ip address", "connect", "refused", "reset", "unreachable", "timed out",
    "timeout", "no route", "broken pipe", "would block", "eof",
)


def resolve_host(host: str):
    """Resolve a hostname to an IP (prefer IPv4, fall back to IPv6). Returns (ip, family)."""
    infos = socket.getaddrinfo(host, None)
    for fam in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == fam:
                return info[4][0], ("ipv4" if fam == socket.AF_INET else "ipv6")
    return infos[0][4][0], "other"


def _canon_quiet(data: dict, tcp_mode: bool) -> str:
    """canonicalize_execution may emit stray debug prints; suppress them to keep stdout clean."""
    with open(os.devnull, "w") as devnull, redirect_stdout(devnull):
        return canonicalize_execution(data, tcp_mode=tcp_mode, live_mode=True)


def run_probe(binary: str, trace_path: Path, ip: str, port: int, sni: str | None,
              timeout: float, retries: int) -> dict:
    """
    Replay one probe against ip:port. Returns a dict with 'outcome' in:
      ok | connection_error | unreachable | binary_error | bad_output
    plus 'data' (parsed JSON) when ok, and 'error' (the in-band PUT error) when relevant.
    """
    cmd = [binary, "tcp", str(trace_path), "--host", ip, "--port", str(port), "--json"]
    if sni:
        cmd += ["--sni", sni]
    last = None
    for _ in range(max(1, retries)):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            last = "timeout"
            continue
        except FileNotFoundError:
            return {"outcome": "binary_error", "error": f"binary not found: {binary}"}
        idx = r.stdout.find("{")
        if idx == -1:
            last = "no_json (binary stderr: %s)" % (r.stderr.strip().splitlines()[-1:] or [""])[0]
            continue
        try:
            data = json.loads(r.stdout[idx:])
        except json.JSONDecodeError:
            last = "unparseable_json"
            continue
        err = data.get("error")
        if err and any(m in str(err).lower() for m in _CONN_ERR_MARKERS):
            return {"outcome": "connection_error", "error": err, "data": data}
        return {"outcome": "ok", "data": data, "error": err}
    return {"outcome": "unreachable", "error": last}


def _executed_until(data: dict) -> int:
    """How many trace steps the TCP engine managed to capture for this probe."""
    ex = data.get("execution") or {}
    return ex.get("executed_until", 0) or 0


def node_signature(binary, trace_path, ip, port, sni, timeout, retries, repeat, tcp_mode) -> dict:
    """
    Probe one tree node up to `repeat` times and return {'outcome': ..., 'sig': ...}:
      matched          -> a stable, non-empty signature (sig set)
      no_tls_response  -> connected but nothing observable (empty signature)
      inconsistent     -> signatures differed at the same capture depth (load-balanced)
      connection_error / unreachable / binary_error / bad_output -> operational failure

    Capture is over a real TCP socket whose read uses a fixed idle timeout
    (tlspuffin's `tcp` PUT), so a slow flight can be *truncated*: the engine
    records fewer steps (`executed_until`) than the server actually sent. This
    only ever drops trailing flights, never invents them, so across `repeat`
    probes the run with the largest `executed_until` is the complete response and
    reproduces the offline (display-execute) signature exactly. We therefore keep
    the most-complete capture rather than requiring every run to agree, and flag
    `inconsistent` only when two *different* signatures tie at that maximum depth.
    """
    from collections import Counter
    best_depth, captures, last_fail = -1, [], None
    for _ in range(max(1, repeat)):
        res = run_probe(binary, trace_path, ip, port, sni, timeout, retries)
        if res["outcome"] != "ok":
            last_fail = res  # a single failed attempt should not abort the node
            continue
        depth = _executed_until(res["data"])
        sig = _canon_quiet(res["data"], tcp_mode)
        captures.append((depth, sig))
        best_depth = max(best_depth, depth)
    if not captures:
        return last_fail  # every attempt failed operationally
    # Among the most-complete captures, take the modal signature. Live TCP has
    # genuine same-depth response jitter; majority-at-max-depth is the stable
    # value and matches how the offline matrix is built (same rule, build_live_matrix.py).
    at_best = Counter(sig for depth, sig in captures if depth == best_depth)
    ranked = at_best.most_common()
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return {"outcome": "inconsistent", "sigs": sorted(s[:12] for s in at_best),
                "depth": best_depth}
    sig = ranked[0][0]
    if sig == EMPTY_SIG:
        return {"outcome": "no_tls_response", "sig": sig}
    return {"outcome": "matched", "sig": sig}


def walk_tree(node, ctx, depth=0, path=None):
    path = path or []
    if node["type"] == "leaf":
        return {"status": "identified", "cluster": node["clusters"], "path": path}
    if ctx["delay"] > 0:
        time.sleep(ctx["delay"])
    trace = ctx["model"] / node["trace"]
    res = node_signature(ctx["binary"], trace, ctx["ip"], ctx["port"], ctx["sni"],
                         ctx["timeout"], ctx["retries"], ctx["repeat"], ctx["tcp_mode"])
    out = res["outcome"]
    if out == "matched":
        sig = res["sig"]
        if sig not in node["children"]:
            return {"status": "unknown_stack", "reason": "response did not match any model branch",
                    "unmatched_sig": sig, "probe": node["trace"], "depth_reached": depth, "path": path}
        return walk_tree(node["children"][sig], ctx, depth + 1, path + [node["trace"]])
    # operational / non-decisive outcomes — NOT a true abstention
    status = {
        "no_tls_response": "no_tls_response",
        "inconsistent": "inconsistent",
        "connection_error": "connection_error",
        "unreachable": "connection_error",
        "binary_error": "binary_error",
    }.get(out, "probe_failed")
    return {"status": status, "detail": res, "probe": node["trace"],
            "depth_reached": depth, "path": path}


def main():
    p = argparse.ArgumentParser(description="Live TLS version fingerprinter")
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--url", help="Target URL, e.g. https://example.com")
    p.add_argument("--host", help="Target hostname or IP")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--sni", help="SNI to inject (defaults to the hostname)")
    p.add_argument("--binary", default=os.environ.get("PUFFIN_BIN", "target/release/tlspuffin"),
                   help="Path to the tlspuffin binary (or set PUFFIN_BIN)")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-probe timeout (s)")
    p.add_argument("--retries", type=int, default=2, help="Retries per probe on timeout/parse fail")
    p.add_argument("--repeat", type=int, default=1, help="Re-probe each node N times to detect flaky/load-balanced targets")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between probes (s) to pace requests")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    def emit(d, code=0):
        if args.json:
            print(json.dumps(d, indent=2))
        else:
            print(f"{d['status'].upper()}: " + json.dumps({k: v for k, v in d.items() if k != 'status'}))
        sys.exit(code)

    # ---- startup checks --------------------------------------------------------------
    if not args.url and not args.host:
        emit({"status": "usage_error", "error": "provide --url or --host"}, 2)
    if not Path(args.binary).exists():
        emit({"status": "binary_error", "error": f"binary not found: {args.binary}"}, 2)
    tree_path, meta_path = args.model / "tree.json", args.model / "meta.json"
    if not tree_path.exists() or not meta_path.exists():
        emit({"status": "model_error", "error": f"{args.model} missing tree.json or meta.json"}, 2)

    host, port, sni = args.host, args.port, args.sni
    if args.url:
        from urllib.parse import urlparse
        u = urlparse(args.url if "//" in args.url else "//" + args.url)
        host = u.hostname or host
        port = u.port or (80 if u.scheme == "http" else 443)
        sni = sni or host
    if not sni and host and not host.replace(".", "").isdigit() and ":" not in host:
        sni = host

    # ---- resolve DNS ourselves (tcp PUT needs an IP) ---------------------------------
    is_ip = host.replace(".", "").isdigit() or ":" in host
    if is_ip:
        ip, fam = host, "literal"
    else:
        try:
            ip, fam = resolve_host(host)
        except Exception as e:
            emit({"status": "connection_error", "error": f"DNS resolution failed for {host}: {e}"}, 1)

    tree = json.loads(tree_path.read_text())
    tcp_mode = json.loads(meta_path.read_text()).get("canon") == "tcp_mode"

    ctx = {"model": args.model, "binary": args.binary, "ip": ip, "port": port, "sni": sni,
           "timeout": args.timeout, "retries": args.retries, "repeat": args.repeat,
           "delay": args.delay, "tcp_mode": tcp_mode}
    result = walk_tree(tree, ctx)
    result.update({"target": host, "resolved_ip": ip, "ip_family": fam, "sni": sni, "port": port})

    code = 0 if result["status"] == "identified" else 1
    emit(result, code)


if __name__ == "__main__":
    main()
