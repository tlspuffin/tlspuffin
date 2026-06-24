#!/usr/bin/env python3
"""Live TLS version fingerprinter (deterministic, AI-free).

Connects to a live server over TCP, replays a decision tree's probe traces, canonicalises each
response with the SAME rules used offline, and walks the tree to a leaf -> a version cluster.

Two modes:
  * `--put openssl wolfssl ...`  identify an UNKNOWN target: walk EACH PUT's committed model
    (reference/<put>/) and report which library *and* which version-cluster, or abstain. A model
    only "claims" the target if every decision probe's live response matched a real branch (no
    forced default, no missing response); the wrong library's tree thus abstains instead of
    forcing a bogus leaf.
  * `--model DIR`                walk a single explicit model (legacy/standalone).

Robust against real-world conditions: resolves DNS itself (the `tcp` PUT needs an IP), distinguishes
connection failures / no-response / divergent-stack / positive instead of collapsing everything to
"unknown", optionally re-probes to detect load-balanced or flaky targets, and never confuses an
operational failure with a true abstention.
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
try:
    from _canon import canonicalize_execution
except ImportError:
    print("ERROR: could not import _canon.py", file=sys.stderr)
    sys.exit(1)
import puts  # noqa: E402

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


def run_probe(binary, trace_path, ip, port, sni, timeout, retries) -> dict:
    """Replay one probe against ip:port. Returns {'outcome': ok|connection_error|unreachable|
    binary_error}, plus 'data' (parsed JSON) when ok."""
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
    ex = data.get("execution") or {}
    return ex.get("executed_until", 0) or 0


def node_signature(binary, trace_path, ip, port, sni, timeout, retries, repeat, tcp_mode) -> dict:
    """Probe one node up to `repeat` times. Returns {'outcome': matched|no_tls_response|
    inconsistent|...}. Keeps the most-complete capture (max executed_until), then the modal sig
    among those, matching how the offline matrix is built (truncation only drops trailing flights)."""
    best_depth, captures, last_fail = -1, [], None
    for _ in range(max(1, repeat)):
        res = run_probe(binary, trace_path, ip, port, sni, timeout, retries)
        if res["outcome"] != "ok":
            last_fail = res
            continue
        depth = _executed_until(res["data"])
        captures.append((depth, _canon_quiet(res["data"], tcp_mode)))
        best_depth = max(best_depth, depth)
    if not captures:
        return last_fail
    at_best = Counter(sig for depth, sig in captures if depth == best_depth)
    ranked = at_best.most_common()
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return {"outcome": "inconsistent", "sigs": sorted(s[:12] for s in at_best), "depth": best_depth}
    sig = ranked[0][0]
    return {"outcome": "no_tls_response" if sig == EMPTY_SIG else "matched", "sig": sig}


def walk_tree(node, ctx, sig_len, depth=0, path=None, defaulted=0):
    """Walk one model against the target. Tracks how many decision probes matched a real branch vs
    fell back to the node `default` (the latter signals the model is the wrong library / off-model)."""
    path = path or []
    if node["type"] == "leaf":
        return {"status": "identified", "cluster": node["clusters"], "path": path,
                "matched": depth - defaulted, "defaulted": defaulted, "depth": depth}
    if ctx["delay"] > 0:
        time.sleep(ctx["delay"])
    trace = ctx["model"] / node["trace"]
    res = node_signature(ctx["binary"], trace, ctx["ip"], ctx["port"], ctx["sni"],
                         ctx["timeout"], ctx["retries"], ctx["repeat"], ctx["tcp_mode"])
    out = res["outcome"]
    if out == "matched":
        key = res["sig"] if not sig_len else res["sig"][:sig_len]   # truncate to model's key length
        if key in node["children"]:
            return walk_tree(node["children"][key], ctx, sig_len, depth + 1,
                             path + [node["trace"]], defaulted)
        if node.get("default") in node["children"]:                 # unseen sig -> majority branch
            return walk_tree(node["children"][node["default"]], ctx, sig_len, depth + 1,
                             path + [node["trace"] + " (default)"], defaulted + 1)
        return {"status": "unknown_stack", "reason": "response matched no model branch",
                "unmatched_sig": key, "probe": node["trace"], "depth_reached": depth, "path": path,
                "matched": depth - defaulted, "defaulted": defaulted}
    status = {"no_tls_response": "no_tls_response", "inconsistent": "inconsistent",
              "connection_error": "connection_error", "unreachable": "connection_error",
              "binary_error": "binary_error"}.get(out, "probe_failed")
    return {"status": status, "detail": res, "probe": node["trace"], "depth_reached": depth,
            "path": path, "matched": depth - defaulted, "defaulted": defaulted}


def identify_one(put, model_dir, ctx_base):
    """Load reference/<put>/ model and walk it against the target. Returns the walk result + put."""
    tree = json.loads((model_dir / "tree.json").read_text())
    meta = json.loads((model_dir / "meta.json").read_text())
    # Adopt the model's recorded probing filter unless the user passed an explicit value (not None).
    p = meta.get("params") or {}
    repeat = ctx_base["repeat"] if ctx_base["repeat"] is not None else int(p.get("n_pool", 3))
    timeout = ctx_base["timeout"] if ctx_base["timeout"] is not None else float(p.get("timeout", 15.0))
    retries = ctx_base["retries"] if ctx_base["retries"] is not None else int(p.get("retry", 2))
    ctx = dict(ctx_base, model=model_dir, tcp_mode=(meta.get("canon") == "tcp_mode"),
               repeat=repeat, timeout=timeout, retries=retries)
    res = walk_tree(tree, ctx, meta.get("sig_len", 0))
    res["put"] = put
    return res


def _summary(r):
    return {"put": r.get("put"), "status": r["status"], "matched": r.get("matched", 0),
            "defaulted": r.get("defaulted", 0),
            "cluster": r.get("cluster") if r["status"] == "identified" else None}


def combine(results):
    """Pick the library+cluster across per-PUT walks. A clean claim = reached a leaf with NO forced
    defaults. Several clean claims -> most matched nodes wins; none -> best-effort or 'unknown'."""
    clean = [r for r in results if r["status"] == "identified" and r.get("defaulted", 0) == 0]
    leafed = [r for r in results if r["status"] == "identified"]
    if len(clean) == 1:
        pick, conf = clean[0], "high"
    elif len(clean) > 1:
        pick, conf = max(clean, key=lambda r: r["matched"]), "multiple_models_claimed"
    elif leafed:
        pick, conf = max(leafed, key=lambda r: r["matched"]), "weak_defaulted"
    else:
        return {"status": "unknown", "reason": "no PUT model recognised the target",
                "per_put": [_summary(r) for r in results]}
    return {"status": "identified", "put": pick["put"], "cluster": pick["cluster"],
            "confidence": conf, "matched": pick["matched"], "path": pick["path"],
            "per_put": [_summary(r) for r in results]}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--put", nargs="+", choices=puts.put_names(),
                   help="identify an unknown target across these PUT models (reference/<put>/)")
    p.add_argument("--model", type=Path, help="single explicit model dir (instead of --put)")
    p.add_argument("--url", help="Target URL, e.g. https://example.com")
    p.add_argument("--host", help="Target hostname or IP")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--sni", help="SNI to inject (defaults to the hostname)")
    p.add_argument("--binary", help="tlspuffin prober (default: --prober/PUFFIN_BIN/derived)")
    # Default None == "adopt the model's recorded filter (meta.json params), else the built-in
    # fallback". A model built at 30/21 is only reproduced when probed at repeat>=n_pool.
    p.add_argument("--timeout", type=float, default=None, help="per-probe timeout s [default: model's, else 15]")
    p.add_argument("--retries", type=int, default=None, help="retries per probe on timeout/parse fail [default: model's retry, else 2]")
    p.add_argument("--repeat", type=int, default=None, help="re-probe each node N times [default: model's n_pool, else 3]")
    p.add_argument("--delay", type=float, default=0.0, help="delay between probes (s)")
    p.add_argument("--json", action="store_true")
    # Only the path options (this script defines its own --timeout/--port/--binary etc.).
    puts.add_common_args(p, only={"repo_root", "vendor_dir", "reference_dir", "prober"})
    args = p.parse_args()
    cfg = puts.resolve(args)

    def emit(d, code=0):
        if args.json:
            print(json.dumps(d, indent=2))
        else:
            print(f"{d['status'].upper()}: " + json.dumps({k: v for k, v in d.items() if k != 'status'}))
        sys.exit(code)

    if not args.url and not args.host:
        emit({"status": "usage_error", "error": "provide --url or --host"}, 2)
    if not args.put and not args.model:
        emit({"status": "usage_error", "error": "provide --put <list> or --model <dir>"}, 2)
    binary = args.binary or cfg.prober()
    if not Path(binary).exists():
        emit({"status": "binary_error", "error": f"binary not found: {binary}"}, 2)

    # ---- resolve target ----
    host, port, sni = args.host, args.port, args.sni
    if args.url:
        from urllib.parse import urlparse
        u = urlparse(args.url if "//" in args.url else "//" + args.url)
        host = u.hostname or host
        port = u.port or (80 if u.scheme == "http" else 443)
        sni = sni or host
    if not sni and host and not host.replace(".", "").isdigit() and ":" not in host:
        sni = host
    is_ip = host.replace(".", "").isdigit() or ":" in host
    if is_ip:
        ip, fam = host, "literal"
    else:
        try:
            ip, fam = resolve_host(host)
        except Exception as e:
            emit({"status": "connection_error", "error": f"DNS resolution failed for {host}: {e}"}, 1)

    ctx_base = {"binary": binary, "ip": ip, "port": port, "sni": sni, "timeout": args.timeout,
                "retries": args.retries, "repeat": args.repeat, "delay": args.delay}

    # ---- single explicit model ----
    if args.model:
        if not (args.model / "tree.json").exists():
            emit({"status": "model_error", "error": f"{args.model} missing tree.json"}, 2)
        result = identify_one(args.model.name, args.model, ctx_base)
    # ---- multi-PUT identification of an unknown target ----
    else:
        results = []
        for put in args.put:
            mdir = cfg.ref(put)
            if not (mdir / "tree.json").exists():
                results.append({"status": "model_error", "put": put,
                                "error": f"{mdir} missing tree.json", "matched": 0, "defaulted": 1})
                continue
            results.append(identify_one(put, mdir, ctx_base))
        result = combine(results)

    result.update({"target": host, "resolved_ip": ip, "ip_family": fam, "sni": sni, "port": port})
    emit(result, 0 if result["status"] == "identified" else 1)


if __name__ == "__main__":
    main()
