#!/usr/bin/env python3
"""Decision tree visualizer with wire-observable details.

This script reads a DDYF decision tree (tree.json) and its signature matrix 
(signatures.csv) to generate a high-fidelity ASCII visualization. Each branch 
is labeled with the exact flight-by-flight TLS records and the specific step 
where the connection terminated, making the cryptographic distinguishers 
human-verifiable.

The script automatically detects whether a tree is "Live (TCP)" or "Offline" by 
inspecting the 'canon' field in the associated meta.json.

Usage:
    ./tree_report.py --put wolfssl
    ./tree_report.py --put openssl --tree custom_tree.json

Features:
    - ASCII tree art with vertical lines for easier tracking of deep branches.
    - Wire-observable labeling: Translates cryptic signatures into sequences 
      like "0: HRR | 4: Alert(HandshakeFailure) | 5: (Terminated)".
    - Auto-discovery: Searches for probe traces in reference dirs and 
      experiment objectives.
    - Parallelization: Replays distinguishers in parallel using a thread pool.
    - Portability: Uses relative paths based on the git repository root.
"""
import argparse
import csv
import json
import os
import re
import subprocess
from pathlib import Path
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor

import probe
import puts

# Cache for trace summaries to avoid redundant executions across different tree branches
_SUMMARY_CACHE = {}
# Map of trace filenames to absolute paths, built once at startup
_TRACE_MAP = {}

def build_trace_map(cfg, put):
    """Scan all likely trace locations once to build a fast lookup map."""
    global _TRACE_MAP
    search_dirs = [
        cfg.ref(put) / "probes_full",
        cfg.ref(put) / "probes",
        cfg.repo / "evaluation-ddyf" / "fingerprinting" / "reference" / put / "probes_full",
        cfg.repo / "evaluation-ddyf" / "fingerprinting" / "reference" / put / "probes",
        cfg.repo / "experiments",
    ]
    for d in search_dirs:
        if not d.exists():
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if f.endswith(".trace") and f not in _TRACE_MAP:
                    _TRACE_MAP[f] = os.path.join(root, f)

def _notable_details(k):
    """Structural sub-fields of a server flight that the message-type list drops but that can be
    the actual distinguisher between two branches (e.g. the EncryptThenMac extension echo, or the
    group a HelloRetryRequest / ServerHello selects). Returned as a sorted, de-duplicated list."""
    det = []
    if 'EncryptThenMac' in k:
        det.append('EncryptThenMac')
    if 'ExtendedMasterSecret' in k:
        det.append('ExtendedMasterSecret')
    # KeyShare group in a ServerHello / HelloRetryRequest (e.g. "KeyShare(secp256r1)")
    for g in re.findall(r'KeyShare\((\w+)\)', k):
        det.append(f'KeyShare({g})')
    for g in re.findall(r'KeyShareEntry\w*\s*\{\s*group:\s*(\w+)', k):
        det.append(f'KeyShare({g})')
    return sorted(set(det))


def _render_flight(data):
    """Parse one execution JSON into a human summary:
    "0: <flight> | 1: <flight> | N: (Terminated)". Server flights are annotated with notable
    structural sub-fields (extensions / selected group) so that two branches that share the same
    message types but differ in a sub-field (e.g. EtM echo, HRR group) render distinctly."""
    ex = data.get('execution', {})
    until = ex.get('executed_until', -1)
    steps = ex.get('steps', [])
    flights = {}
    for i, step in enumerate(steps):
        if i > until:
            break
        msgs = []
        for k in step.get('knowledges', []):
            if not (isinstance(k, str) and k.startswith('MessageFlight')):
                continue
            # TLS Alerts: keep the description code (the true distinguisher)
            alerts = re.findall(r'Alert\(AlertMessagePayload { level: \w+, description: (\w+) } ?\)', k)
            if alerts:
                msgs.append(" + ".join(f"Alert({a})" for a in alerts))
            else:
                types = re.findall(r'typ: (\w+)', k)
                t_filtered = [t for t in types if t not in ('HandshakeMessagePayload', 'Message')]
                if t_filtered:
                    label = " + ".join(t_filtered)
                    details = _notable_details(k)
                    if details:
                        label += " [" + ", ".join(details) + "]"
                    msgs.append(label)
        if msgs:
            flights[i] = ", ".join(msgs)
    summary_parts = []
    term_step = until + 1
    for s in sorted(set(list(flights.keys()) + [term_step])):
        if s in flights:
            summary_parts.append(f"{s}: {flights[s]}")
        if s == term_step:
            summary_parts.append(f"{s}: (Terminated)")
    return " | ".join(summary_parts)


def _live_capture(cfg, trace_path, port):
    """One live-TCP replay -> (depth, full_canon_sig, data) or None."""
    try:
        r = subprocess.run(cfg.task_prefix() + [cfg.prober(), "tcp", str(trace_path),
                                                "--host", "127.0.0.1", "--port", str(port), "--json"],
                           capture_output=True, text=True, timeout=cfg.timeout)
    except subprocess.TimeoutExpired:
        return None
    i = r.stdout.find("{")
    if i < 0:
        return None
    try:
        d = json.loads(r.stdout[i:])
    except json.JSONDecodeError:
        return None
    depth = (d.get("execution") or {}).get("executed_until", 0) or 0
    return (depth, probe._canon_quiet(d, seg_robust=getattr(cfg, "seg_robust", False)), d)


def get_trace_summary(cfg, put, trace_name, version, port=None, target_sig=None, sig_len=0):
    """Render a branch's wire observable by probing the version LIVE over TCP -- the same channel
    the tree keys on -- pooled over K replays.

    Previously this used FFI `display-execute`, whose response can diverge from the live server
    (e.g. an FFI `HandshakeFailure` where the live server sends `InternalError`), producing labels
    that don't match the tree's live-TCP branch signatures. When `target_sig` is given, the label
    is rendered from a replay whose canonical signature (truncated to `sig_len`) equals it, so the
    printed label is guaranteed to correspond to the actual branch; otherwise the modal max-depth
    replay is used.
    """
    cache_key = (trace_name, version)
    if cache_key in _SUMMARY_CACHE:
        return _SUMMARY_CACHE[cache_key]
    trace_path = _TRACE_MAP.get(trace_name)
    if not trace_path:
        return "Trace not found"
    if port is None:
        port = cfg.base_port + 500
    srv = None
    try:
        srv = probe.launch(cfg, put, version, port)
        if not probe.wait_listen(port):
            res = "(server unavailable)"
        else:
            K = max(getattr(cfg, "n_pool", 15) // 2, 9)
            caps = [c for c in (_live_capture(cfg, trace_path, port) for _ in range(K)) if c]
            if not caps:
                res = "(no response)"
            else:
                best = max(d for d, _, _ in caps)
                pool = [(s, dat) for d, s, dat in caps if d == best]
                data = None
                if target_sig is not None:
                    for s, dat in pool:
                        if probe.sigkey(s, sig_len) == target_sig:
                            data = dat
                            break
                if data is None:
                    modal = Counter(s for s, _ in pool).most_common(1)[0][0]
                    data = next(dat for s, dat in pool if s == modal)
                res = _render_flight(data)
    except Exception as e:
        res = f"(Summary Error: {e})"
    finally:
        if srv is not None:
            probe.kill(srv)
    _SUMMARY_CACHE[cache_key] = res
    return res

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap)
    puts.add_common_args(ap)
    ap.add_argument("--signatures", help="Path to signatures.csv (default: from reference)")
    ap.add_argument("--tree", help="Path to tree.json (default: from reference)")
    args = ap.parse_args()
    
    put = args.put
    cfg = puts.resolve(args)
    ref_dir = cfg.ref(put)
    
    # Resolve the tree and signature files
    tree_path = Path(args.tree) if args.tree else ref_dir / "tree.json"
    sigs_path = Path(args.signatures) if args.signatures else ref_dir / "signatures.csv"
    
    if not tree_path.exists():
        print(f"Error: Tree not found at {tree_path}")
        return
    if not sigs_path.exists():
        print(f"Error: Signatures not found at {sigs_path}")
        return

    try:
        tree = json.loads(tree_path.read_text())
    except Exception as e:
        print(f"Error: Failed to parse tree JSON: {e}")
        return
    
    # Map (trace, signature) pairs to the versions that produced them.
    sig_map = defaultdict(list)
    try:
        with open(sigs_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                trace = os.path.basename(row['trace'])
                for v in reader.fieldnames[1:]:
                    sig_map[(trace, row[v])].append(v)
    except Exception as e:
        print(f"Error: Failed to read signatures CSV: {e}")
        return

    # 1. Faster Lookup: Pre-scan likely trace locations
    print(f"Scanning for traces...", end="", flush=True)
    build_trace_map(cfg, put)
    print(" done.")

    # Signature key length the tree was built on (0/None => full sig), so labels are rendered
    # from the live replay whose canonical signature matches the branch key.
    sig_len = 0
    try:
        sig_len = json.loads((tree_path.parent / "meta.json").read_text()).get("sig_len", 0) or 0
    except Exception:
        pass

    # 2. Parallelism: Pre-calculate all required branch summaries (live-TCP, matched to branch sig)
    reqs = set()
    def collect_reqs(node):
        if node['type'] == 'leaf':
            return
        trace = os.path.basename(node['trace'])
        for sig in node['children'].keys():
            if (trace, sig) in sig_map:
                reqs.add((trace, sig_map[(trace, sig)][0], sig))
            collect_reqs(node['children'][sig])
    collect_reqs(tree)

    reqs_list = list(reqs)
    print(f"Replaying {len(reqs_list)} distinguishers live over TCP...", end="", flush=True)
    with ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        list(ex.map(
            lambda iv: get_trace_summary(cfg, put, iv[1][0], iv[1][1],
                                         port=cfg.base_port + 500 + iv[0],
                                         target_sig=iv[1][2], sig_len=sig_len),
            list(enumerate(reqs_list))))
    print(" done.")

    # Infer mode (Live vs Offline) from meta.json
    meta_path = tree_path.parent / "meta.json"
    mode = "Unknown"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            mode = "Live (TCP)" if meta.get("canon") == "tcp_mode" else "Offline"
        except Exception: pass

    # Recursively calculate tree statistics
    def get_stats(node, depth=0):
        if node['type'] == 'leaf':
            num_v = sum(len(c) for c in node['clusters'])
            return depth, 1, num_v, set()
        
        max_d = depth
        total_clusters, total_versions = 0, 0
        probes = {os.path.basename(node['trace'])}
        for child in node['children'].values():
            d, c, v, p = get_stats(child, depth + 1)
            max_d = max(max_d, d)
            total_clusters += c
            total_versions += v
            probes.update(p)
        return max_d, total_clusters, total_versions, probes

    tree_depth, num_clusters, num_versions, used_probes = get_stats(tree)

    # Print the report header
    print(f"\nDecision Tree for {put.upper()} [{mode}]")
    print(f"{'=' * (len(put) + len(mode) + 18)}")
    print(f"Versions: {num_versions}")
    print(f"Clusters: {num_clusters}")
    print(f"Probes:   {len(used_probes)}")
    print(f"Depth:    {tree_depth}")
    print(f"Source:   {os.path.relpath(tree_path, cfg.repo)}")
    print(f"{'=' * (len(put) + len(mode) + 18)}\n")

    def walk(node, prefix="", is_last=True):
        """Recursive walker that prints the ASCII tree art."""
        marker = "└── " if is_last else "├── "
        
        if node['type'] == 'leaf':
            # Leaves show the final version cluster
            versions = [puts.dotted(put, v) for v in node['clusters'][0]]
            print(f"{prefix}{marker}[Cluster] {{{', '.join(versions)}}}")
            return

        # Decision nodes show the probe filename
        trace = os.path.basename(node['trace'])
        print(f"{prefix}{marker}[Probe] {trace}")
        
        new_prefix = prefix + ("    " if is_last else "│   ")
        sigs = sorted(node['children'].keys())
        for i, sig in enumerate(sigs):
            child = node['children'][sig]
            is_last_child = (i == len(sigs) - 1)
            
            # Find a version that follows this branch to get its wire summary (live-TCP, matched
            # to this branch's signature). Normally a cache hit from the parallel pre-pass.
            rep_ver = sig_map[(trace, sig)][0] if (trace, sig) in sig_map else None
            summary = get_trace_summary(cfg, put, trace, rep_ver, target_sig=sig,
                                        sig_len=sig_len) if rep_ver else "Unknown"
            
            # Print the branch label (the wire observable)
            child_marker = "└── " if is_last_child else "├── "
            print(f"{new_prefix}│")
            print(f"{new_prefix}{child_marker}({summary})")
            
            # Recurse into the child node
            walk(child, new_prefix + ("    " if is_last_child else "│   "), is_last_child)

    walk(tree)
    print("\n")

if __name__ == "__main__":
    main()
