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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

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

def get_trace_summary(cfg, put, trace_name, version):
    """Run display-execute to extract the wire-observable flight sequence.
    
    This function replays the given trace against a specific version of the PUT
    using the 'display-execute' command. It then parses the resulting JSON to
    extract high-level message types (e.g., ServerHello, Alert) and identifies
    the exact step where the PUT stopped responding.
    """
    cache_key = (trace_name, version)
    if cache_key in _SUMMARY_CACHE:
        return _SUMMARY_CACHE[cache_key]

    trace_path = _TRACE_MAP.get(trace_name)
    if not trace_path:
        return "Trace not found"
        
    try:
        binary = cfg.prober(put)
        # Replay the trace using display-execute to get the full execution log
        cmd = [binary, '--put', version, 'display-execute', '--json', '-k', str(trace_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        out = proc.stdout
        idx = out.find('{')
        
        if idx < 0:
            res = "(Binary Error)"
        else:
            data = json.loads(out[idx:])
            ex = data.get('execution', {})
            until = ex.get('executed_until', -1)
            steps = ex.get('steps', [])
            
            flights = {}
            for i, step in enumerate(steps):
                if i > until:
                    break
                knowledges = step.get('knowledges', [])
                msgs = []
                for k in knowledges:
                    if k.startswith('MessageFlight'):
                        # Capture TLS Alerts with their description codes
                        alerts = re.findall(r'Alert\(AlertMessagePayload { level: \w+, description: (\w+) } ?\)', k)
                        if alerts:
                            msgs.append(" + ".join([f"Alert({a})" for a in alerts]))
                        else:
                            # Capture other TLS message types
                            types = re.findall(r'typ: (\w+)', k)
                            if types:
                                 # Strip internal puffin structural types
                                 t_filtered = [t for t in types if t not in ('HandshakeMessagePayload', 'Message')]
                                 if t_filtered:
                                     msgs.append(" + ".join(t_filtered))
                if msgs:
                    flights[i] = ", ".join(msgs)
            
            # Build the sequence: "Step: Flight | Step: Flight | LastStep: (Terminated)"
            summary_parts = []
            term_step = until + 1
            all_steps = sorted(set(list(flights.keys()) + [term_step]))
            for s in all_steps:
                if s in flights:
                    summary_parts.append(f"{s}: {flights[s]}")
                if s == term_step:
                    summary_parts.append(f"{s}: (Terminated)")
            res = " | ".join(summary_parts)
            
        _SUMMARY_CACHE[cache_key] = res
        return res
    except Exception as e:
        return f"(Summary Error: {str(e)})"

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

    # 2. Parallelism: Pre-calculate all required branch summaries
    reqs = set()
    def collect_reqs(node):
        if node['type'] == 'leaf':
            return
        trace = os.path.basename(node['trace'])
        for sig in node['children'].keys():
            if (trace, sig) in sig_map:
                reqs.add((trace, sig_map[(trace, sig)][0]))
            collect_reqs(node['children'][sig])
    collect_reqs(tree)

    print(f"Replaying {len(reqs)} distinguishers in parallel...", end="", flush=True)
    with ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        list(ex.map(lambda r: get_trace_summary(cfg, put, r[0], r[1]), reqs))
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
            
            # Find a version that follows this branch to get its wire summary
            rep_ver = sig_map[(trace, sig)][0] if (trace, sig) in sig_map else None
            summary = get_trace_summary(cfg, put, trace, rep_ver) if rep_ver else "Unknown"
            
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
