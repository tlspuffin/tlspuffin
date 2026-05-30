#!/usr/bin/env python3
"""
Phase 5: Decision tree & minimal separating set.

Reads candidates/signatures.csv and candidates/clusters.json, then:

  1. Builds a greedy information-gain (ID3-style) decision tree over clusters.
     Each internal node picks the trace that best splits the remaining cluster
     set; leaves are single clusters.
  2. Finds a minimal separating set: the fewest traces such that every pair of
     distinguishable clusters is separated by ≥ 1 trace.
  3. Emits:
       candidates/tree.json     — serialised decision tree
       candidates/tree.dot      — Graphviz visualisation
       candidates/report.md     — metrics + heatmap

Run from repo root: python3 evaluation-ddyf/fingerprinting/build_tree.py
"""
import csv
import json
import math
import sys
from pathlib import Path
from collections import defaultdict
from typing import Any

# ─── Configurable constants ───────────────────────────────────────────────────
# Tie-break strategy when multiple traces share the maximum info-gain:
# 'fewest_steps' = prefer shorter probes (fewer trace steps).
# Can be changed to 'first' (pick whichever comes first in sorted order).
TIEBREAK = 'fewest_steps'
# ──────────────────────────────────────────────────────────────────────────────

_HERE       = Path(__file__).resolve().parent
CANDIDATES  = _HERE / "candidates"
SIG_CSV     = CANDIDATES / "signatures.csv"
CLUSTERS_JSON = CANDIDATES / "clusters.json"
TREE_JSON   = CANDIDATES / "tree.json"
TREE_DOT    = CANDIDATES / "tree.dot"
REPORT_MD   = CANDIDATES / "report.md"

# Sentinel for execution failure
_ERR = "ERROR"

# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────


def _load_matrix() -> tuple[list[str], list[str], dict[str, dict[str, str]]]:
    """
    Returns (traces, versions, matrix)
    where matrix[trace][version] = sig_hash (or _ERR).
    """
    if not SIG_CSV.exists():
        print(f"ERROR: {SIG_CSV} not found — run signatures.py first.", file=sys.stderr)
        sys.exit(1)

    with open(SIG_CSV, newline='') as f:
        reader = csv.DictReader(f)
        versions = [c for c in (reader.fieldnames or []) if c != 'trace']
        matrix: dict[str, dict[str, str]] = {}
        traces: list[str] = []
        for row in reader:
            t = row['trace']
            traces.append(t)
            matrix[t] = {v: row[v] for v in versions}

    return traces, versions, matrix


def _load_clusters() -> list[list[str]]:
    """Return list-of-version-lists from clusters.json."""
    if not CLUSTERS_JSON.exists():
        print(f"ERROR: {CLUSTERS_JSON} not found — run signatures.py first.", file=sys.stderr)
        sys.exit(1)
    with open(CLUSTERS_JSON) as f:
        data = json.load(f)
    return [c['versions'] for c in data['clusters']]


def _load_num_steps() -> dict[str, int]:
    """Read num_steps from manifest.csv for tie-breaking."""
    manifest = CANDIDATES / "manifest.csv"
    result: dict[str, int] = {}
    if manifest.exists():
        with open(manifest, newline='') as f:
            for row in csv.DictReader(f):
                try:
                    result[row['trace']] = int(row['num_steps'])
                except (KeyError, ValueError):
                    pass
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Decision tree
# ─────────────────────────────────────────────────────────────────────────────


def _cluster_sig(trace: str, cluster: list[str], matrix: dict) -> str:
    """
    The canonical signature of a cluster for a given trace.
    All versions in the cluster must agree; if they don't (shouldn't happen by
    construction), return a composite hash to force a split.
    """
    sigs = {matrix[trace].get(v, _ERR) for v in cluster}
    if len(sigs) == 1:
        return next(iter(sigs))
    return "MIXED:" + "|".join(sorted(sigs))


def _entropy(cluster_set: list[list[str]]) -> float:
    """
    Shannon entropy of the cluster-size distribution.
    H = -Σ p_i log2(p_i) where p_i = |cluster_i| / total_versions.
    """
    total = sum(len(c) for c in cluster_set)
    if total <= 1:
        return 0.0
    h = 0.0
    for c in cluster_set:
        p = len(c) / total
        if p > 0:
            h -= p * math.log2(p)
    return h


def _info_gain(
    cluster_set: list[list[str]],
    trace: str,
    matrix: dict,
) -> float:
    """
    Information gain of splitting cluster_set by trace signature.
    IG = H(cluster_set) - Σ_{sig_value} P(sig)*H(clusters_with_sig)
    """
    h_before = _entropy(cluster_set)

    # Group clusters by their signature for this trace
    groups: dict[str, list[list[str]]] = defaultdict(list)
    total = sum(len(c) for c in cluster_set)
    for cluster in cluster_set:
        sig = _cluster_sig(trace, cluster, matrix)
        groups[sig].append(cluster)

    if len(groups) <= 1:
        return 0.0   # trace doesn't split at all

    h_after = 0.0
    for group in groups.values():
        p = sum(len(c) for c in group) / total
        h_after += p * _entropy(group)

    return h_before - h_after


def _build_tree(
    cluster_set: list[list[str]],
    available: list[str],
    matrix: dict,
    num_steps: dict[str, int],
) -> dict[str, Any]:
    """
    Recursively build a greedy info-gain decision tree.

    Returns a nested dict:
      Leaf:   {"type": "leaf", "clusters": [["v1", ...], ...]}
      Node:   {"type": "node", "trace": "path", "children": {sig: subtree, ...}}
    """
    # Leaf: all clusters already a singleton or nothing splits them further
    if len(cluster_set) <= 1 or not available:
        return {"type": "leaf", "clusters": cluster_set}

    # Check if all clusters are already singletons (fully distinguished)
    if all(len(c) == 1 for c in cluster_set) and len(cluster_set) > 1:
        # Need a trace that separates them
        pass  # fall through to pick the best trace

    # Pick the trace with the highest information gain
    def sort_key(t: str) -> tuple:
        ig = _info_gain(cluster_set, t, matrix)
        steps = num_steps.get(t, 9999)
        return (-ig, steps if TIEBREAK == 'fewest_steps' else 0, t)

    best = min(available, key=sort_key)
    best_ig = _info_gain(cluster_set, best, matrix)

    if best_ig <= 0.0:
        # No trace separates remaining clusters — they are truly indistinguishable
        return {"type": "leaf", "clusters": cluster_set}

    # Split
    groups: dict[str, list[list[str]]] = defaultdict(list)
    for cluster in cluster_set:
        sig = _cluster_sig(best, cluster, matrix)
        groups[sig].append(cluster)

    remaining = [t for t in available if t != best]
    children = {
        sig: _build_tree(group, remaining, matrix, num_steps)
        for sig, group in groups.items()
    }

    return {
        "type":     "node",
        "trace":    best,
        "children": children,
    }


def _tree_depth(node: dict) -> int:
    if node["type"] == "leaf":
        return 0
    return 1 + max(_tree_depth(c) for c in node["children"].values())


def _tree_probes(node: dict) -> set[str]:
    """All distinct trace paths used as decision nodes."""
    if node["type"] == "leaf":
        return set()
    probes = {node["trace"]}
    for child in node["children"].values():
        probes |= _tree_probes(child)
    return probes


# ─────────────────────────────────────────────────────────────────────────────
# Minimal separating set
# ─────────────────────────────────────────────────────────────────────────────


def _greedy_min_sep_set(
    clusters: list[list[str]],
    traces: list[str],
    matrix: dict,
) -> list[str]:
    """
    Greedy minimum test cover:
    Find the smallest set of traces such that every pair of distinguishable
    clusters is separated by at least one trace in the set.

    A trace t separates clusters Ci and Cj iff
        cluster_sig(t, Ci) != cluster_sig(t, Cj)
    and neither is _ERR.
    """
    # Build the set of distinguishable (unordered) cluster pairs
    n = len(clusters)
    cids = list(range(n))
    uncovered: set[frozenset] = set()
    for i in range(n):
        for j in range(i + 1, n):
            ci, cj = clusters[i], clusters[j]
            # Check if ANY trace separates them
            separable = any(
                _cluster_sig(t, ci, matrix) != _cluster_sig(t, cj, matrix)
                and _cluster_sig(t, ci, matrix) != _ERR
                and _cluster_sig(t, cj, matrix) != _ERR
                for t in traces
            )
            if separable:
                uncovered.add(frozenset([i, j]))

    selected: list[str] = []
    available = list(traces)

    while uncovered and available:
        # Pick the trace covering the most uncovered pairs
        def covers(t: str) -> set[frozenset]:
            result = set()
            for pair in uncovered:
                i, j = list(pair)
                si = _cluster_sig(t, clusters[i], matrix)
                sj = _cluster_sig(t, clusters[j], matrix)
                if si != sj and si != _ERR and sj != _ERR:
                    result.add(pair)
            return result

        best = max(available, key=lambda t: len(covers(t)))
        covered_now = covers(best)
        if not covered_now:
            break  # remaining pairs are indistinguishable
        selected.append(best)
        uncovered -= covered_now
        available = [t for t in available if t != best]

    if uncovered:
        print(f"  WARNING: {len(uncovered)} cluster pair(s) cannot be separated by any trace.")

    return selected


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ascii_tree(node: dict, prefix: str = "", is_last: bool = True) -> list[str]:
    """Return an ASCII-art representation of the tree."""
    lines: list[str] = []
    connector = "└── " if is_last else "├── "
    if node["type"] == "leaf":
        leaf_label = ", ".join(
            "+".join(sorted(c)) for c in node["clusters"]
        )
        lines.append(prefix + connector + f"[LEAF: {leaf_label}]")
        return lines

    trace_name = Path(node["trace"]).name
    lines.append(prefix + connector + f"? {trace_name}")
    ext = "    " if is_last else "│   "
    items = list(node["children"].items())
    for k, (sig_val, child) in enumerate(items):
        is_child_last = (k == len(items) - 1)
        short_sig = sig_val[:12] + "…" if len(sig_val) > 12 else sig_val
        child_prefix = prefix + ext
        child_lines = _ascii_tree(child, child_prefix, is_child_last)
        if child_lines:
            # Insert sig label before first child line
            first = child_lines[0]
            # Replace connector with sig-labeled connector
            child_lines[0] = child_prefix + ("└── " if is_child_last else "├── ") \
                              + f"sig={short_sig}:"
            child_lines.insert(1, first.replace(
                child_prefix + ("└── " if is_child_last else "├── "), child_prefix + "    "))
        lines += child_lines
    return lines


def _write_dot(node: dict, traces: list[str]) -> None:
    """Write Graphviz DOT file."""
    lines = ["digraph fingerprint_tree {",
             '  node [shape=box fontname="Courier"];']
    counter = [0]

    def _node_id() -> str:
        counter[0] += 1
        return f"n{counter[0]}"

    def _recurse(n: dict) -> str:
        nid = _node_id()
        if n["type"] == "leaf":
            label = "\\n".join(
                "+".join(sorted(c)) for c in n["clusters"]
            )
            lines.append(f'  {nid} [label="{label}" shape=ellipse];')
        else:
            tname = Path(n["trace"]).name
            lines.append(f'  {nid} [label="{tname}"];')
            for sig_val, child in n["children"].items():
                cid = _recurse(child)
                short = sig_val[:16] + "…" if len(sig_val) > 16 else sig_val
                lines.append(f'  {nid} -> {cid} [label="{short}"];')
        return nid

    _recurse(node)
    lines.append("}")
    TREE_DOT.write_text("\n".join(lines) + "\n")
    print(f"Wrote {TREE_DOT}")


def _tree_probes_to_distinguish(
    node: dict,
    v1: str,
    v2: str,
    matrix: dict,
    depth: int = 0,
) -> int | None:
    """
    Walk the decision tree following v1 and v2 simultaneously.

    Returns the number of probes that must be played live to tell v1 apart
    from v2: that is, (depth of the first diverging node) + 1.
    Returns None when the two versions are indistinguishable in the tree
    (they share a leaf or an ERROR value prevents routing).
    """
    if node['type'] == 'leaf':
        return None  # both reached the same leaf — indistinguishable

    trace = node['trace']
    s1 = matrix.get(trace, {}).get(v1, _ERR)
    s2 = matrix.get(trace, {}).get(v2, _ERR)

    if s1 == _ERR or s2 == _ERR:
        return None  # cannot route — treat as indistinguishable

    if s1 != s2:
        # They diverge at this probe; depth is 0-based, so probe count = depth + 1
        return depth + 1

    # Same signature → follow the shared child
    child = node['children'].get(s1)
    if child is None:
        return None
    return _tree_probes_to_distinguish(child, v1, v2, matrix, depth + 1)


def _write_heatmap(
    clusters: list[list[str]],
    traces: list[str],
    matrix: dict,
    versions: list[str],
    tree: dict,
) -> str:
    """
    Return a Markdown heatmap (versions × versions).

    Cell value = number of probes that must be played live to distinguish the
    pair, as determined by the decision tree.
    — = same version;  ≡ = indistinguishable by any candidate trace.
    """
    v2c: dict[str, int] = {}
    for i, c in enumerate(clusters):
        for v in c:
            v2c[v] = i

    header = "| version | " + " | ".join(
        v.replace('wolfssl', '') for v in versions
    ) + " |"
    sep = "| --- | " + " | ".join("---" for _ in versions) + " |"
    rows = [header, sep]

    for v1 in versions:
        cells: list[str] = []
        for v2 in versions:
            if v1 == v2:
                cells.append("—")
            elif v2c.get(v1, -1) == v2c.get(v2, -2):
                cells.append("≡")
            else:
                n = _tree_probes_to_distinguish(tree, v1, v2, matrix)
                cells.append(str(n) if n is not None else "≡")
        short = v1.replace('wolfssl', '')
        rows.append(f"| {short} | " + " | ".join(cells) + " |")
    return "\n".join(rows)


def _write_report(
    clusters: list[list[str]],
    traces: list[str],
    versions: list[str],
    matrix: dict,
    tree: dict,
    min_sep: list[str],
) -> None:
    depth = _tree_depth(tree)
    n_probes_tree = len(_tree_probes(tree))
    n_clusters = len(clusters)
    lower_bound = math.ceil(math.log2(n_clusters)) if n_clusters > 1 else 0
    heatmap = _write_heatmap(clusters, traces, matrix, versions, tree)

    lines = [
        "# Fingerprinting Pipeline — Report",
        "",
        "## Metrics",
        "",
        f"| metric | value |",
        f"| --- | --- |",
        f"| versions evaluated | {len(versions)} |",
        f"| candidate traces   | {len(traces)} |",
        f"| clusters           | {n_clusters} |",
        f"| lower bound ⌈log₂(clusters)⌉ | {lower_bound} |",
        f"| probes in tree     | {n_probes_tree} |",
        f"| tree depth         | {depth} |",
        f"| minimal separating set size | {len(min_sep)} |",
        "",
        "## Clusters",
        "",
    ]
    for i, c in enumerate(clusters):
        lines.append(f"- **C{i}**: {', '.join(sorted(c))}")
    lines += [
        "",
        "## Minimal separating set",
        "",
    ]
    for t in min_sep:
        lines.append(f"- `{t}`")
    lines += [
        "",
        "## Distinguishability heatmap",
        "(cell = # probes to play live to distinguish the pair;  ≡ = indistinguishable)",
        "",
        heatmap,
        "",
    ]

    REPORT_MD.write_text("\n".join(lines) + "\n")
    print(f"Wrote {REPORT_MD}")


# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    traces, versions, matrix = _load_matrix()
    clusters = _load_clusters()
    num_steps = _load_num_steps()

    print(f"Traces   : {len(traces)}")
    print(f"Versions : {versions}")
    print(f"Clusters : {len(clusters)}")
    print()

    # ── Build decision tree ──────────────────────────────────────────────────
    print("Building decision tree …")
    tree = _build_tree(clusters, traces, matrix, num_steps)
    n_probes = len(_tree_probes(tree))
    depth = _tree_depth(tree)
    print(f"  Tree depth  : {depth}")
    print(f"  Probes used : {n_probes}")

    with open(TREE_JSON, 'w') as f:
        json.dump(tree, f, indent=2)
    print(f"Wrote {TREE_JSON}")

    # ── Print ASCII tree ─────────────────────────────────────────────────────
    print("\nDecision tree:")
    for line in _ascii_tree(tree, "", True):
        print(line)

    # ── Minimal separating set ───────────────────────────────────────────────
    print("\nFinding minimal separating set …")
    min_sep = _greedy_min_sep_set(clusters, traces, matrix)
    print(f"  Minimal separating set ({len(min_sep)} trace(s)):")
    for t in min_sep:
        print(f"    {t}")

    # ── Dot, report ──────────────────────────────────────────────────────────
    _write_dot(tree, traces)
    _write_report(clusters, traces, versions, matrix, tree, min_sep)

    # ── Summary ──────────────────────────────────────────────────────────────
    n_clusters = len(clusters)
    lower = math.ceil(math.log2(n_clusters)) if n_clusters > 1 else 0
    print(f"\n{'─'*50}")
    print(f"  Versions   : {len(versions)}")
    print(f"  Clusters   : {n_clusters}  (lower bound log₂ = {lower})")
    print(f"  Tree probes: {n_probes}  (depth {depth})")
    print(f"  Min sep set: {len(min_sep)}")

    # ── Export Self-Contained Model ──────────────────────────────────────────
    import shutil
    import copy

    model_dir = _HERE / "model"
    model_probes_dir = model_dir / "probes"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_probes_dir.mkdir(parents=True, exist_ok=True)
    
    deployable_tree = copy.deepcopy(tree)
    
    def _export_node(node):
        if node["type"] == "node":
            abs_trace = Path(node["trace"])
            trace_id = abs_trace.stem
            dest_trace = model_probes_dir / f"{trace_id}.trace"
            if not dest_trace.exists():
                shutil.copy2(abs_trace, dest_trace)
            node["trace"] = f"probes/{trace_id}.trace"
            for child in node["children"].values():
                _export_node(child)
                
    _export_node(deployable_tree)
    
    with open(model_dir / "tree.json", 'w') as f:
        json.dump(deployable_tree, f, indent=2)
        
    def _get_vendor(v):
        for i, c in enumerate(v):
            if c.isdigit():
                return v[:i]
        return "unknown"
        
    vendor = _get_vendor(versions[0]) if versions else "unknown"
    meta = {
        "canon": "default",
        "vendor": vendor,
        "clusters": clusters
    }
    with open(model_dir / "meta.json", 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"Exported self-contained model to {model_dir}")


if __name__ == '__main__':
    main()
