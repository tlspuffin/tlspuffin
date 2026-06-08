#!/usr/bin/env python3
"""Stage 3 -- induce the wildcard-aware decision tree (the deployment model).

Greedy, ID3-style induction over the signature matrix: at each node pick the probe that stably
separates the most still-merged version pairs, branch on the distinct stable signatures, and
recurse. UNSTABLE/SRVFAIL cells are treated as MISSING -- a probe never counts as distinguishing a
version it is unstable on, and an unstable version follows the node's MAJORITY branch (recorded as
`default`) so it can still be separated later by a probe it IS stable on. A leaf is a set of
versions no stable probe can tell apart -> one distinguishability cluster.

Emits a model compatible with fingerprint_probe.py / validate.py:
  reference/<put>/tree.json   nodes {type:node, trace:"probes/<f>", default, children:{sig:child}}
                              leaves {type:leaf, clusters:[[versions]]}
  reference/<put>/meta.json   {canon, vendor, sig_len, clusters}
  reference/<put>/probes/     ONLY the decision-node probe traces (+ manifest.csv), copied from the
                              full probe set (probes_full/) if present.

Input: reference/<put>/signatures.csv (from build_matrix.py).
"""
import argparse
import csv
import json
import os
import shutil
from collections import defaultdict
from itertools import combinations

import puts
from probe import MISSING


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap)
    puts.add_common_args(ap)
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)
    sig_len = puts.PUTS[put]["sig_len"]
    out = cfg.ref(put)

    # Guard: rebuilding the tree requires the FULL probe set so every decision-node trace can be
    # placed in probes/. Without it we would emit a tree referencing traces we cannot ship and might
    # clobber a shipped, validated model with a weaker one. A pre-built model (e.g. the WolfSSL one)
    # has no probes_full/ -> do not rebuild; reproduce it with `--stages validate,report` instead.
    if not cfg.reps_file(put).exists():
        raise SystemExit(
            f"[build_tree] refusing to rebuild: no full probe set at {cfg.reps_file(put)}.\n"
            f"  The committed {out}/tree.json is a pre-built, validated model -- reproduce it with\n"
            f"  `run_fingerprint.py --put {put} --stages validate,report` (skip the tree stage),\n"
            f"  or run `mine_probes.py --put {put}` first to regenerate the full probe set.")

    # ---- load the matrix (rows = probe basename, cols = version) ----
    rows = list(csv.reader(open(out / "signatures.csv")))
    all_versions = rows[0][1:]
    keep = [i for i, v in enumerate(all_versions) if puts.is_version(put, v)]
    versions = sorted([all_versions[i] for i in keep], key=lambda v: puts.vkey(put, v))
    probe_files = [r[0] for r in rows[1:]]                 # basenames, indexed by probe id
    M = {all_versions[i]: [] for i in keep}
    for r in rows[1:]:
        cells = r[1:]
        for i in keep:
            M[all_versions[i]].append(cells[i])
    nP = len(probe_files)
    print(f"[build_tree] PUT={put}  versions={len(versions)}  probes available={nP}", flush=True)

    stats = {"depth": 0, "used": set()}

    def build(V, depth=0):
        stats["depth"] = max(stats["depth"], depth)
        if len(V) <= 1:
            return {"type": "leaf", "clusters": [sorted(V, key=lambda v: puts.vkey(put, v))]}
        best, best_gain, best_split = None, 0, None
        for pi in range(nP):
            groups, unstable = defaultdict(list), []
            for v in V:
                s = M[v][pi]
                (unstable if s in MISSING else groups[s]).append(v)
            if len(groups) < 2:                            # separates no pair stably at this node
                continue
            gain = sum(len(a) * len(b) for a, b in combinations(groups.values(), 2))
            if gain > best_gain:
                best, best_gain, best_split = pi, gain, (dict(groups), unstable)
        if best is None:                                   # indistinguishable leaf
            return {"type": "leaf", "clusters": [sorted(V, key=lambda v: puts.vkey(put, v))]}
        stats["used"].add(best)
        groups, unstable = best_split
        default = max(groups, key=lambda k: len(groups[k]))
        if unstable:
            groups[default] = groups[default] + unstable    # unstable-on-best -> majority branch
        # `probe` (matrix column index) is extra metadata used by report.py; the live prober
        # ignores it and routes purely on `trace`/`children`/`default`.
        return {"type": "node", "trace": f"probes/{probe_files[best]}", "probe": best,
                "default": default,
                "children": {s: build(g, depth + 1) for s, g in groups.items()}}

    tree = build(versions)

    # ---- collect leaves (the cluster partition) for meta.json ----
    leaves = []
    def collect(n):
        if n["type"] == "leaf":
            leaves.append(n["clusters"][0])
        else:
            for c in n["children"].values():
                collect(c)
    collect(tree)
    leaves.sort(key=lambda g: (-len(g), puts.vkey(put, g[0])))

    # ---- copy ONLY the decision-node probe traces into the committed probes/ dir ----
    out.mkdir(parents=True, exist_ok=True)
    probes_dir = cfg.probes_dir(put)
    probes_dir.mkdir(exist_ok=True)
    # basename -> full path, from the (gitignored) full probe set if available
    src = {}
    reps_file = cfg.reps_file(put)
    if reps_file.exists():
        for p in reps_file.read_text().split():
            if p:
                src[os.path.basename(p)] = p
    used_files = sorted({probe_files[pi] for pi in stats["used"]})
    copied, missing = 0, []
    for bn in used_files:
        dst = probes_dir / bn
        if dst.exists():
            copied += 1
            continue
        if bn in src and os.path.exists(src[bn]):
            shutil.copy2(src[bn], dst)
            copied += 1
        else:
            missing.append(bn)
    with open(probes_dir / "manifest.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["probe_file", "probe_index"])
        for pi in sorted(stats["used"]):
            w.writerow([probe_files[pi], pi])
    if missing:
        print(f"[build_tree] WARNING: {len(missing)} decision-probe trace(s) not found "
              f"(need probes_full/ or a pre-populated probes/): {missing[:3]}...", flush=True)

    # ---- write tree.json + meta.json ----
    (out / "tree.json").write_text(json.dumps(tree, indent=2))
    (out / "meta.json").write_text(json.dumps(
        {"canon": "tcp_mode", "vendor": put, "sig_len": sig_len, "clusters": leaves}, indent=2))

    print(f"[build_tree] wrote {out}/tree.json + meta.json ; probes/ has {copied} decision traces",
          flush=True)
    print(f"[build_tree] === {len(leaves)} leaves (clusters), depth {stats['depth']}, "
          f"{len(stats['used'])} probes used ===", flush=True)
    for i, g in enumerate(leaves):
        print(f"  C{i:<2d} ({len(g)}): " + ", ".join(puts.dotted(put, v) for v in g))


if __name__ == "__main__":
    main()
