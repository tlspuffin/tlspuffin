#!/usr/bin/env python3
"""Stage 5 -- generate the human-readable report for a PUT.

Self-contained: reads only the committed reference data (signatures.csv + tree.json + meta.json +
validation.json) -- no external logs. Emits:
  reference/<put>/report.md    clusters, decision-tree stats, deployment-validation line, and the
                               pairwise heatmap (#probes needed to distinguish each version pair).
  reference/<put>/heatmap.csv  the full pairwise distinguish-depth matrix.
"""
import argparse
import csv
import json
import os
from collections import Counter
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
    out = cfg.ref(put)
    line = puts.PUTS[put]["line"]
    sig_len = puts.PUTS[put]["sig_len"]

    rows = list(csv.reader(open(out / "signatures.csv")))
    allv = rows[0][1:]
    keep = [i for i, v in enumerate(allv) if puts.is_version(put, v)]
    versions = sorted([allv[i] for i in keep], key=lambda v: puts.vkey(put, v))
    M = {allv[i]: [] for i in keep}
    for r in rows[1:]:
        cells = r[1:]
        for i in keep:
            M[allv[i]].append(cells[i])
    nP = len(rows) - 1
    tree = json.loads((out / "tree.json").read_text())
    meta = json.loads((out / "meta.json").read_text())
    leaves = [sorted(g, key=lambda v: puts.vkey(put, v)) for g in meta["clusters"]]
    leaves.sort(key=lambda g: (-len(g), puts.vkey(put, g[0])))

    # Map a node to its matrix column index. New trees store "probe"; older ones (e.g. the WolfSSL
    # model) only store the trace filename, so fall back to matching the basename.
    base_to_idx = {os.path.basename(r[0]): i for i, r in enumerate(rows[1:])}
    def node_pi(node):
        return node["probe"] if "probe" in node else base_to_idx[os.path.basename(node["trace"])]

    def trunc(s):
        return s if (s in MISSING or not sig_len) else s[:sig_len]

    def child_of(node, v):
        s = trunc(M[v][node_pi(node)])
        return node["children"].get(s) or node["children"].get(node.get("default")) \
            or next(iter(node["children"].values()))

    def path_of(v):
        """Sequence of probe indices visited from root to v's leaf (for the heatmap)."""
        p, node = [], tree
        while node["type"] != "leaf":
            p.append(node_pi(node))
            node = child_of(node, v)
        return p
    paths = {v: path_of(v) for v in versions}

    def depth_of(n):
        return 0 if n["type"] == "leaf" else 1 + max(depth_of(c) for c in n["children"].values())
    used = set()
    def collect_used(n):
        if n["type"] == "node":
            used.add(node_pi(n))
            for c in n["children"].values():
                collect_used(c)
    collect_used(tree)
    depth = depth_of(tree)

    def dprobes(u, v):
        pu, pv = paths[u], paths[v]
        for i in range(min(len(pu), len(pv))):
            if pu[i] != pv[i]:
                return i + 1
        return None        # identical path -> same leaf -> indistinguishable

    informative = sum(1 for j in range(nP)
                      if len({M[v][j] for v in versions if M[v][j] not in MISSING}) >= 2)

    L = []
    def w(s=""):
        L.append(s)

    w(f"# {put} version fingerprinting -- result\n")
    w(f"Distinguishing {len(versions)} {put} releases "
      f"({puts.dotted(put, versions[0])}-{puts.dotted(put, versions[-1])}) over live TCP via DDYF "
      f"differential-fuzzing probes. LLM-free; reproduce with `run_fingerprint.py --put {put}`.\n")

    w("## Decision-tree stats\n")
    w(f"- Distinguishable clusters (tree leaves): **{len(leaves)}**")
    w(f"- Tree depth: **{depth}** -> identify any server by replaying **<= {depth} traces**")
    w(f"- Distinct probe traces used: **{len(used)}** (of {nP} confirmed)")
    w(f"- Informative probes (distinguish >= 1 pair): {informative}")
    vp = out / "validation.json"
    if vp.exists():
        vd = json.loads(vp.read_text())
        w(f"\n**Live deployment validation:** **{vd['correct']}/{vd['total']}** servers recognised, "
          f"{vd['consistent']}/{vd['total']} consistently across {vd['walks']} walks, "
          f"<= {vd['max_traces']} traces each. _Honest, deployment-validated number._\n")
    else:
        w("\n> validation.json not found; run validate.py for the deployment number.\n")

    # Probing parameters: the reproducibility filter the model was built and validated under. These
    # MUST match to reproduce the numbers above -- a 30/21 model probed at 10/7 may not validate.
    p = (vd.get("params") if vp.exists() else None) or meta.get("params")
    if p:
        w(f"**Probing parameters (reproducibility filter):** N_POOL={p.get('n_pool')}, "
          f"DOM={p.get('dom')}, retry={p.get('retry')}, timeout={p.get('timeout')}s. "
          f"Reproduce with: `run_fingerprint.py --put {put} --n-pool {p.get('n_pool')} "
          f"--dom {p.get('dom')} --retry {p.get('retry')} --timeout {p.get('timeout')}` "
          f"(or just `--stages validate,report`; validate adopts these from the model).\n")

    w(f"## Reliably-distinguishable clusters ({len(leaves)})\n")
    w("Two versions share a cluster iff no probe gives them stably-different live responses.\n")
    for i, g in enumerate(leaves):
        w(f"- **C{i}** ({len(g)}): " + ", ".join(puts.dotted(put, v) for v in g))
    w("")

    w("## Pairwise heatmap -- #probes to distinguish each pair\n")
    w("`cell` = number of decision probes played before two versions diverge (`.` = same cluster).\n")
    dist = Counter()
    for a, b in combinations(versions, 2):
        d = dprobes(a, b)
        dist["." if d is None else d] += 1
    w(f"**Distribution over {len(versions) * (len(versions) - 1) // 2} pairs:**\n")
    w("| #probes | pairs |")
    w("|---|---:|")
    for k in sorted([x for x in dist if x != "."]) + (["."] if "." in dist else []):
        w(f"| {'indistinguishable' if k == '.' else k} | {dist[k]} |")
    w("")
    w("Legend (index -> version): " + ", ".join(f"{i}={puts.dotted(put, v)}" for i, v in enumerate(versions)))
    w("")

    (out / "report.md").write_text("\n".join(L) + "\n")
    with open(out / "heatmap.csv", "w", newline="") as f:
        cw = csv.writer(f)
        cw.writerow([""] + [puts.dotted(put, v) for v in versions])
        for u in versions:
            cw.writerow([puts.dotted(put, u)] +
                        ["" if u == v else ("" if dprobes(u, v) is None else dprobes(u, v)) for v in versions])
    print(f"[report] wrote {out}/report.md + heatmap.csv "
          f"({len(leaves)} clusters, depth {depth}, {len(used)} probes)", flush=True)


if __name__ == "__main__":
    main()
