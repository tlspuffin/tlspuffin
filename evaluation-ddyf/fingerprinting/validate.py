#!/usr/bin/env python3
"""Stage 4 -- deployment validation (train/test split).

The tree was induced from a construction matrix; this stage checks it actually holds on
FRESHLY-probed live servers (not the data it was built from). For each vendored version we launch
its real server and WALK the committed model: at each node we replay only that node's probe, follow
the branch matching the live response (or the node `default` when the response is unstable/unseen),
reach a leaf, and check the server's version is in that leaf. Each server is walked R times to
require reproducibility. This is the honest, deployment-validated robustness number -- not the
construction count.

Input : reference/<put>/{tree.json, meta.json, probes/}   (the model, from build_tree.py)
Output: reference/<put>/validation.json
"""
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor

import probe
import puts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap)
    puts.add_common_args(ap)
    ap.add_argument("--walks", type=int, default=5, help="independent walks per server (R)")
    args = ap.parse_args()
    put = args.put
    cfg = puts.resolve(args)
    cfg.prober(put)
    model = cfg.ref(put)
    tree = json.loads((model / "tree.json").read_text())
    meta = json.loads((model / "meta.json").read_text())
    sig_len = meta.get("sig_len", 0)
    # Validate exactly the versions the MODEL covers (its leaves), intersected with what is
    # actually vendored as a live server -- a model may cover fewer versions than are installed.
    vendored = set(cfg.versions(put))
    model_versions = [v for cl in meta["clusters"] for v in cl]
    versions = sorted([v for v in model_versions if v in vendored], key=lambda v: puts.vkey(put, v))
    skipped = [v for v in model_versions if v not in vendored]
    if skipped:
        print(f"[validate] note: {len(skipped)} modelled versions have no vendored server, skipped: "
              f"{[puts.dotted(put, v) for v in skipped]}", flush=True)

    def depth_of(n):
        return 0 if n["type"] == "leaf" else 1 + max(depth_of(c) for c in n["children"].values())
    tree_depth = depth_of(tree)

    def walk(port):
        """Walk the model against a live server on `port`; return (leaf_versions, traces_played)."""
        node, played = tree, 0
        while node["type"] != "leaf":
            tracef = model / node["trace"]              # node["trace"] == "probes/<file>"
            s = probe.sigkey(probe.pooled_sig(cfg, tracef, port), sig_len)
            # match the live sig to a branch; fall back to the node default (wildcard trees), then
            # to the first child as a last resort (older trees without a default key never need it).
            child = node["children"].get(s)
            if child is None and node.get("default") is not None:
                child = node["children"].get(node["default"])
            node = child if child is not None else next(iter(node["children"].values()))
            played += 1
        return frozenset(node["clusters"][0]), played

    # Launch every server up front (walks touch only the few decision probes, so load stays light).
    ports = {v: cfg.base_port + i for i, v in enumerate(versions)}
    servers = {v: probe.launch(cfg, put, v, ports[v]) for v in versions}
    for v in versions:
        probe.wait_listen(ports[v])
    print(f"[validate] PUT={put}  walking {len(versions)} live servers x {args.walks} "
          f"(tree depth {tree_depth}, cores {cfg.cores or 'unpinned'})", flush=True)

    def trial(v):
        leaves, plays = [], []
        for _ in range(args.walks):
            lf, pl = walk(ports[v])
            leaves.append(lf)
            plays.append(pl)
        return v, leaves, plays

    t0, results = time.time(), {}
    with ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        for v, leaves, plays in ex.map(trial, versions):
            results[v] = (leaves, plays)
    probe.kill(*servers.values())

    correct = consistent = maxplay = 0
    for v in versions:
        leaves, plays = results[v]
        maxplay = max(maxplay, max(plays))
        in_leaf = all(v in lf for lf in leaves)
        same = len(set(leaves)) == 1
        correct += in_leaf
        consistent += in_leaf and same
        flag = "OK" if (in_leaf and same) else ("ok-but-flips" if in_leaf else "WRONG")
        print(f"  {puts.dotted(put, v):7s} {flag:13s} plays={plays}", flush=True)

    print(f"\n[validate] === R={args.walks} walks/server, <= {tree_depth} traces each ===")
    print(f"recognised (lands in a leaf with its version): {correct}/{len(versions)}")
    print(f"recognised CONSISTENTLY (same leaf every walk): {consistent}/{len(versions)}")
    print(f"max traces played to classify a server:        {maxplay}   ({int(time.time()-t0)}s)")
    json.dump({"put": put, "correct": correct, "consistent": consistent, "total": len(versions),
               "max_traces": maxplay, "walks": args.walks, "depth": tree_depth},
              open(model / "validation.json", "w"), indent=2)
    print(f"[validate] wrote {model}/validation.json", flush=True)


if __name__ == "__main__":
    main()
