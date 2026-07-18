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
    # Reproduce the model under the SAME probing filter it was built with (a model built at 30/21 is
    # only reproducible when probed at 30/21). Any param the user passed explicitly still wins.
    adopted = cfg.apply_model_params(meta)
    if adopted:
        print(f"[validate] adopted model probe params: "
              f"{', '.join(f'{k}={v}' for k, v in adopted)}", flush=True)
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

    # Print FIRST (before any blocking work) so the run never looks frozen, then launch every server
    # up front (walks touch only the few decision probes, so load stays light) and wait for each to
    # listen -- a server that never comes up is flagged here rather than as a silent hang later.
    print(f"[validate] PUT={put}  prober {cfg.prober(put)}  tree depth {tree_depth}  "
          f"cores {cfg.cores or 'unpinned'}  -- launching {len(versions)} servers...", flush=True)
    ports = {v: cfg.base_port + i for i, v in enumerate(versions)}
    servers = {v: probe.launch(cfg, put, v, ports[v]) for v in versions}
    not_up = [v for v in versions if not probe.wait_listen(ports[v])]
    if not_up:
        print(f"[validate] WARNING: {len(not_up)} server(s) never listened (vendored build missing, "
              f"or port busy): {[puts.dotted(put, v) for v in not_up]}", flush=True)
    print(f"[validate] servers up; walking each x {args.walks} (streaming verdicts)...", flush=True)

    def trial(v):
        leaves, plays = [], []
        for _ in range(args.walks):
            lf, pl = walk(ports[v])
            leaves.append(lf)
            plays.append(pl)
        return v, leaves, plays

    # Stream each server's verdict AS its walks finish (as_completed, not ordered map), so progress
    # is visible live and a slow/stuck server is obvious instead of the run looking frozen.
    from concurrent.futures import as_completed
    t0, results, correct, consistent, maxplay = time.time(), {}, 0, 0, 0
    with ThreadPoolExecutor(max_workers=cfg.jobs) as ex:
        futs = {ex.submit(trial, v): v for v in versions}
        for n, fut in enumerate(as_completed(futs), 1):
            v, leaves, plays = fut.result()
            results[v] = (leaves, plays)
            in_leaf = all(v in lf for lf in leaves)   # version landed in a leaf containing it
            same = len(set(leaves)) == 1               # every walk reached the SAME leaf
            correct += in_leaf
            consistent += in_leaf and same
            maxplay = max(maxplay, max(plays))
            flag = "OK" if (in_leaf and same) else ("ok-but-flips" if in_leaf else "WRONG")
            print(f"  [{n:2d}/{len(versions)}] {puts.dotted(put, v):7s} {flag:13s} plays={plays}",
                  flush=True)
    probe.kill(*servers.values())

    print(f"\n[validate] === R={args.walks} walks/server, <= {tree_depth} traces each ===")
    print(f"recognised (lands in a leaf with its version): {correct}/{len(versions)}")
    print(f"recognised CONSISTENTLY (same leaf every walk): {consistent}/{len(versions)}")
    print(f"max traces played to classify a server:        {maxplay}   ({int(time.time()-t0)}s)")
    json.dump({"put": put, "correct": correct, "consistent": consistent, "total": len(versions),
               "max_traces": maxplay, "walks": args.walks, "depth": tree_depth,
               "params": cfg.probe_params()},   # the filter these numbers were measured under
              open(model / "validation.json", "w"), indent=2)
    print(f"[validate] wrote {model}/validation.json", flush=True)


if __name__ == "__main__":
    main()
