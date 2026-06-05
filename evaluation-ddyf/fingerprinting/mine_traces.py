#!/usr/bin/env python3
"""
Automated, LLM-free trace miner.

The DDYF campaigns left ~56k non-hidden objective traces under experiments/, each
discovered as a behavioural diff between a specific adjacent version pair (encoded
in the experiment directory name, e.g. ...fpp-3.0.11-3.0.12--...). The published
matrix used only ~129 of them, sampled ~100 per experiment, which is why most
clusters end up separated by 1-2 traces. This script instead selects, for EACH
adjacent pair, up to K distinct traces -- a deterministic redundant cover so that
every adjacent pair is distinguished by ~K traces (transitively separating all
pairs). Output is a manifest consumed by build_live_matrix.py.

Selection is purely algorithmic: dedup by content hash, then per pair take the K
shortest traces (fewest bytes -> simplest -> most reproducible capture), ties
broken by name. No model, no LLM, reproducible.

Usage:
  python3 mine_traces.py --k 8 --out candidates_ossl_mined/manifest.csv
"""
import argparse, csv, glob, hashlib, os, re
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
PAIR_RX = re.compile(r"fpp-(\d+\.\d+\.\d+)-(\d+\.\d+\.\d+)")


def ver_key(v):  # "3.0.11" -> "openssl3011"
    return "openssl" + v.replace(".", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=8, help="max distinct traces per adjacent pair")
    ap.add_argument("--vendor", default="openssl")
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    # group non-hidden objective traces by adjacent pair
    by_pair = {}
    for d in glob.glob(str(_REPO / f"experiments/*{args.vendor}*")):
        m = PAIR_RX.search(os.path.basename(d))
        if not m:
            continue
        pair = (ver_key(m.group(1)), ver_key(m.group(2)))
        for t in glob.glob(os.path.join(d, "objective", "*.trace")):  # excludes hidden
            by_pair.setdefault(pair, []).append(t)

    seen = set()  # content-hash dedup across the whole pool
    selected, per_pair_counts = [], {}
    for pair in sorted(by_pair):
        cands = by_pair[pair]
        # deterministic: shortest first (fewest bytes), then by name
        cands.sort(key=lambda t: (os.path.getsize(t), os.path.basename(t)))
        n = 0
        for t in cands:
            if n >= args.k:
                break
            h = hashlib.sha1(open(t, "rb").read()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            selected.append((os.path.abspath(t), pair))
            n += 1
        per_pair_counts[pair] = n

    args.out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["trace", "put1", "put2", "diff_kinds", "sig_put1", "sig_put2", "num_steps", "candidate_path"]
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for t, (p1, p2) in selected:
            w.writerow({"trace": t, "put1": p1, "put2": p2})
    short = sum(1 for p, c in per_pair_counts.items() if c < args.k)
    print(f"pairs={len(by_pair)} selected={len(selected)} (k={args.k}); "
          f"{short} pairs under-filled (sparse campaigns)")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
