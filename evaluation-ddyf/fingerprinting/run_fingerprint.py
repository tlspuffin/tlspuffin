#!/usr/bin/env python3
"""Unified driver for the DDYF version-fingerprinting pipeline.

Construction (default):
    run_fingerprint.py --put openssl wolfssl [--stages matrix,tree,validate,report]
  Runs the requested stages for each PUT IN SEQUENCE (one PUT's matrix at a time -- never two in
  parallel -- to preserve the controlled-load guarantee that keeps the matrix uncorrupted). Each
  stage is the corresponding stand-alone script; all path/runtime options are forwarded.

Identification:
    run_fingerprint.py identify --host H --port P --put openssl wolfssl
  Thin wrapper over fingerprint_probe.py: walk an unknown target against several PUT models.

Stages: mine -> matrix -> tree -> validate -> report. `mine` is OFF by default (it needs fresh
differential campaigns); the default stages reproduce the numbers from the committed probe set.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import puts

HERE = Path(__file__).resolve().parent
STAGE_SCRIPT = {
    "mine": "mine_probes.py",
    "matrix": "build_matrix.py",
    "tree": "build_tree.py",
    "validate": "validate.py",
    "report": "report.py",
}
STAGE_ORDER = ["mine", "matrix", "tree", "validate", "report"]

# Common path/runtime flags to forward to each stage subprocess, if the user set them.
_FORWARD = [("repo_root", "--repo-root"), ("vendor_dir", "--vendor-dir"),
            ("reference_dir", "--reference-dir"), ("prober", "--prober"),
            ("experiments_dir", "--experiments-dir"), ("experiments_glob", "--experiments-glob"),
            ("cores", "--cores"), ("jobs", "--jobs"), ("base_port", "--base-port"),
            ("timeout", "--timeout"), ("n_pool", "--n-pool"), ("dom", "--dom"),
            ("retry", "--retry"), ("disposition", "--disposition"), ("stable_only", "--stable-only")]


def _forwarded(args):
    out = []
    for attr, flag in _FORWARD:
        v = getattr(args, attr, None)
        if v is not None:
            if isinstance(v, bool):
                if v:
                    out += [flag]
            else:
                out += [flag, str(v)]
    return out


def run_build(args):
    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    bad = [s for s in stages if s not in STAGE_SCRIPT]
    if bad:
        sys.exit(f"unknown stage(s): {bad}; choose from {STAGE_ORDER}")
    stages.sort(key=STAGE_ORDER.index)
    fwd = _forwarded(args)
    print(f"=== run_fingerprint: PUTs={args.put}  stages={stages}  (sequential) ===", flush=True)
    t0 = time.time()
    for put in args.put:                              # PUTs strictly sequential (controlled load)
        for stage in stages:
            stage_fwd = fwd
            if stage != "tree":
                stage_fwd = [f for f in fwd if f != "--stable-only"]

            cmd = [sys.executable, str(HERE / STAGE_SCRIPT[stage]), "--put", put] + stage_fwd
            print(f"\n--- [{put}] stage '{stage}': {' '.join(cmd)} ---", flush=True)
            rc = subprocess.run(cmd).returncode
            if rc != 0:
                sys.exit(f"stage '{stage}' for PUT '{put}' failed (exit {rc})")

    # ---- combined summary across PUTs ----
    cfg = puts.resolve(args)
    print(f"\n=== SUMMARY ({int(time.time() - t0)}s) ===")
    for put in args.put:
        ref = cfg.ref(put)
        meta_p, val_p = ref / "meta.json", ref / "validation.json"
        clusters = len(json.loads(meta_p.read_text())["clusters"]) if meta_p.exists() else "?"
        if val_p.exists():
            v = json.loads(val_p.read_text())
            print(f"  {put:8s}: {clusters} clusters, depth {v['depth']}, "
                  f"recognised {v['consistent']}/{v['total']} consistently (<= {v['max_traces']} traces)")
        else:
            print(f"  {put:8s}: {clusters} clusters (no validation.json)")


def run_identify(argv):
    """Delegate to fingerprint_probe.py with the remaining args."""
    cmd = [sys.executable, str(HERE / "fingerprint_probe.py")] + argv
    sys.exit(subprocess.run(cmd).returncode)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "identify":
        run_identify(sys.argv[2:])
        return
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    puts.add_put_arg(ap, multi=True)
    ap.add_argument("--stages", default="validate,report",
                    help="comma list of stages (mine,matrix,tree,validate,report). Default "
                         "'validate,report' live-tests the committed models. Full rebuild "
                         "'matrix,tree,validate,report' needs the full probe set (run 'mine' first).")
    ap.add_argument("--stable-only", action="store_true", help="exclude probes with any MISSING values in tree induction")
    puts.add_common_args(ap)
    args = ap.parse_args()
    run_build(args)


if __name__ == "__main__":
    main()
