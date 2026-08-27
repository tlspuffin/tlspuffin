# Run from the repo root, e.g.:
#   PUFFIN_PATH=$PWD/target/release/sshpuffin python3 evaluation-ddyf/scan_decrypt_content.py <args>
# (PUFFIN_PATH defaults to target/release/sshpuffin)

#!/usr/bin/env python3
"""Re-run objectives with the CURRENT (fully denoised) binary and find genuine
decrypted-content divergences: Knowledges diffs sourced from the decryption
recipes (Source::Label("Decryption")). The current filter_diff drops the benign
()-count-pad, so a surviving Decryption diff is a real cross-vendor difference in
a DECRYPTED message — exactly "a difference under decryption"."""
import json, os, re, subprocess, sys
from multiprocessing.pool import ThreadPool as Pool

PUFFIN = os.environ.get("PUFFIN_PATH", "target/release/sshpuffin")
FIRST, SECOND = "libssh0114-asan", "wolfssh-asan"
VALID = re.compile(r"^[^.].*\.trace(-[0-9]+)?$")


def src_is_decryption(s):
    return isinstance(s, dict) and s.get("Label") == "Decryption"


def scan(path):
    if VALID.search(os.path.basename(path)) is None:
        return None
    try:
        r = subprocess.run([PUFFIN, "differential-execute", "--json", FIRST, SECOND, path],
                           capture_output=True, timeout=15)
        d = json.loads(r.stdout)
    except Exception:
        return None
    if not d:
        return ("clean", None)
    kinds = set()
    decrypt_hit = None
    for e in d:
        k = e.get("Knowledges")
        if k is None:
            kinds.add(next(iter(e.keys())))
            continue
        inner = k.get("InnerDifference")
        dt = k.get("DifferentTypes")
        if inner and src_is_decryption(inner.get("source")):
            kinds.add("DECRYPT-content")
            decrypt_hit = ("InnerDifference", inner, path)
        elif dt and (src_is_decryption(dt.get("first_source")) or src_is_decryption(dt.get("second_source"))):
            kinds.add("DECRYPT-type")
            decrypt_hit = ("DifferentTypes", dt, path)
        else:
            kinds.add("Knowledges-other")
    return (tuple(sorted(kinds)), decrypt_hit)


def main():
    from collections import Counter

    import glob

    pattern, cap = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    par = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    hitfile = open(sys.argv[4], "w") if len(sys.argv) > 4 else open("/tmp/decrypt_hits.jsonl", "w")
    # pattern may be a single objective dir OR a glob matching several campaign
    # objective dirs (aggregate). Gather .trace files from all matches.
    folders = [pattern] if os.path.isdir(pattern) and not glob.has_magic(pattern) else glob.glob(pattern)
    files = []
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        files.extend(os.path.join(folder, f) for f in os.listdir(folder))
    files = files[:cap]
    sys.stderr.write(f"aggregating {len(folders)} folder(s), {len(files)} entries\n")
    total = len(files)
    cats = Counter()
    n_hits = 0
    done = 0
    with Pool(par) as p:
        for r in p.imap_unordered(scan, files, chunksize=64):
            done += 1
            if done % 10000 == 0:
                sys.stderr.write(f"  ...{done}/{total} processed, {n_hits} decrypt-content hits\n")
                sys.stderr.flush()
            if r is None:
                continue
            kinds, hit = r
            cats[kinds] += 1
            if hit is not None:
                n_hits += 1
                kind, detail, path = hit
                hitfile.write(json.dumps({"kind": kind, "path": path, "detail": detail}) + "\n")
                hitfile.flush()
    hitfile.close()
    print(f"\nscanned {sum(cats.values())} objectives (of {total} entries)")
    for k, n in cats.most_common(20):
        print(f"  {n:8d}  {k}")
    print(f"\n=== DECRYPTION-sourced content divergences: {n_hits} (details in hitfile) ===")


if __name__ == "__main__":
    main()
