# Run from the repo root, e.g.:
#   PUFFIN_PATH=$PWD/target/release/sshpuffin python3 evaluation-ddyf/find_content_diffs.py <args>
# (PUFFIN_PATH defaults to target/release/sshpuffin)

#!/usr/bin/env python3
"""Find decryption CONTENT differences (InnerDifference: same SshMessage kind on
both sides but different bytes) — the strongest signal."""
import json, os, re, subprocess, sys
from multiprocessing.pool import ThreadPool as Pool

PUFFIN = os.environ.get("PUFFIN_PATH", "target/release/sshpuffin")
VALID = re.compile(r"^[^.].*\.trace(-[0-9]+)?$")


def scan(path):
    if VALID.search(os.path.basename(path)) is None:
        return None
    try:
        r = subprocess.run([PUFFIN, "differential-execute", "--json",
                            "libssh0114-asan", "wolfssh-asan", path],
                           capture_output=True, timeout=15)
        d = json.loads(r.stdout)
    except Exception:
        return None
    for e in d or []:
        k = e.get("Knowledges")
        if k and k.get("InnerDifference"):
            inner = k["InnerDifference"]
            src = inner.get("source", {})
            if isinstance(src, dict) and src.get("Label") == "Decryption":
                return (path, inner.get("diff", "")[:400])
    return None


def main():
    import glob
    import re
    from collections import Counter

    folders = glob.glob(sys.argv[1]) if glob.has_magic(sys.argv[1]) else [sys.argv[1]]
    par = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    tail = int(sys.argv[3]) if len(sys.argv) > 3 else 0  # 0 = all; else newest N by name
    files = []
    for fo in folders:
        if os.path.isdir(fo):
            files += [os.path.join(fo, f) for f in os.listdir(fo)]
    files = [f for f in files if VALID.search(os.path.basename(f))]
    files.sort(key=os.path.basename)  # basename starts with timestamp
    if tail:
        files = files[-tail:]
    with Pool(par) as p:
        hits = [r for r in p.map(scan, files) if r]
    print(f"scanned {len(files)}, content-diff objectives: {len(hits)}")
    # group by a normalized signature (message kind + which fields changed)
    sigs = Counter()
    for path, diff in hits:
        kind = diff.split("(", 1)[0]
        fields = tuple(sorted(set(re.findall(r"([A-Za-z]+)\(U32Change|([A-Za-z]+)\(SshBytesChange|([A-Za-z]+)\(StringChange", diff))))
        flat = tuple(x for t in fields for x in t if x)
        sigs[(kind, flat)] += 1
    print("\n=== distinct content-divergence signatures ===")
    for (kind, flat), n in sigs.most_common():
        print(f"  {n:5d}x  {kind}  fields={flat}")
    # show a couple of examples per rare signature
    print("\n=== examples (first 8) ===")
    for path, diff in hits[:8]:
        print(f"\n{path}\n  {diff}")


if __name__ == "__main__":
    main()
