#!/usr/bin/env python3
# Run from the repo root, e.g.:
#   PUFFIN_PATH=$PWD/target/release/sshpuffin python3 evaluation-ddyf/find_content_diffs.py <dir> [par] [tail]
#
# Environment:
#   PUFFIN_PATH            fuzzer binary (default: target/release/sshpuffin)
#   SSHPUFFIN_FIRST_PUT    first PUT name  (default: libssh0114)   -- must exist in the binary
#   SSHPUFFIN_SECOND_PUT   second PUT name (default: wolfssh)
#
# Scans a directory tree RECURSIVELY (so it covers both top-level objectives and
# any per-bucket subfolders), runs `differential-execute --json` on every trace,
# and reports the decrypted-transcript divergences, split into two classes:
#
#   CONTENT   — same AlignmentKey present on BOTH sides, but the message bytes
#               differ (`Changed(AlignmentKey ...)`). This is the STRONGEST signal:
#               a genuine same-message byte-level divergence.
#   PRESENCE  — a message present on one side only (`Added/Removed(AlignmentKey ...)`),
#               e.g. the known RFC 4253 §7.1 rekey KexInit (msg 20, ordinal:1) that one
#               stack emits and the other withholds. A real divergence, but NOT a
#               same-message byte difference — kept separate so it doesn't masquerade
#               as a content bug.
"""Find decryption divergences in the s2c transcript, separating true CONTENT
byte-differences from mere presence/ordering differences."""
import json, os, re, subprocess, sys
from collections import Counter
from multiprocessing.pool import ThreadPool as Pool

PUFFIN = os.environ.get("PUFFIN_PATH", "target/release/sshpuffin")
FIRST_PUT = os.environ.get("SSHPUFFIN_FIRST_PUT", "libssh0114")
SECOND_PUT = os.environ.get("SSHPUFFIN_SECOND_PUT", "wolfssh")
VALID = re.compile(r"^[^.].*\.trace(-[0-9]+)?$")


def classify(diff: str) -> str:
    """CONTENT if a key changed on both sides; PRESENCE if a key was added/removed."""
    if "Changed(AlignmentKey" in diff:
        return "CONTENT"
    if "Added(AlignmentKey" in diff or "Removed(AlignmentKey" in diff:
        return "PRESENCE"
    return "OTHER"


def scan(path):
    if VALID.search(os.path.basename(path)) is None:
        return None
    try:
        r = subprocess.run(
            [PUFFIN, "differential-execute", "--json", FIRST_PUT, SECOND_PUT, path],
            capture_output=True, timeout=20,
        )
        d = json.loads(r.stdout)
    except Exception:
        return None
    for e in d or []:
        k = e.get("Knowledges")
        if k and k.get("InnerDifference"):
            inner = k["InnerDifference"]
            src = inner.get("source", {})
            if isinstance(src, dict) and src.get("Label") == "Decryption":
                diff = inner.get("diff", "")
                return (path, classify(diff), diff[:400])
    return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print(f"\nusage: {sys.argv[0]} <dir> [parallelism] [tail-N]")
        print(f"  PUFFIN_PATH={PUFFIN}  FIRST_PUT={FIRST_PUT}  SECOND_PUT={SECOND_PUT}")
        sys.exit(2)
    root = sys.argv[1]
    par = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    tail = int(sys.argv[3]) if len(sys.argv) > 3 else 0  # 0 = all; else newest N by name

    # RECURSIVE: walk the whole tree so bucketed + unbucketed traces are all covered.
    files = []
    for dirpath, _dirs, fnames in os.walk(root):
        files += [os.path.join(dirpath, f) for f in fnames if VALID.search(f)]
    files.sort(key=os.path.basename)  # basename starts with a timestamp
    if tail:
        files = files[-tail:]

    with Pool(par) as p:
        hits = [r for r in p.map(scan, files) if r]

    content = [h for h in hits if h[1] == "CONTENT"]
    presence = [h for h in hits if h[1] == "PRESENCE"]
    other = [h for h in hits if h[1] == "OTHER"]
    print(f"scanned {len(files)} trace(s) with {FIRST_PUT} vs {SECOND_PUT}")
    print(f"  CONTENT  (same key, different bytes -- strongest signal): {len(content)}")
    print(f"  PRESENCE (added/removed message, e.g. §7.1 rekey KexInit): {len(presence)}")
    print(f"  OTHER    (unclassified transcript diff):                   {len(other)}")

    def signatures(group, label):
        if not group:
            return
        sigs = Counter()
        for _path, _cat, diff in group:
            kind = diff.split("(", 1)[0]
            fields = tuple(sorted(set(re.findall(
                r"([A-Za-z]+)\(U32Change|([A-Za-z]+)\(U8Change|"
                r"([A-Za-z]+)\(SshBytesChange|([A-Za-z]+)\(StringChange", diff))))
            flat = tuple(x for t in fields for x in t if x)
            sigs[(kind, flat)] += 1
        print(f"\n=== distinct {label} signatures ===")
        for (kind, flat), n in sigs.most_common():
            print(f"  {n:5d}x  {kind}  fields={flat}")

    signatures(content, "CONTENT")
    signatures(presence, "PRESENCE")

    print("\n=== CONTENT examples (first 8) ===")
    for path, _cat, diff in content[:8]:
        print(f"\n{path}\n  {diff}")
    if not content:
        print("  (none)")


if __name__ == "__main__":
    main()
