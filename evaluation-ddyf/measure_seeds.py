# Run from the repo root, e.g.:
#   PUFFIN_PATH=$PWD/target/release/sshpuffin python3 evaluation-ddyf/measure_seeds.py <args>
# (PUFFIN_PATH defaults to target/release/sshpuffin)

#!/usr/bin/env python3
"""Run differential-execute on the 3 differential seeds and categorize each diff
by root cause, so we can watch the denoising steps shrink the count."""
import json
import os
import subprocess
import sys

PUFFIN = os.environ.get("PUFFIN_PATH", "target/release/sshpuffin")
SEEDS = [
    "seed_client_attacker_full_aesgcm",
    "seed_client_attacker_pubkey_aesgcm",
    "seed_client_attacker_full_kexinit_synth",
]


def categorize(e):
    k = e.get("Knowledges")
    if k is None:
        return next(iter(e.keys()))  # Status / Claims / SecurityClaim
    inner = k.get("InnerDifference") or {}
    dt = k.get("DifferentTypes") or {}
    src = str(inner.get("source") or dt.get("second_source"))
    body = json.dumps(k)
    lvl = inner.get("type_name", "") or dt.get("second_type", "")
    lvl = lvl.split("::")[-1]
    if "Decryption" in src:
        return f"decrypt:{lvl}"
    if "KexAlgorithm" in body or "NameList" in body:
        return f"kexinit-order[{lvl}]"
    if "public_host_key" in body or "KeyData" in body:
        return f"hostkey[{lvl}]"
    return f"other-know[{lvl}]"


def main():
    for s in SEEDS:
        r = subprocess.run(
            [PUFFIN, "differential-execute", "--json", "libssh0114-asan", "wolfssh-asan",
             f"./seeds/{s}.trace"],
            capture_output=True, timeout=30,
        )
        try:
            d = json.loads(r.stdout)
        except Exception:
            print(f"{s:45s} PARSE-FAIL: {r.stdout[:80]!r} {r.stderr[:120]!r}")
            continue
        cats = {}
        for e in d:
            c = categorize(e)
            cats[c] = cats.get(c, 0) + 1
        print(f"{s:45s} total={len(d):2d}  {cats}")


if __name__ == "__main__":
    main()
