#!/usr/bin/env python3
"""Reproduce CVE-2023-35784 (LibreSSL SSL_clear double free / use-after-free) with the real PUT.

Runs the trace `seed_server_attacker12_then_12` (two TLS 1.2 handshakes, a DY attacker playing the
server, against the real LibreSSL client of the PUT) through the `tlspuffin` binary:

  1. without `--put-use-clear`: the agent is recreated between the two handshakes   -> no crash
  2. with    `--put-use-clear`: the agent is reset with SSL_clear() between them    -> ASAN crash
                                                                      on a vulnerable build

Prerequisites (in the project's Nix shell):
  just mk_vendor libressl libressl362-asan
  cargo build --features=cputs --bin tlspuffin

Usage: tools/repro_cve_2023_35784.py [--put libressl362-asan] [--bin target/debug/tlspuffin]
"""
import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED = "tlspuffin::tls::seeds::seed_server_attacker12_then_12.trace"


def run(cmd, cwd, timeout):
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, errors="replace"
    )


def summarize_asan(output):
    """Return the ASAN headline and the first frames of the crash/free stacks, if any."""
    head = re.search(r"ERROR: AddressSanitizer: (.+)", output)
    if not head:
        return None
    lines = output.splitlines()
    frames = []
    for i, line in enumerate(lines):
        if "ERROR: AddressSanitizer" in line:
            frames = [l.strip() for l in lines[i + 2 : i + 9] if l.strip().startswith("#")]
            break
    return head.group(1).split(" on address")[0], frames


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--put", default="libressl362-asan", help="PUT / vendor preset to run against")
    ap.add_argument("--bin", default=str(ROOT / "target/debug/tlspuffin"), help="tlspuffin binary")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    binary = Path(args.bin)
    if not binary.exists():
        sys.exit(f"{binary} not found: run `cargo build --features=cputs --bin tlspuffin` first")

    with tempfile.TemporaryDirectory() as tmp:
        gen = run([str(binary), "seed", "--puts", args.put], tmp, args.timeout)
        trace = Path(tmp) / "seeds" / SEED
        if gen.returncode != 0 or not trace.exists():
            sys.exit(f"seed generation failed for PUT {args.put}:\n{gen.stdout}{gen.stderr}")
        print(f"[+] trace: {SEED} (PUT {args.put})")

        results = {}
        for use_clear in (False, True):
            cmd = [str(binary)]
            if use_clear:
                cmd.append("--put-use-clear")
            cmd += ["--put", args.put, "execute", str(trace)]
            res = run(cmd, tmp, args.timeout)
            out = res.stdout + res.stderr
            asan = summarize_asan(out)
            label = "with    --put-use-clear" if use_clear else "without --put-use-clear"
            status = f"ASAN {asan[0]}" if asan else f"no crash (exit code {res.returncode})"
            print(f"[{'!' if asan else '+'}] {label}: {status}")
            if asan:
                for frame in asan[1]:
                    print(f"      {frame[:110]}")
            results[use_clear] = asan

    if results[True] and not results[False]:
        print("\nREPRODUCED: crash only when the agent is reset with SSL_clear().")
        return 0
    if not results[True]:
        print("\nNOT reproduced (fixed build, or the PUT does not call SSL_clear).")
        return 1
    print("\nUNEXPECTED: crash also without --put-use-clear.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
