#!/usr/bin/env python3
"""Diagnose where a version's tree-walk goes inconsistent over lab TCP.
Usage: python3 diag_node.py <version> [cpus] [reps]"""
import subprocess, json, sys, io, contextlib, time, socket, os
from collections import Counter
sys.path.append(os.path.dirname(__file__))
from _canon import canonicalize_execution

VER = sys.argv[1]
CPUS = sys.argv[2] if len(sys.argv) > 2 else "0-3"
REPS = int(sys.argv[3]) if len(sys.argv) > 3 else 15
PORT = 18100
HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "lab_validation")
VBIN = f"/home/lhirschi/DDYF-fingerprinting/vendor/{VER}/bin/openssl"
PUFFIN = "/tmp/tlspuffin_o3x"
tree = json.load(open(os.path.join(HERE, "model_openssl3x_live/tree.json")))

env = dict(os.environ, OPENSSL_CONF="/dev/null")
srv = subprocess.Popen(["taskset", "-c", CPUS, VBIN, "s_server", "-accept", str(PORT),
                        "-cert", f"{LAB}/server.crt", "-key", f"{LAB}/server.key", "-quiet"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
# wait for listen
for _ in range(50):
    try:
        socket.create_connection(("127.0.0.1", PORT), 0.3).close(); break
    except OSError:
        time.sleep(0.1)

def cap(tr):
    r = subprocess.run(["taskset", "-c", CPUS, PUFFIN, "tcp",
                        os.path.join(HERE, "model_openssl3x_live", tr),
                        "--host", "127.0.0.1", "--port", str(PORT), "--json"],
                       capture_output=True, text=True, timeout=30)
    idx = r.stdout.find("{")
    data = json.loads(r.stdout[idx:]) if idx >= 0 else {}
    eu = (data.get("execution") or {}).get("executed_until", 0)
    with contextlib.redirect_stdout(io.StringIO()):
        sig = canonicalize_execution(data, tcp_mode=True, live_mode=True)
    return eu, sig

try:
    node, depth = tree, 0
    while node["type"] != "leaf":
        tr = node["trace"]; c = Counter()
        for _ in range(REPS):
            c[cap(tr)] += 1
        bestd = max(eu for eu, _ in c)
        atbest = Counter({s: n for (eu, s), n in c.items() if eu == bestd})
        print(f"depth={depth} probe={tr.split('/')[-1][:28]} bestdepth={bestd} distinct_at_best={len(atbest)}")
        for (eu, s), n in sorted(c.items()):
            print(f"    eu={eu} sig={s[:12]} x{n}")
        chosen = atbest.most_common(1)[0][0]
        print(f"  -> maxdepth-majority={chosen[:12]} in_children={chosen in node['children']}")
        if chosen not in node["children"]:
            print("  UNKNOWN (no matching branch)"); break
        node = node["children"][chosen]; depth += 1
    if node.get("type") == "leaf":
        print("LEAF:", node["clusters"])
finally:
    srv.terminate()
