#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
try:
    from _canon import canonicalize_execution
except ImportError:
    print("ERROR: could not import _canon.py", file=sys.stderr)
    sys.exit(1)

def run_probe(trace_path: Path, host: str, port: int) -> dict | None:
    cmd = [
        "target/release/tlspuffin", "tcp", str(trace_path),
        "--host", host,
        "--port", str(port),
        "--json"
    ]
    for attempt in range(3):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            # Find the JSON object in stdout (in case of other output)
            out = result.stdout.strip()
            if out:
                try:
                    # sometimes there might be extra lines, find first '{'
                    idx = out.find('{')
                    if idx != -1:
                        return json.loads(out[idx:])
                    return json.loads(out)
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            pass
    return None

def walk_tree(node, host, port, model_dir):
    if node["type"] == "leaf":
        return node, []
    
    trace_path = model_dir / node["trace"]
    data = run_probe(trace_path, host, port)
    if not data:
        return {"error": f"Failed to get valid JSON from probe {trace_path.name} (target might be unresponsive)"}, []
    
    sig = canonicalize_execution(data)
    if sig not in node["children"]:
        return {"error": "unknown / unsupported target", "unmatched_sig": sig, "trace": node["trace"]}, []
        
    child_node, path = walk_tree(node["children"][sig], host, port, model_dir)
    return child_node, [node["trace"]] + path

def main():
    parser = argparse.ArgumentParser(description="Live TLS Fingerprinter")
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    tree_path = args.model / "tree.json"
    meta_path = args.model / "meta.json"
    
    if not tree_path.exists() or not meta_path.exists():
        print(f"ERROR: Model directory {args.model} is missing tree.json or meta.json", file=sys.stderr)
        sys.exit(1)
        
    with open(tree_path) as f:
        tree = json.load(f)
        
    with open(meta_path) as f:
        meta = json.load(f)
        
    result_node, branch_path = walk_tree(tree, args.host, args.port, args.model)
    
    if "error" in result_node:
        out = {
            "status": "failed",
            "error": result_node["error"],
            "path": branch_path
        }
        if "unmatched_sig" in result_node:
            out["unmatched_sig"] = result_node["unmatched_sig"]
            out["trace"] = result_node["trace"]
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"FAILED: {result_node['error']}")
            if "unmatched_sig" in result_node:
                print(f"Unmatched signature on probe {result_node['trace']}:\n{result_node['unmatched_sig']}")
        sys.exit(1)
    else:
        out = {
            "status": "success",
            "cluster": result_node["clusters"],
            "path": branch_path
        }
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"SUCCESS! Target identified as cluster:")
            for cluster in result_node["clusters"]:
                print(f"  {cluster}")
            print(f"Probes executed: {len(branch_path)}")

if __name__ == '__main__':
    main()
