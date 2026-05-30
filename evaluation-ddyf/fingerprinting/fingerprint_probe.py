#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
try:
    from _canon import canonicalize_execution
except ImportError:
    print("ERROR: could not import _canon.py", file=sys.stderr)
    sys.exit(1)

def run_probe(trace_path: Path, host: str, port: int, sni: str | None) -> dict | None:
    cmd = [
        "target/debug/tlspuffin", "tcp", str(trace_path),
        "--host", host,
        "--port", str(port),
        "--json"
    ]
    if sni:
        cmd.extend(["--sni", sni])
        
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

def walk_tree(node, host, port, sni, delay, model_dir, tcp_mode):
    if node["type"] == "leaf":
        return node, []
    
    if delay > 0:
        time.sleep(delay)
        
    trace_path = model_dir / node["trace"]
    data = run_probe(trace_path, host, port, sni)
    if not data:
        return {"error": f"Failed to get valid JSON from probe {trace_path.name} (target might be unresponsive)"}, []
    
    sig = canonicalize_execution(data, tcp_mode=tcp_mode)
    if sig not in node["children"]:
        return {"error": "unknown / unsupported target", "unmatched_sig": sig, "trace": node["trace"]}, []
        
    child_node, path = walk_tree(node["children"][sig], host, port, sni, delay, model_dir, tcp_mode)
    return child_node, [node["trace"]] + path

def main():
    parser = argparse.ArgumentParser(description="Live TLS Fingerprinter")
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--host", help="Target IP or Hostname")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--sni", help="Explicit SNI to inject (defaults to host/url domain)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between probes to evade WAFs")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.url and not args.host:
        print("ERROR: Must provide either --url or --host", file=sys.stderr)
        sys.exit(1)
        
    host = args.host
    port = args.port
    sni = args.sni
    
    if args.url:
        parsed = urllib.parse.urlparse(args.url)
        # If no scheme is provided, netloc might be empty
        if not parsed.netloc:
            parsed = urllib.parse.urlparse("//" + args.url)
            
        host = parsed.hostname or host
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not sni:
            sni = host
            
    if not sni and host and not host.replace('.', '').isdigit():
        sni = host # Default SNI to host if it looks like a domain name

    tree_path = args.model / "tree.json"
    meta_path = args.model / "meta.json"
    
    if not tree_path.exists() or not meta_path.exists():
        print(f"ERROR: Model directory {args.model} is missing tree.json or meta.json", file=sys.stderr)
        sys.exit(1)
        
    with open(tree_path) as f:
        tree = json.load(f)
        
    with open(meta_path) as f:
        meta = json.load(f)
        
    tcp_mode = meta.get("canon") == "tcp_mode"
        
    result_node, branch_path = walk_tree(tree, host, port, sni, args.delay, args.model, tcp_mode)
    
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
