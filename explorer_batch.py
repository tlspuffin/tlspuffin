#!/usr/bin/env python3
import json
import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, timeout=60):
    """Run a command and return stdout or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/home/nbaffou/dev/tlspuffin"
        )
        return result.stdout, result.returncode
    except subprocess.TimeoutExpired:
        print(f"Timeout on command: {cmd[:100]}...", file=sys.stderr)
        return None, -1
    except Exception as e:
        print(f"Error running command: {e}", file=sys.stderr)
        return None, -1

def extract_json(output):
    """Extract JSON from output."""
    if not output:
        return None
    try:
        # Try to find JSON object in output
        lines = output.strip().split('\n')
        for i, line in enumerate(lines):
            if line.startswith('{') or line.startswith('['):
                json_str = '\n'.join(lines[i:])
                return json.loads(json_str)
    except:
        pass
    return None

def extract_recipe(action_obj, max_len=300):
    """Extract recipe from action object."""
    if not isinstance(action_obj, dict):
        return None
    if "Input" in action_obj:
        recipe = action_obj["Input"].get("recipe", "")
        return recipe[:max_len] if recipe else None
    return None

def extract_type_name(knowledge_str):
    """Extract type name from knowledge string."""
    for sep in ['{', '(']:
        if sep in knowledge_str:
            return knowledge_str.split(sep)[0].strip()
    return knowledge_str.strip()

def process_differential_execute(trace_path):
    """Run differential-execute and extract diff info."""
    cmd = f"./target/release/tlspuffin differential-execute --json openssl340 libressl421 {trace_path}"
    output, rc = run_command(cmd, timeout=60)

    if rc != 0 or not output:
        return {"error": "differential_execute_failed" if rc != -1 else "diff_timeout"}

    data = extract_json(output)
    if not data:
        return {"error": "json_parse_failed"}

    result = {}

    # Extract diff_types (first-level keys)
    if isinstance(data, dict):
        result["diff_types"] = list(data.keys()) if data else None

        # Handle Status
        if "Status" in data:
            status_obj = data["Status"]
            result["ossl_error"] = status_obj.get("first_status", None)
            result["libre_error"] = status_obj.get("second_status", None)
            result["ossl_steps"] = status_obj.get("first_executed_steps", None)
            result["libre_steps"] = status_obj.get("second_executed_steps", None)
            result["total_steps"] = status_obj.get("total_step", None)

            # Determine first_to_fail
            ossl_steps = status_obj.get("first_executed_steps")
            libre_steps = status_obj.get("second_executed_steps")
            if ossl_steps is not None and libre_steps is not None:
                if ossl_steps < libre_steps:
                    result["first_to_fail"] = "openssl340"
                elif libre_steps < ossl_steps:
                    result["first_to_fail"] = "libressl421"
                else:
                    result["first_to_fail"] = "same"
        else:
            result["ossl_error"] = None
            result["libre_error"] = None
            result["ossl_steps"] = None
            result["libre_steps"] = None
            result["total_steps"] = None
            result["first_to_fail"] = None

        # Handle Knowledges
        result["knowledge_diff"] = None
        if "Knowledges" in data:
            knowl_obj = data["Knowledges"]
            if "InnerDifference" in knowl_obj:
                inner = knowl_obj["InnerDifference"]
                type_name = inner.get("type_name", "Unknown")
                diff = inner.get("diff", "")[:100]
                result["knowledge_diff"] = f"Inner[{type_name}]:{diff}"
            elif "DifferentTypes" in knowl_obj:
                dt = knowl_obj["DifferentTypes"]
                first_type = dt.get("first_type", "Unknown")
                second_type = dt.get("second_type", "Unknown")
                result["knowledge_diff"] = f"DifferentTypes[{first_type}][{second_type}]"

        # Handle Claims
        result["claim_diff"] = None
        if "Claims" in data:
            claims_obj = data["Claims"]
            if "DifferentTypes" in claims_obj:
                dt = claims_obj["DifferentTypes"]
                first_type = dt.get("first_type", "Unknown")
                second_type = dt.get("second_type", "Unknown")
                result["claim_diff"] = f"DifferentTypes[{first_type}][{second_type}]"
            elif "InnerDifference" in claims_obj:
                inner = claims_obj["InnerDifference"]
                diff = inner.get("diff", "")[:80]
                result["claim_diff"] = f"Inner:{diff}"

    return result

def process_display_execute(trace_path, put_name):
    """Run display-execute and extract execution info."""
    cmd = f"./target/release/tlspuffin --put {put_name} display-execute --json -t -k -c {trace_path}"
    output, rc = run_command(cmd, timeout=60)

    if rc != 0 or not output:
        return {
            "tls_version": None,
            "executed_until": None,
            "failing_input_recipe": None,
            "claims": [],
            "knowledge_types": []
        }

    data = extract_json(output)
    if not data or "execution" not in data:
        return {
            "tls_version": None,
            "executed_until": None,
            "failing_input_recipe": None,
            "claims": [],
            "knowledge_types": []
        }

    execution = data["execution"]
    result = {}

    # Extract TLS version
    tls_version = None
    if "agents" in execution and len(execution["agents"]) > 0:
        agent = execution["agents"][0]
        if "protocol_config" in agent:
            tls_version = agent["protocol_config"].get("tls_version", None)
    result["tls_version"] = tls_version

    # Extract executed_until
    eu = execution.get("executed_until", None)
    result["executed_until"] = eu

    # Extract failing_input_recipe
    result["failing_input_recipe"] = None
    if eu is not None and "steps" in execution and eu < len(execution["steps"]):
        step = execution["steps"][eu]
        if "action" in step and isinstance(step["action"], dict):
            recipe = extract_recipe(step["action"], 300)
            result["failing_input_recipe"] = recipe

    # Extract claims (flatten all claims from all steps)
    claims_list = []
    if "steps" in execution:
        for step in execution["steps"]:
            if "claims" in step and isinstance(step["claims"], list):
                for claim in step["claims"]:
                    claim_str = str(claim)[:150]
                    if claim_str:
                        claims_list.append(claim_str)
    result["claims"] = claims_list

    # Extract knowledge types
    knowledge_types = set()
    if "steps" in execution:
        for step in execution["steps"]:
            if "knowledges" in step and isinstance(step["knowledges"], list):
                for knowl in step["knowledges"]:
                    knowl_str = str(knowl)
                    type_name = extract_type_name(knowl_str)
                    if type_name:
                        knowledge_types.add(type_name)
    result["knowledge_types"] = sorted(list(knowledge_types))[:10]

    return result

def process_trace(trace_path):
    """Process a single trace."""
    trace_entry = {
        "trace": trace_path,
        "tls_version": None,
        "diff_types": None,
        "ossl_error": None,
        "libre_error": None,
        "ossl_steps": None,
        "libre_steps": None,
        "total_steps": None,
        "first_to_fail": None,
        "knowledge_diff": None,
        "claim_diff": None,
        "failing_input_recipe_ossl": None,
        "failing_input_recipe_libre": None,
        "claims_ossl": [],
        "claims_libre": [],
        "knowledge_types_ossl": [],
        "knowledge_types_libre": [],
        "error": None
    }

    # Run differential-execute
    diff_data = process_differential_execute(trace_path)
    if "error" in diff_data:
        trace_entry["error"] = diff_data["error"]
        return trace_entry

    # Merge differential data
    trace_entry.update({k: v for k, v in diff_data.items() if k != "error"})

    # Run display-execute for OSSL
    ossl_data = process_display_execute(trace_path, "openssl340")
    if trace_entry["tls_version"] is None:
        trace_entry["tls_version"] = ossl_data["tls_version"]
    trace_entry["failing_input_recipe_ossl"] = ossl_data["failing_input_recipe"]
    trace_entry["claims_ossl"] = ossl_data["claims"]
    trace_entry["knowledge_types_ossl"] = ossl_data["knowledge_types"]

    # Run display-execute for LibreSSL
    libre_data = process_display_execute(trace_path, "libressl421")
    trace_entry["failing_input_recipe_libre"] = libre_data["failing_input_recipe"]
    trace_entry["claims_libre"] = libre_data["claims"]
    trace_entry["knowledge_types_libre"] = libre_data["knowledge_types"]

    return trace_entry

def main():
    traces_file = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_2/batches/batch_08.txt"
    output_file = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_2/batches/batch_08.json"

    # Read trace list
    with open(traces_file, 'r') as f:
        traces = [line.strip() for line in f if line.strip()]

    print(f"Processing {len(traces)} traces with 60s timeout...", file=sys.stderr)

    results = []
    for i, trace in enumerate(traces):
        print(f"[{i+1}/{len(traces)}] Processing {trace}...", file=sys.stderr)
        entry = process_trace(trace)
        results.append(entry)

    # Write output
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Results written to {output_file}", file=sys.stderr)

if __name__ == "__main__":
    main()
