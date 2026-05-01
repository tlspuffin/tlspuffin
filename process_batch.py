#!/usr/bin/env python3
import json
import subprocess
import sys
import re
from pathlib import Path

BINARY = "/home/nbaffou/dev/tlspuffin/target/release/tlspuffin"
WORK_DIR = "/home/nbaffou/dev/tlspuffin"

TRACES = [
    "objective/20260428-214021097-f1de3b45e62ec8c2.trace",
    "objective/20260428-214024644-c25f829c41a9fc97.trace",
    "objective/20260428-214028184-f84bd576453b773b.trace",
    "objective/20260428-214031075-fc9aa40279bc8733.trace",
    "objective/20260428-214034099-4b6d28656fe0bee2.trace",
    "objective/20260428-214037390-c5a06a8295d6ab5f.trace",
    "objective/20260428-214040744-7746249bbb8154ac.trace",
    "objective/20260428-214044308-89bc01bb358204fc.trace",
    "objective/20260428-214048418-47e0ac4b3148c350.trace",
    "objective/20260428-214052668-79cc887b9e132d9f.trace",
    "objective/20260428-214056431-437a8635716d3e09.trace",
    "objective/20260428-214059431-38f49d370b35d07e.trace",
    "objective/20260428-214102876-51e43b56722ef86c.trace",
    "objective/20260428-214106422-babba1de764707f7.trace",
    "objective/20260428-214110297-1f5a1eb97d5faf8b.trace",
    "objective/20260428-214113745-44f08931b9ef5eff.trace",
    "objective/20260428-214118213-3ef8add587073a6f.trace",
    "objective/20260428-214121829-18274912f1a01e7c.trace",
    "objective/20260428-214125747-6308f3068320cee4.trace",
    "objective/20260428-214128972-3d9cfdb37131b60f.trace",
    "objective/20260428-214133474-ec3659517e7437b6.trace",
    "objective/20260428-214136847-8729974c0a3dc2bf.trace",
    "objective/20260428-214141194-4e18df1c119bf74a.trace",
    "objective/20260428-214144410-cc4ff4002e294431.trace",
    "objective/20260428-214147952-c27fb577340a61a7.trace",
    "objective/20260428-214152103-9f120d24f9bc2831.trace",
    "objective/20260428-214155000-19d361c3a691e981.trace",
    "objective/20260428-214157809-34a0f0880c9bc614.trace",
    "objective/20260428-214202223-344fb67634ee9698.trace",
    "objective/20260428-214206824-b567a8f7edc6b80b.trace",
]

def run_cmd(cmd, timeout=10):
    """Run a command and return stdout, stderr, returncode"""
    try:
        # Change to work dir and run command
        full_cmd = f"cd {WORK_DIR} && {cmd}"
        result = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return None, "timeout", -1
    except Exception as e:
        return None, str(e), -1

def extract_json(output):
    """Try to extract JSON from output, handling multi-line and log lines"""
    if not output:
        return None

    # Try to parse the full output first
    try:
        return json.loads(output)
    except:
        pass

    # Remove log lines (they start with ISO timestamp or don't look like JSON)
    lines = output.strip().split('\n')

    # Find first line that looks like JSON (starts with { or [)
    json_lines = []
    in_json = False
    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith('{') or line_stripped.startswith('['):
            in_json = True
        if in_json:
            json_lines.append(line)

    if json_lines:
        try:
            return json.loads('\n'.join(json_lines))
        except:
            pass

    # Fallback: try each line individually
    for line in lines:
        try:
            return json.loads(line)
        except:
            pass

    return None

def get_diff_types(diff_obj):
    """Get list of keys in diff object"""
    if isinstance(diff_obj, dict):
        return list(diff_obj.keys())
    return []

def extract_diff_info(diff_obj):
    """Extract Status and Knowledge/Claim diffs"""
    result = {
        "ossl_error": None,
        "libre_error": None,
        "ossl_steps": None,
        "libre_steps": None,
        "total_steps": None,
        "first_to_fail": None,
        "knowledge_diff": None,
        "claim_diff": None,
    }

    if not isinstance(diff_obj, dict):
        return result

    # Extract Status info
    if "Status" in diff_obj:
        status = diff_obj["Status"]
        if isinstance(status, dict):
            result["ossl_error"] = status.get("first_status")
            result["libre_error"] = status.get("second_status")
            result["ossl_steps"] = status.get("first_executed_steps")
            result["libre_steps"] = status.get("second_executed_steps")
            result["total_steps"] = status.get("total_step")

            # Determine first_to_fail
            if result["ossl_steps"] is not None and result["libre_steps"] is not None:
                if result["ossl_steps"] < result["libre_steps"]:
                    result["first_to_fail"] = "openssl340"
                elif result["libre_steps"] < result["ossl_steps"]:
                    result["first_to_fail"] = "libressl421"
                else:
                    result["first_to_fail"] = "same"

    # Extract Knowledge diff
    if "Knowledges" in diff_obj:
        kg = diff_obj["Knowledges"]
        if isinstance(kg, dict):
            if "InnerDifference" in kg:
                inner = kg["InnerDifference"]
                if isinstance(inner, dict):
                    type_name = inner.get("type_name", "Unknown")
                    diff_text = inner.get("diff", "")[:100]
                    result["knowledge_diff"] = f"Inner[{type_name}]:{diff_text}"
            elif "DifferentTypes" in kg:
                dt = kg["DifferentTypes"]
                if isinstance(dt, dict):
                    first = dt.get("first_type") or dt.get("first", "?")
                    second = dt.get("second_type") or dt.get("second", "?")
                    result["knowledge_diff"] = f"DifferentTypes[{first}][{second}]"

    # Extract Claim diff
    if "Claims" in diff_obj:
        cl = diff_obj["Claims"]
        if isinstance(cl, dict):
            if "DifferentTypes" in cl:
                dt = cl["DifferentTypes"]
                if isinstance(dt, dict):
                    first = dt.get("first_type") or dt.get("first", "?")
                    second = dt.get("second_type") or dt.get("second", "?")
                    result["claim_diff"] = f"DifferentTypes[{first}][{second}]"
            elif "InnerDifference" in cl:
                inner = cl["InnerDifference"]
                if isinstance(inner, dict):
                    diff_text = inner.get("diff", "")[:80]
                    result["claim_diff"] = f"Inner:{diff_text}"

    return result

def extract_type_name(knowledge_str):
    """Extract type name from knowledge string (first word before { or ()"""
    match = re.search(r'^(\w+)', knowledge_str.strip())
    if match:
        return match.group(1)
    return None

def extract_display_info(json_data, put_name):
    """Extract info from display-execute output"""
    result = {
        "tls_version": None,
        "executed_until": None,
        "failing_recipe": None,
        "claims": [],
        "knowledge_types": [],
    }

    if not isinstance(json_data, dict):
        return result

    if "execution" not in json_data:
        return result

    exec_data = json_data["execution"]

    # Get TLS version
    if "agents" in exec_data and len(exec_data["agents"]) > 0:
        agent = exec_data["agents"][0]
        if "protocol_config" in agent and "tls_version" in agent["protocol_config"]:
            result["tls_version"] = agent["protocol_config"]["tls_version"]

    # Get executed_until
    eu = exec_data.get("executed_until")
    result["executed_until"] = eu

    # Get failing recipe
    if "steps" in exec_data and eu is not None and eu < len(exec_data["steps"]):
        step = exec_data["steps"][eu]
        if "action" in step:
            action = step["action"]
            if isinstance(action, dict) and "Input" in action:
                recipe = action["Input"].get("recipe", "")
                result["failing_recipe"] = recipe[:300] if recipe else None

    # Collect claims
    type_set = set()
    if "steps" in exec_data:
        for step in exec_data["steps"]:
            if "claims" in step and isinstance(step["claims"], list):
                for claim in step["claims"]:
                    claim_str = str(claim)[:150]
                    result["claims"].append(claim_str)

            # Collect knowledge types
            if "knowledges" in step and isinstance(step["knowledges"], list):
                for kg in step["knowledges"]:
                    kg_str = str(kg)
                    type_name = extract_type_name(kg_str)
                    if type_name:
                        type_set.add(type_name)

    result["knowledge_types"] = list(type_set)[:10]

    return result

def process_trace(trace_path):
    """Process a single trace and return result object"""
    result = {
        "trace": trace_path,
        "tls_version": None,
        "diff_types": [],
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
    }

    # Step 1: Run differential-execute
    cmd = f"{BINARY} differential-execute --json openssl340 libressl421 {trace_path}"
    stdout, stderr, rc = run_cmd(cmd)

    if stdout is None:
        result["error"] = "timeout" if stderr == "timeout" else "execution_failed"
        return result

    diff_data = extract_json(stdout)
    if diff_data is None:
        result["error"] = "execution_failed"
        return result

    # Extract diff info
    # diff_data might be a list with one dict, or just a dict
    diff_obj = diff_data
    if isinstance(diff_data, list) and len(diff_data) > 0:
        diff_obj = diff_data[0]

    if isinstance(diff_obj, dict):
        result["diff_types"] = get_diff_types(diff_obj)
        diff_info = extract_diff_info(diff_obj)
        result.update(diff_info)

    # Step 2: Run display-execute on OSSL
    cmd = f"{BINARY} --put openssl340 display-execute --json -t -k -c {trace_path}"
    stdout, stderr, rc = run_cmd(cmd)

    if stdout is not None:
        ossl_data = extract_json(stdout)
        if ossl_data:
            ossl_info = extract_display_info(ossl_data, "openssl340")
            if result["tls_version"] is None:
                result["tls_version"] = ossl_info["tls_version"]
            result["failing_input_recipe_ossl"] = ossl_info["failing_recipe"]
            result["claims_ossl"] = ossl_info["claims"]
            result["knowledge_types_ossl"] = ossl_info["knowledge_types"]

    # Step 3: Run display-execute on LibreSSL
    cmd = f"{BINARY} --put libressl421 display-execute --json -t -k -c {trace_path}"
    stdout, stderr, rc = run_cmd(cmd)

    if stdout is not None:
        libre_data = extract_json(stdout)
        if libre_data:
            libre_info = extract_display_info(libre_data, "libressl421")
            if result["tls_version"] is None:
                result["tls_version"] = libre_info["tls_version"]
            result["failing_input_recipe_libre"] = libre_info["failing_recipe"]
            result["claims_libre"] = libre_info["claims"]
            result["knowledge_types_libre"] = libre_info["knowledge_types"]

    return result

def main():
    results = []

    for i, trace in enumerate(TRACES):
        print(f"Processing {i+1}/{len(TRACES)}: {trace}", file=sys.stderr)
        result = process_trace(trace)
        results.append(result)

    # Write output
    output_path = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_1/batches/batch_03.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results written to {output_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
