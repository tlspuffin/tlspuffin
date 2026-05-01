#!/usr/bin/env python3

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

# Wait for binary if needed
BINARY = "/home/nbaffou/dev/tlspuffin/target/release/tlspuffin"
for i in range(120):  # Wait up to 2 minutes
    if Path(BINARY).exists():
        break
    time.sleep(1)
else:
    print("Binary not found after 2 minutes", file=sys.stderr)
    sys.exit(1)
TRACES = [
    "objective/20260428-224539921-89c793b2c31348ae.trace",
    "objective/20260428-224603665-181b503a26cc0174.trace",
    "objective/20260428-224626854-55b696095ecd33f5.trace",
    "objective/20260428-224644243-e12949a89483be3b.trace",
    "objective/20260428-224708459-f21d992286650345.trace",
    "objective/20260428-224735019-811c5d5d464e610f.trace",
    "objective/20260428-224758230-6c419b405ff25c43.trace",
    "objective/20260428-224820759-7e1286ba77831367.trace",
    "objective/20260428-224850285-7747fbc5d5282982.trace",
    "objective/20260428-224917095-655004c57752fbdb.trace",
    "objective/20260428-224934551-1ad704639c7e003d.trace",
    "objective/20260428-224954876-3448af463734593b.trace",
    "objective/20260428-225021152-3e72ac3e5a17f8c4.trace",
    "objective/20260428-225046067-faee826822e67ea7.trace",
    "objective/20260428-225106674-dd6c97c9354e3d90.trace",
    "objective/20260428-225134244-33f7185a28558875.trace",
    "objective/20260428-225157137-cd03a5e4b3c20edb.trace",
    "objective/20260428-225219360-69b35c91d9db13b3.trace",
    "objective/20260428-225246070-c2342331a7f387ba.trace",
    "objective/20260428-225314751-eed21dd431eb95f0.trace",
    "objective/20260428-225340808-2b2e184ae83cf557.trace",
    "objective/20260428-225415716-18ab22a49a37ab66.trace",
    "objective/20260428-225440770-223a2aaefb4a2195.trace",
    "objective/20260428-225506358-2e917a47b2f6dcca.trace",
    "objective/20260428-225535080-7f12de95ec64aaeb.trace",
    "objective/20260428-225603800-71172705b41a5a38.trace",
    "objective/20260428-225638172-50a1862ea7e62a7c.trace",
    "objective/20260428-225656740-dd864f3b3d62b6bd.trace",
    "objective/20260428-225728394-e7bb6bf9880582db.trace",
    "objective/20260428-225749495-5a28d3cdd5559835.trace",
]

def run_cmd(cmd, timeout=10):
    """Run command and return output or None if timeout/error."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            timeout=timeout,
            cwd="/home/nbaffou/dev/tlspuffin"
        )
        return result.stdout.decode('utf-8', errors='ignore')
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def extract_diff_info(json_str: str) -> dict:
    """Extract diff types and status info from differential-execute output."""
    result = {
        "diff_types": [],
        "ossl_error": None,
        "libre_error": None,
        "ossl_steps": None,
        "libre_steps": None,
        "total_steps": None,
        "first_to_fail": None,
        "knowledge_diff": None,
        "claim_diff": None,
    }

    if not json_str:
        return result

    try:
        data = json.loads(json_str)

        # data should be a list
        if not isinstance(data, list) or len(data) < 1:
            return result

        first_obj = data[0]

        # Extract diff_types (keys of first object)
        result["diff_types"] = list(first_obj.keys())

        # Extract Status info
        if "Status" in first_obj:
            status_obj = first_obj["Status"]
            result["ossl_error"] = status_obj.get("first_status")
            result["libre_error"] = status_obj.get("second_status")
            result["ossl_steps"] = status_obj.get("first_executed_steps")
            result["libre_steps"] = status_obj.get("second_executed_steps")
            result["total_steps"] = status_obj.get("total_step")

            # Determine first_to_fail
            ossl_steps = result["ossl_steps"]
            libre_steps = result["libre_steps"]
            if ossl_steps is not None and libre_steps is not None:
                if ossl_steps < libre_steps:
                    result["first_to_fail"] = "openssl340"
                elif libre_steps < ossl_steps:
                    result["first_to_fail"] = "libressl421"
                else:
                    result["first_to_fail"] = "same"

        # Extract Knowledges info
        if "Knowledges" in first_obj:
            kn = first_obj["Knowledges"]
            if isinstance(kn, dict):
                if "InnerDifference" in kn:
                    inner = kn["InnerDifference"]
                    if isinstance(inner, dict):
                        for key, val in inner.items():
                            result["knowledge_diff"] = f"Inner[{key}]:{str(val)[:100]}"
                            break
                elif "DifferentTypes" in kn:
                    dt = kn["DifferentTypes"]
                    if isinstance(dt, dict) and len(dt) > 0:
                        first_key = list(dt.keys())[0]
                        first_val = dt[first_key]
                        result["knowledge_diff"] = f"DifferentTypes[{first_key}][{first_val}]"

        # Extract Claims info
        if "Claims" in first_obj:
            cl = first_obj["Claims"]
            if isinstance(cl, dict):
                if "DifferentTypes" in cl:
                    dt = cl["DifferentTypes"]
                    if isinstance(dt, dict) and len(dt) > 0:
                        first_key = list(dt.keys())[0]
                        first_val = dt[first_key]
                        result["claim_diff"] = f"DifferentTypes[{first_key}][{first_val}]"
                elif "InnerDifference" in cl:
                    inner = cl["InnerDifference"]
                    if isinstance(inner, dict):
                        for key, val in inner.items():
                            result["claim_diff"] = f"Inner:{str(val)[:80]}"
                            break

    except Exception as e:
        pass

    return result

def extract_display_info(json_str: str) -> dict:
    """Extract display-execute info from JSON output."""
    result = {
        "tls_version": None,
        "executed_until": None,
        "failing_input_recipe": None,
        "claims": [],
        "knowledge_types": [],
    }

    if not json_str:
        return result

    try:
        data = json.loads(json_str)

        # Extract tls_version from first agent
        if "execution" in data and "agents" in data["execution"]:
            agents = data["execution"]["agents"]
            if len(agents) > 0:
                agent = agents[0]
                if "protocol_config" in agent and "tls_version" in agent["protocol_config"]:
                    result["tls_version"] = agent["protocol_config"]["tls_version"]

        # Extract executed_until
        if "execution" in data and "executed_until" in data["execution"]:
            result["executed_until"] = data["execution"]["executed_until"]

        eu = result["executed_until"]

        # Extract failing_input_recipe
        if eu is not None and "execution" in data and "steps" in data["execution"]:
            steps = data["execution"]["steps"]
            if eu < len(steps):
                step = steps[eu]
                if "action" in step and isinstance(step["action"], dict):
                    if "Input" in step["action"]:
                        inp = step["action"]["Input"]
                        if "recipe" in inp:
                            result["failing_input_recipe"] = str(inp["recipe"])[:300]

        # Extract claims (flatten from all steps)
        if "execution" in data and "steps" in data["execution"]:
            steps = data["execution"]["steps"]
            for step in steps:
                if "claims" in step and isinstance(step["claims"], list):
                    for claim in step["claims"]:
                        claim_str = str(claim)[:150]
                        result["claims"].append(claim_str)

        # Extract knowledge_types from knowledges
        knowledge_types_set = set()
        if "execution" in data and "steps" in data["execution"]:
            steps = data["execution"]["steps"]
            for step in steps:
                if "knowledges" in step and isinstance(step["knowledges"], list):
                    for kn_str in step["knowledges"]:
                        kn_str = str(kn_str)
                        # Extract type name: first word before { or (
                        type_name = None
                        for delim in ['{', '(']:
                            if delim in kn_str:
                                type_name = kn_str.split(delim)[0].strip()
                                break
                        if type_name:
                            knowledge_types_set.add(type_name)

        # Limit to 10 types
        result["knowledge_types"] = list(knowledge_types_set)[:10]

    except Exception as e:
        pass

    return result

def process_trace(trace_path: str) -> dict:
    """Process a single trace and return the result object."""
    print(f"Processing {trace_path}...", file=sys.stderr)

    entry = {
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
    }

    # Step 1: Differential execute
    diff_cmd = f"{BINARY} differential-execute --json openssl340 libressl421 {trace_path}"
    diff_output = run_cmd(diff_cmd)

    if diff_output:
        diff_info = extract_diff_info(diff_output)
        entry["tls_version"] = diff_info.get("tls_version")
        entry["diff_types"] = diff_info.get("diff_types")
        entry["ossl_error"] = diff_info.get("ossl_error")
        entry["libre_error"] = diff_info.get("libre_error")
        entry["ossl_steps"] = diff_info.get("ossl_steps")
        entry["libre_steps"] = diff_info.get("libre_steps")
        entry["total_steps"] = diff_info.get("total_steps")
        entry["first_to_fail"] = diff_info.get("first_to_fail")
        entry["knowledge_diff"] = diff_info.get("knowledge_diff")
        entry["claim_diff"] = diff_info.get("claim_diff")
    else:
        entry["error"] = "differential_execute_failed"
        return entry

    # Step 2: Display execute on OSSL
    ossl_cmd = f"{BINARY} --put openssl340 display-execute --json -t -k -c {trace_path}"
    ossl_output = run_cmd(ossl_cmd)

    if ossl_output:
        ossl_info = extract_display_info(ossl_output)
        # Use tls_version from display if not already set
        if not entry["tls_version"]:
            entry["tls_version"] = ossl_info.get("tls_version")
        entry["failing_input_recipe_ossl"] = ossl_info.get("failing_input_recipe")
        entry["claims_ossl"] = ossl_info.get("claims", [])
        entry["knowledge_types_ossl"] = ossl_info.get("knowledge_types", [])

    # Step 3: Display execute on LibreSSL
    libre_cmd = f"{BINARY} --put libressl421 display-execute --json -t -k -c {trace_path}"
    libre_output = run_cmd(libre_cmd)

    if libre_output:
        libre_info = extract_display_info(libre_output)
        entry["failing_input_recipe_libre"] = libre_info.get("failing_input_recipe")
        entry["claims_libre"] = libre_info.get("claims", [])
        entry["knowledge_types_libre"] = libre_info.get("knowledge_types", [])

    return entry

def main():
    results = []
    for trace in TRACES:
        result = process_trace(trace)
        results.append(result)

    output_file = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_2/batches/batch_08.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Output written to {output_file}", file=sys.stderr)

if __name__ == "__main__":
    main()
