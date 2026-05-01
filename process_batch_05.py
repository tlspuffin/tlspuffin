#!/usr/bin/env python3
"""
Process batch_05 traces according to explorer.md instructions
"""

import json
import subprocess
import sys
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

BASE_DIR = Path("/home/nbaffou/dev/tlspuffin")
BINARY = BASE_DIR / "target/release/tlspuffin"
TRACES = [
    "objective/20260428-214403465-d2f05b199a5d9c5a.trace",
    "objective/20260428-214406967-ca79d3e39d742c12.trace",
    "objective/20260428-214410736-338170b783e515ae.trace",
    "objective/20260428-214413767-e49e2186225b2fed.trace",
    "objective/20260428-214418631-dfd354e7572698a4.trace",
    "objective/20260428-214422288-584687c0a6b096da.trace",
    "objective/20260428-214426442-2c52844c341f147d.trace",
    "objective/20260428-214430283-d692d79b94c40b21.trace",
    "objective/20260428-214433464-c07afc4376c0abb5.trace",
    "objective/20260428-214437259-b41650fdcf59e77d.trace",
    "objective/20260428-214441261-f62ceb6bc82c0988.trace",
    "objective/20260428-214444466-e07378e1826f8953.trace",
    "objective/20260428-214448911-9a54f3483874ed60.trace",
    "objective/20260428-214452411-38dbe70cc520eb14.trace",
    "objective/20260428-214456616-ddf2c150fda22a60.trace",
    "objective/20260428-214459940-8c64f522dd503eaf.trace",
    "objective/20260428-214504597-c60a60a2d1e63c7f.trace",
    "objective/20260428-214507310-ea46015240584c11.trace",
    "objective/20260428-214510489-688769b638f32a06.trace",
    "objective/20260428-214515218-76dc9da3c5112021.trace",
    "objective/20260428-214518578-5a6ec93f959f4c31.trace",
    "objective/20260428-214522317-e7fa6e607cb47f0a.trace",
    "objective/20260428-214526083-0b13bfbaa4ed3ec1.trace",
    "objective/20260428-214530071-10ed9839d747d329.trace",
    "objective/20260428-214534292-244b5142d6e621af.trace",
    "objective/20260428-214538917-7d9bb3cdcdab4ccb.trace",
    "objective/20260428-214541829-52b60df69cbd25e8.trace",
    "objective/20260428-214546470-619aadbf5f1f3136.trace",
    "objective/20260428-214549570-f302477f454dda13.trace",
    "objective/20260428-214552731-fd82d4c5e308e5e2.trace",
]

def run_cmd(cmd: List[str], timeout: int = 10, skip_log_line: bool = False) -> tuple[bool, Optional[str]]:
    """Run command and return success and output"""
    try:
        result = subprocess.run(
            cmd,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout
        if skip_log_line and output:
            # Skip the first log line (contains timestamp and log info)
            lines = output.split('\n')
            if lines and lines[0].startswith('202'):  # Timestamp format
                output = '\n'.join(lines[1:])
        # For display-execute, we want the output even if exit code is non-zero
        # For differential-execute, same thing - we want the JSON output
        return output is not None and len(output) > 0, output
    except subprocess.TimeoutExpired:
        return False, None
    except Exception as e:
        return False, None

def extract_diff_info(json_output: str) -> Dict[str, Any]:
    """Extract diff info from differential-execute output"""
    try:
        data = json.loads(json_output)
    except:
        return {}

    result = {}

    # Handle array - take first element
    if isinstance(data, list):
        if len(data) > 0:
            data = data[0]
        else:
            return {}

    # Extract diff_types (top-level keys in first object if it's a dict)
    if isinstance(data, dict):
        result["diff_types"] = list(data.keys())

        # Extract Status info
        if "Status" in data:
            status_obj = data["Status"]
            result["ossl_error"] = status_obj.get("first_status")
            result["libre_error"] = status_obj.get("second_status")
            result["ossl_steps"] = status_obj.get("first_executed_steps")
            result["libre_steps"] = status_obj.get("second_executed_steps")
            result["total_steps"] = status_obj.get("total_step")

            # Determine first_to_fail
            ossl_s = result.get("ossl_steps")
            libre_s = result.get("libre_steps")
            if ossl_s is not None and libre_s is not None:
                if ossl_s < libre_s:
                    result["first_to_fail"] = "openssl340"
                elif libre_s < ossl_s:
                    result["first_to_fail"] = "libressl421"
                else:
                    result["first_to_fail"] = "same"

        # Extract Knowledges info
        if "Knowledges" in data:
            kn = data["Knowledges"]
            if "InnerDifference" in kn:
                diff_str = str(kn["InnerDifference"])[:100]
                result["knowledge_diff"] = f"Inner:{diff_str}"
            elif "DifferentTypes" in kn:
                dt = kn["DifferentTypes"]
                first_type = dt.get("first_type", "Unknown")
                second_type = dt.get("second_type", "Unknown")
                result["knowledge_diff"] = f"DifferentTypes[{first_type}][{second_type}]"

        # Extract Claims info
        if "Claims" in data:
            cl = data["Claims"]
            if "DifferentTypes" in cl:
                dt = cl["DifferentTypes"]
                first_type = dt.get("first_type", "Unknown")
                second_type = dt.get("second_type", "Unknown")
                result["claim_diff"] = f"DifferentTypes[{first_type}][{second_type}]"
            elif "InnerDifference" in cl:
                diff_str = str(cl["InnerDifference"])[:80]
                result["claim_diff"] = f"Inner:{diff_str}"

    return result

def extract_display_info(json_output: str, put_name: str) -> Dict[str, Any]:
    """Extract display-execute info"""
    try:
        data = json.loads(json_output)
    except:
        return {}

    result = {}

    try:
        # TLS version
        tls_version = data.get("execution", {}).get("agents", [{}])[0].get("protocol_config", {}).get("tls_version")
        if tls_version:
            result["tls_version"] = tls_version

        # Executed until
        eu = data.get("execution", {}).get("executed_until")
        result["executed_until"] = eu

        # Failing input recipe
        if eu is not None and "steps" in data.get("execution", {}):
            steps = data["execution"]["steps"]
            if eu < len(steps):
                step = steps[eu]
                action = step.get("action")
                if isinstance(action, dict) and "Input" in action:
                    recipe = str(action["Input"].get("recipe", ""))[:300]
                    result["failing_input_recipe"] = recipe

        # Claims
        claims_list = []
        steps = data.get("execution", {}).get("steps", [])
        for step in steps:
            step_claims = step.get("claims", [])
            if isinstance(step_claims, list):
                for claim in step_claims:
                    claim_str = str(claim)[:150]
                    claims_list.append(claim_str)
        result["claims"] = claims_list

        # Knowledge types
        knowledge_types = set()
        for step in steps:
            knowledges = step.get("knowledges", [])
            if isinstance(knowledges, list):
                for knowledge in knowledges:
                    kn_str = str(knowledge)
                    # Extract type name (first word before { or ()
                    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", kn_str)
                    if match:
                        knowledge_types.add(match.group(1))

        result["knowledge_types"] = list(knowledge_types)[:10]
    except:
        pass

    return result

def process_trace(trace_path: str) -> Dict[str, Any]:
    """Process a single trace"""
    result = {
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
    success, output = run_cmd([
        str(BINARY), "differential-execute", "--json",
        "openssl340", "libressl421", trace_path
    ])

    if success and output:
        diff_info = extract_diff_info(output)
        result.update(diff_info)
    else:
        result["error"] = "execution_failed"
        return result

    # Step 2: Display execute OSSL
    success, output = run_cmd([
        str(BINARY), "--put", "openssl340",
        "display-execute", "--json", "-t", "-k", "-c", trace_path
    ], skip_log_line=True)

    if success and output:
        ossl_info = extract_display_info(output, "openssl340")
        if "tls_version" in ossl_info and result["tls_version"] is None:
            result["tls_version"] = ossl_info["tls_version"]
        if "failing_input_recipe" in ossl_info:
            result["failing_input_recipe_ossl"] = ossl_info["failing_input_recipe"]
        if "claims" in ossl_info:
            result["claims_ossl"] = ossl_info["claims"]
        if "knowledge_types" in ossl_info:
            result["knowledge_types_ossl"] = ossl_info["knowledge_types"]

    # Step 3: Display execute LibreSSL
    success, output = run_cmd([
        str(BINARY), "--put", "libressl421",
        "display-execute", "--json", "-t", "-k", "-c", trace_path
    ], skip_log_line=True)

    if success and output:
        libre_info = extract_display_info(output, "libressl421")
        if "tls_version" in libre_info and result["tls_version"] is None:
            result["tls_version"] = libre_info["tls_version"]
        if "failing_input_recipe" in libre_info:
            result["failing_input_recipe_libre"] = libre_info["failing_input_recipe"]
        if "claims" in libre_info:
            result["claims_libre"] = libre_info["claims"]
        if "knowledge_types" in libre_info:
            result["knowledge_types_libre"] = libre_info["knowledge_types"]

    return result

def main():
    print(f"Processing {len(TRACES)} traces for batch_05...", file=sys.stderr)

    results = []
    for i, trace in enumerate(TRACES):
        print(f"[{i+1}/{len(TRACES)}] Processing {trace}...", file=sys.stderr)
        trace_result = process_trace(trace)
        results.append(trace_result)

    # Write output
    output_path = BASE_DIR / "triaging-orchestration/state/round_1/batches/batch_05.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results written to {output_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
