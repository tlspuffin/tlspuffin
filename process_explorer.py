#!/usr/bin/env python3
import json
import subprocess
import sys
import os
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

os.chdir("/home/nbaffou/dev/tlspuffin")

# Trace list
traces = [
    "objective/20260428-213526684-bb31afd1f6ad7284.trace",
    "objective/20260428-213554382-a510b43a2a9585c2.trace",
    "objective/20260428-213613743-4f07c671f06d437c.trace",
    "objective/20260428-213643546-974b6e6688062a1c.trace",
    "objective/20260428-213703096-e041af0330597e62.trace",
    "objective/20260428-213723245-d46620fca62c2992.trace",
    "objective/20260428-213745968-5d5b124166c74e54.trace",
    "objective/20260428-213811054-3fac1c5eb4814f96.trace",
    "objective/20260428-213830792-62044b9bea4f5894.trace",
    "objective/20260428-213847110-d42fb161f7ca31aa.trace",
    "objective/20260428-213904868-6b84240d54c8f137.trace",
    "objective/20260428-213932396-61adb4ca075e0923.trace",
    "objective/20260428-213954436-386393562a6285ab.trace",
    "objective/20260428-214012814-5f10bdc95c4db444.trace",
    "objective/20260428-214032561-e62d455b92bc14e5.trace",
    "objective/20260428-214048475-bf1289177ad20ce6.trace",
    "objective/20260428-214113805-4a335341214dcd17.trace",
    "objective/20260428-214131535-3043f3106fc88672.trace",
    "objective/20260428-214154643-658dacb88fe270eb.trace",
    "objective/20260428-214215096-4020bef1e57fa201.trace",
    "objective/20260428-214234115-da86c98287e90c38.trace",
    "objective/20260428-214303559-2ddd2697a27d6981.trace",
    "objective/20260428-214324026-eb00e54fd2827f73.trace",
    "objective/20260428-214344689-ae603220369ea96e.trace",
    "objective/20260428-214404240-d7dba44a89567b0a.trace",
    "objective/20260428-214422020-5d973007764ea675.trace",
    "objective/20260428-214449278-54d87bbc908d5bcc.trace",
    "objective/20260428-214510178-15270c1642e2e73a.trace",
    "objective/20260428-214531333-aa4240289860c2b6.trace",
    "objective/20260428-214549488-090a8c3e4134485f.trace",
]

def run_command(cmd: List[str], timeout: int = 10) -> Optional[Dict[str, Any]]:
    """Run a command and return parsed JSON output, or None on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return None
        output = result.stdout.strip()
        if not output:
            return None
        return json.loads(output)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return None

def extract_recipe(action: Any, max_len: int = 300) -> Optional[str]:
    """Extract recipe from action if it's an Input dict."""
    if isinstance(action, dict) and "Input" in action:
        recipe = action["Input"].get("recipe", "")
        return recipe[:max_len] if recipe else None
    return None

def extract_type_name(knowledge_str: str) -> Optional[str]:
    """Extract the first word before { or ( from a knowledge string."""
    match = re.match(r'^(\w+)', knowledge_str.strip())
    if match:
        return match.group(1)
    return None

def extract_knowledge_types(execution: Dict[str, Any]) -> List[str]:
    """Extract unique knowledge types from all steps, max 10."""
    types_set = set()
    steps = execution.get("steps", [])
    for step in steps:
        knowledges = step.get("knowledges", [])
        if isinstance(knowledges, list):
            for k_str in knowledges:
                if isinstance(k_str, str):
                    type_name = extract_type_name(k_str)
                    if type_name:
                        types_set.add(type_name)
    # Return sorted list, max 10
    return sorted(list(types_set))[:10]

def extract_claims(execution: Dict[str, Any], max_claim_len: int = 150) -> List[str]:
    """Extract all claims from all steps, truncate each to 150 chars."""
    claims_list = []
    steps = execution.get("steps", [])
    for step in steps:
        claims = step.get("claims", [])
        if isinstance(claims, list):
            for claim_str in claims:
                if isinstance(claim_str, str):
                    claims_list.append(claim_str[:max_claim_len])
    return claims_list

def process_trace(trace_path: str) -> Dict[str, Any]:
    """Process a single trace and return result dict."""
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
        "error": None
    }

    # Step 1: Run differential-execute
    diff_data = run_command(["./target/release/tlspuffin", "differential-execute", "--json", "openssl340", "libressl421", trace_path])

    if diff_data is None:
        result["error"] = "diff_execution_failed"
        return result

    # Extract diff_types and Status/Knowledge/Claims info
    if isinstance(diff_data, dict):
        first_obj = diff_data.get("first", {}) if "first" in diff_data else {}
        diff_types = list(first_obj.keys()) if first_obj else []
        result["diff_types"] = diff_types

        if "Status" in first_obj:
            status_obj = first_obj["Status"]
            result["ossl_error"] = status_obj.get("first_status")
            result["libre_error"] = status_obj.get("second_status")
            result["ossl_steps"] = status_obj.get("first_executed_steps")
            result["libre_steps"] = status_obj.get("second_executed_steps")
            result["total_steps"] = status_obj.get("total_step")

            # Determine first_to_fail
            if result["ossl_steps"] is not None and result["libre_steps"] is not None:
                if result["ossl_steps"] < result["libre_steps"]:
                    result["first_to_fail"] = "openssl340"
                elif result["libre_steps"] < result["ossl_steps"]:
                    result["first_to_fail"] = "libressl421"
                else:
                    result["first_to_fail"] = "same"

        if "Knowledges" in first_obj:
            knowledge_obj = first_obj["Knowledges"]
            if "InnerDifference" in knowledge_obj:
                inner = knowledge_obj["InnerDifference"]
                type_name = inner.get("type_name", "Unknown")
                diff_text = inner.get("diff", "")[:100]
                result["knowledge_diff"] = f"Inner[{type_name}]:{diff_text}"
            elif "DifferentTypes" in knowledge_obj:
                diff_types_obj = knowledge_obj["DifferentTypes"]
                first_t = diff_types_obj.get("first_type", "Unknown")
                second_t = diff_types_obj.get("second_type", "Unknown")
                result["knowledge_diff"] = f"DifferentTypes[{first_t}][{second_t}]"

        if "Claims" in first_obj:
            claims_obj = first_obj["Claims"]
            if "DifferentTypes" in claims_obj:
                diff_types_obj = claims_obj["DifferentTypes"]
                first_t = diff_types_obj.get("first_type", "Unknown")
                second_t = diff_types_obj.get("second_type", "Unknown")
                result["claim_diff"] = f"DifferentTypes[{first_t}][{second_t}]"
            elif "InnerDifference" in claims_obj:
                inner = claims_obj["InnerDifference"]
                diff_text = inner.get("diff", "")[:80]
                result["claim_diff"] = f"Inner:{diff_text}"

    # Step 2: Execute display-execute on OSSL
    ossl_data = run_command(["./target/release/tlspuffin", "--put", "openssl340", "display-execute", "--json", "-t", "-k", "-c", trace_path])

    if ossl_data is not None:
        execution = ossl_data.get("execution", {})

        # Extract tls_version
        agents = execution.get("agents", [])
        if agents and result["tls_version"] is None:
            protocol_config = agents[0].get("protocol_config", {})
            result["tls_version"] = protocol_config.get("tls_version")

        # Extract eu_ossl
        eu_ossl = execution.get("executed_until")

        # Extract failing_input_recipe_ossl
        if eu_ossl is not None:
            steps = execution.get("steps", [])
            if 0 <= eu_ossl < len(steps):
                action = steps[eu_ossl].get("action")
                result["failing_input_recipe_ossl"] = extract_recipe(action)

        # Extract claims and knowledge types
        result["claims_ossl"] = extract_claims(execution)
        result["knowledge_types_ossl"] = extract_knowledge_types(execution)

    # Step 3: Execute display-execute on LibreSSL
    libre_data = run_command(["./target/release/tlspuffin", "--put", "libressl421", "display-execute", "--json", "-t", "-k", "-c", trace_path])

    if libre_data is not None:
        execution = libre_data.get("execution", {})

        # Extract eu_libre
        eu_libre = execution.get("executed_until")

        # Extract failing_input_recipe_libre
        if eu_libre is not None:
            steps = execution.get("steps", [])
            if 0 <= eu_libre < len(steps):
                action = steps[eu_libre].get("action")
                result["failing_input_recipe_libre"] = extract_recipe(action)

        # Extract claims and knowledge types
        result["claims_libre"] = extract_claims(execution)
        result["knowledge_types_libre"] = extract_knowledge_types(execution)

    return result

# Process all traces
results = []
for i, trace in enumerate(traces):
    print(f"Processing trace {i+1}/30: {trace}", file=sys.stderr)
    result = process_trace(trace)
    results.append(result)

# Write output
output_path = "triaging-orchestration/state/round_3/batches/batch_00.json"
with open(output_path, "w") as f:
    json.dump(results, f, indent=2)

print(f"Results written to {output_path}", file=sys.stderr)
