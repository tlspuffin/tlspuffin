#!/usr/bin/env python3
"""
Explorer script for round 3 batches 01-09.
Processes each trace in a batch and generates the JSON output.
"""

import json
import subprocess
import sys
import os
import re
from typing import Optional, List, Dict, Any
from pathlib import Path

BASE_DIR = Path("/home/nbaffou/dev/tlspuffin")
BINARY = BASE_DIR / "target/release/tlspuffin"
BATCH_DIR = BASE_DIR / "triaging-orchestration/state/round_3/batches"

def read_batch_traces(batch_num: int) -> List[str]:
    """Read traces from batch_XX.txt"""
    batch_file = BATCH_DIR / f"batch_{batch_num:02d}.txt"
    if not batch_file.exists():
        print(f"ERROR: {batch_file} not found")
        return []

    with open(batch_file) as f:
        traces = [line.strip() for line in f if line.strip()]
    return traces

def run_command(cmd: List[str], timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout, or None on failure/timeout"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(BASE_DIR)
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        print(f"Command error: {e}")
        return None

def extract_json_value(json_str: Optional[str], *keys) -> Any:
    """Safely extract a value from JSON using a path of keys"""
    if not json_str:
        return None
    try:
        data = json.loads(json_str)
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key)
            elif isinstance(data, list) and isinstance(key, int):
                data = data[key] if key < len(data) else None
            else:
                return None
            if data is None:
                return None
        return data
    except:
        return None

def parse_diff_execution(trace_path: str) -> Dict[str, Any]:
    """Execute differential-execute and extract fields"""
    result = {
        "diff_types": None,
        "ossl_error": None,
        "libre_error": None,
        "ossl_steps": None,
        "libre_steps": None,
        "total_steps": None,
        "first_to_fail": None,
        "knowledge_diff": None,
        "claim_diff": None,
    }

    cmd = [str(BINARY), "differential-execute", "--json", "openssl340", "libressl421", trace_path]
    output = run_command(cmd)

    if not output:
        result["error"] = "diff_execution_failed"
        return result

    try:
        data = json.loads(output)

        # Extract diff_types (top-level keys of first object)
        if isinstance(data, dict):
            result["diff_types"] = list(data.keys())

            # Handle Status
            if "Status" in data:
                status_data = data["Status"]
                result["ossl_error"] = status_data.get("first_status")
                result["libre_error"] = status_data.get("second_status")
                result["ossl_steps"] = status_data.get("first_executed_steps")
                result["libre_steps"] = status_data.get("second_executed_steps")
                result["total_steps"] = status_data.get("total_step")

                # Determine first_to_fail
                if result["ossl_steps"] is not None and result["libre_steps"] is not None:
                    if result["ossl_steps"] < result["libre_steps"]:
                        result["first_to_fail"] = "openssl340"
                    elif result["libre_steps"] < result["ossl_steps"]:
                        result["first_to_fail"] = "libressl421"
                    else:
                        result["first_to_fail"] = "same"

            # Handle Knowledges
            if "Knowledges" in data:
                kg_data = data["Knowledges"]
                if "InnerDifference" in kg_data:
                    inner = kg_data["InnerDifference"]
                    type_name = inner.get("type_name", "Unknown")
                    diff = inner.get("diff", "")[:100]
                    result["knowledge_diff"] = f"Inner[{type_name}]:{diff}"
                elif "DifferentTypes" in kg_data:
                    dt = kg_data["DifferentTypes"]
                    first_type = dt.get("first_type", "Unknown")
                    second_type = dt.get("second_type", "Unknown")
                    result["knowledge_diff"] = f"DifferentTypes[{first_type}][{second_type}]"

            # Handle Claims
            if "Claims" in data:
                claim_data = data["Claims"]
                if "DifferentTypes" in claim_data:
                    dt = claim_data["DifferentTypes"]
                    first_type = dt.get("first_type", "Unknown")
                    second_type = dt.get("second_type", "Unknown")
                    result["claim_diff"] = f"DifferentTypes[{first_type}][{second_type}]"
                elif "InnerDifference" in claim_data:
                    inner = claim_data["InnerDifference"]
                    diff = inner.get("diff", "")[:80]
                    result["claim_diff"] = f"Inner:{diff}"

    except Exception as e:
        result["error"] = "diff_execution_failed"

    return result

def parse_display_execution(put: str, trace_path: str) -> Dict[str, Any]:
    """Execute display-execute and extract fields"""
    result = {
        "tls_version": None,
        "eu": None,
        "failing_input_recipe": None,
        "claims": [],
        "knowledge_types": [],
    }

    cmd = [str(BINARY), "--put", put, "display-execute", "--json", "-t", "-k", "-c", trace_path]
    output = run_command(cmd)

    if not output:
        return result

    try:
        data = json.loads(output)

        # Extract tls_version
        exec_data = data.get("execution", {})
        agents = exec_data.get("agents", [])
        if agents:
            tls_ver = agents[0].get("protocol_config", {}).get("tls_version")
            result["tls_version"] = tls_ver

        # Extract executed_until
        eu = exec_data.get("executed_until")
        result["eu"] = eu

        # Extract failing_input_recipe
        if eu is not None:
            steps = exec_data.get("steps", [])
            if eu < len(steps):
                step = steps[eu]
                action = step.get("action", {})
                if isinstance(action, dict) and "Input" in action:
                    recipe = action["Input"].get("recipe", "")[:300]
                    result["failing_input_recipe"] = recipe

        # Extract claims
        claims_list = []
        steps = exec_data.get("steps", [])
        for step in steps:
            claims = step.get("claims", [])
            for claim in claims:
                claim_str = str(claim)[:150]
                claims_list.append(claim_str)
        result["claims"] = claims_list

        # Extract knowledge_types
        knowledge_types = set()
        for step in steps:
            knowledges = step.get("knowledges", [])
            for kg in knowledges:
                if isinstance(kg, str):
                    # Extract type name (first word before { or ()
                    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", kg)
                    if match:
                        knowledge_types.add(match.group(1))
        result["knowledge_types"] = list(knowledge_types)[:10]

    except Exception as e:
        pass

    return result

def process_trace(trace_path: str) -> Dict[str, Any]:
    """Process a single trace and return the result object"""
    record = {
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
    diff_result = parse_diff_execution(trace_path)
    if "error" in diff_result:
        record["error"] = diff_result["error"]
        return record

    record.update(diff_result)

    # Step 2: Display execute for OSSL
    ossl_result = parse_display_execution("openssl340", trace_path)
    if not record["tls_version"] and ossl_result["tls_version"]:
        record["tls_version"] = ossl_result["tls_version"]
    record["ossl_steps"] = ossl_result["eu"]
    record["failing_input_recipe_ossl"] = ossl_result["failing_input_recipe"]
    record["claims_ossl"] = ossl_result["claims"]
    record["knowledge_types_ossl"] = ossl_result["knowledge_types"]

    # Step 3: Display execute for LibreSSL
    libre_result = parse_display_execution("libressl421", trace_path)
    record["failing_input_recipe_libre"] = libre_result["failing_input_recipe"]
    record["claims_libre"] = libre_result["claims"]
    record["knowledge_types_libre"] = libre_result["knowledge_types"]

    # Clean up null error field if no error
    if "error" not in record:
        pass

    return record

def process_batch(batch_num: int):
    """Process a single batch and write the JSON output"""
    print(f"Processing batch {batch_num:02d}...")

    traces = read_batch_traces(batch_num)
    if not traces:
        print(f"No traces found for batch {batch_num:02d}")
        return

    results = []
    for i, trace in enumerate(traces, 1):
        print(f"  [{i}/{len(traces)}] Processing {trace}...", end="", flush=True)
        try:
            result = process_trace(trace)
            results.append(result)
            print(" OK")
        except Exception as e:
            print(f" ERROR: {e}")
            result = {
                "trace": trace,
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
                "error": "processing_failed"
            }
            results.append(result)

    # Write output JSON
    output_file = BATCH_DIR / f"batch_{batch_num:02d}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Wrote {output_file}")

if __name__ == "__main__":
    # Process batches 01-09
    for batch_num in range(1, 10):
        process_batch(batch_num)
        print()
