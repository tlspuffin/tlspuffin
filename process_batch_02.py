#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

# Les traces sont dans /home/nbaffou/dev/tlspuffin, mais le binaire est dans /home/nbaffou/dev/tls2/tlspuffin
TRACE_DIR = "/home/nbaffou/dev/tlspuffin"
BINARY_DIR = "/home/nbaffou/dev/tls2/tlspuffin"
BINARY = f"{BINARY_DIR}/target/release/tlspuffin"
TIMEOUT = 30

TRACES = [
    "objective/20260428-215237303-c949a13824ee0797.trace",
    "objective/20260428-215253418-1c2cc9215c8a6184.trace",
    "objective/20260428-215308900-73c38810e4635fc1.trace",
    "objective/20260428-215321854-ff632b1a4b55e51b.trace",
    "objective/20260428-215335418-318628fdda0d64a6.trace",
    "objective/20260428-215350146-9602a060f40a5ae1.trace",
    "objective/20260428-215405125-47ff7b51c45b9f62.trace",
    "objective/20260428-215424102-12a4c630d0446929.trace",
    "objective/20260428-215440029-57463fdf772f787d.trace",
    "objective/20260428-215459151-895070a898103676.trace",
    "objective/20260428-215516772-2a0413df64cee3b8.trace",
    "objective/20260428-215533067-9986d0ce3af97937.trace",
    "objective/20260428-215545586-e3c7239000c1cca6.trace",
    "objective/20260428-215558795-fcb8dab46374e097.trace",
    "objective/20260428-215611159-227ffab95806c603.trace",
    "objective/20260428-215627613-acaa381b53cf7581.trace",
    "objective/20260428-215641582-44430c6fa0ca7167.trace",
    "objective/20260428-215700237-64dd91ad8f87dbf8.trace",
    "objective/20260428-215716322-4fa5b1843676c434.trace",
    "objective/20260428-215732273-a339d9864c5cba4c.trace",
    "objective/20260428-215748049-70f71923d3503b10.trace",
    "objective/20260428-215805343-4ce57aef05ab3677.trace",
    "objective/20260428-215820180-e0ad508dd24bead0.trace",
    "objective/20260428-215834561-aae67761e5028ced.trace",
    "objective/20260428-215848630-c8d4e4ddea845fee.trace",
    "objective/20260428-215901697-72060372aaa43044.trace",
    "objective/20260428-215915658-cb288e06f6a8855c.trace",
    "objective/20260428-215930781-d0c48662894624e4.trace",
    "objective/20260428-215944894-f84b4a85b8ec6f31.trace",
    "objective/20260428-220003132-1b3ea6259b25e9bc.trace",
]

def run_cmd(cmd: List[str], work_dir: str) -> Optional[str]:
    """Run command with timeout, return stdout or None."""
    try:
        result = subprocess.run(
            cmd,
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=TIMEOUT
        )
        return result.stdout if result.returncode == 0 else None
    except subprocess.TimeoutExpired:
        print(f"Timeout on command: {' '.join(cmd)}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error on command: {' '.join(cmd)}: {e}", file=sys.stderr)
        return None

def extract_diff_data(diff_json: Dict) -> Dict[str, Any]:
    """Extract diff data from differential-execute output."""
    result = {}

    # Get diff_types
    result["diff_types"] = list(diff_json.keys()) if isinstance(diff_json, dict) else []

    # Extract status info
    if "Status" in diff_json:
        status = diff_json["Status"]
        result["ossl_error"] = status.get("first_status")
        result["libre_error"] = status.get("second_status")
        result["ossl_steps"] = status.get("first_executed_steps")
        result["libre_steps"] = status.get("second_executed_steps")
        result["total_steps"] = status.get("total_step")

        # Determine first_to_fail
        ossl_s = status.get("first_executed_steps")
        libre_s = status.get("second_executed_steps")
        if ossl_s is not None and libre_s is not None:
            if ossl_s < libre_s:
                result["first_to_fail"] = "openssl340"
            elif libre_s < ossl_s:
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

    # Extract knowledge diff
    result["knowledge_diff"] = None
    if "Knowledges" in diff_json:
        kn = diff_json["Knowledges"]
        if "InnerDifference" in kn:
            diff_text = str(kn["InnerDifference"]).split(":")[0]
            type_name = diff_text.split("{")[0].strip()
            diff_preview = str(kn["InnerDifference"])[:100]
            result["knowledge_diff"] = f"Inner[{type_name}]:{diff_preview}"
        elif "DifferentTypes" in kn:
            dt = kn["DifferentTypes"]
            first_type = str(dt.get("first", "Unknown"))[:50]
            second_type = str(dt.get("second", "Unknown"))[:50]
            result["knowledge_diff"] = f"DifferentTypes[{first_type}][{second_type}]"

    # Extract claim diff
    result["claim_diff"] = None
    if "Claims" in diff_json:
        cl = diff_json["Claims"]
        if "DifferentTypes" in cl:
            dt = cl["DifferentTypes"]
            first_type = str(dt.get("first", "Unknown"))[:50]
            second_type = str(dt.get("second", "Unknown"))[:50]
            result["claim_diff"] = f"DifferentTypes[{first_type}][{second_type}]"
        elif "InnerDifference" in cl:
            diff_preview = str(cl["InnerDifference"])[:80]
            result["claim_diff"] = f"Inner:{diff_preview}"

    return result

def extract_tls_version(display_json: Dict) -> Optional[str]:
    """Extract TLS version from display-execute output."""
    try:
        execution = display_json.get("execution", {})
        agents = execution.get("agents", [])
        if agents:
            config = agents[0].get("protocol_config", {})
            return config.get("tls_version")
    except:
        pass
    return None

def extract_executed_until(display_json: Dict) -> Optional[int]:
    """Extract executed_until index from display-execute output."""
    try:
        execution = display_json.get("execution", {})
        return execution.get("executed_until")
    except:
        pass
    return None

def extract_recipe(display_json: Dict, eu_index: Optional[int]) -> Optional[str]:
    """Extract failing_input_recipe from a step."""
    try:
        if eu_index is None:
            return None
        execution = display_json.get("execution", {})
        steps = execution.get("steps", [])
        if eu_index < len(steps):
            action = steps[eu_index].get("action")
            if isinstance(action, dict) and "Input" in action:
                recipe = action["Input"].get("recipe", "")
                return recipe[:300] if recipe else None
    except:
        pass
    return None

def extract_claims(display_json: Dict) -> List[str]:
    """Extract all claims from all steps."""
    claims = []
    try:
        execution = display_json.get("execution", {})
        steps = execution.get("steps", [])
        for step in steps:
            step_claims = step.get("claims", [])
            for claim in step_claims:
                claim_str = str(claim)[:150]
                claims.append(claim_str)
    except:
        pass
    return claims

def extract_knowledge_types(display_json: Dict) -> List[str]:
    """Extract knowledge type names from all steps."""
    types = set()
    try:
        execution = display_json.get("execution", {})
        steps = execution.get("steps", [])
        for step in steps:
            knowledges = step.get("knowledges", [])
            for knowledge in knowledges:
                kn_str = str(knowledge)
                # Extract first word before { or (
                match = re.match(r"(\w+)", kn_str)
                if match:
                    types.add(match.group(1))
            if len(types) >= 10:
                break
    except:
        pass
    return sorted(list(types))[:10]

def process_trace(trace_path: str) -> Dict[str, Any]:
    """Process a single trace and extract all required data."""
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

    # Convert relative path to absolute path in TRACE_DIR
    abs_trace = os.path.join(TRACE_DIR, trace_path)

    # Step 1: differential-execute (run in BINARY_DIR)
    diff_cmd = [BINARY, "differential-execute", "--json", "openssl340", "libressl421", abs_trace]
    diff_output = run_cmd(diff_cmd, BINARY_DIR)

    if diff_output:
        try:
            diff_json = json.loads(diff_output)
            diff_data = extract_diff_data(diff_json)
            result.update(diff_data)
        except Exception as e:
            print(f"JSON parse error on diff for {trace_path}: {e}", file=sys.stderr)

    if result["diff_types"] is None:
        result["error"] = "timeout"
        return result

    # Step 2: display-execute for OSSL
    ossl_cmd = [BINARY, "--put", "openssl340", "display-execute", "--json", "-t", "-k", "-c", abs_trace]
    ossl_output = run_cmd(ossl_cmd, BINARY_DIR)

    if ossl_output:
        try:
            ossl_json = json.loads(ossl_output)
            tls_ver = extract_tls_version(ossl_json)
            if tls_ver:
                result["tls_version"] = tls_ver

            eu_ossl = extract_executed_until(ossl_json)
            if eu_ossl is not None:
                result["failing_input_recipe_ossl"] = extract_recipe(ossl_json, eu_ossl)

            result["claims_ossl"] = extract_claims(ossl_json)
            result["knowledge_types_ossl"] = extract_knowledge_types(ossl_json)
        except Exception as e:
            print(f"JSON parse error on OSSL display for {trace_path}: {e}", file=sys.stderr)

    # Step 3: display-execute for LibreSSL
    libre_cmd = [BINARY, "--put", "libressl421", "display-execute", "--json", "-t", "-k", "-c", abs_trace]
    libre_output = run_cmd(libre_cmd, BINARY_DIR)

    if libre_output:
        try:
            libre_json = json.loads(libre_output)
            eu_libre = extract_executed_until(libre_json)
            if eu_libre is not None:
                result["failing_input_recipe_libre"] = extract_recipe(libre_json, eu_libre)

            result["claims_libre"] = extract_claims(libre_json)
            result["knowledge_types_libre"] = extract_knowledge_types(libre_json)
        except Exception as e:
            print(f"JSON parse error on LibreSSL display for {trace_path}: {e}", file=sys.stderr)

    return result

def main():
    results = []
    for i, trace in enumerate(TRACES, 1):
        print(f"Processing {i}/{len(TRACES)}: {trace}", file=sys.stderr)
        result = process_trace(trace)
        results.append(result)

    # Write output
    output_path = f"{TRACE_DIR}/triaging-orchestration/state/round_2/batches/batch_02.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Written {len(results)} results to {output_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
