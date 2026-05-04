#!/usr/bin/env python3
import json
import subprocess
import sys
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import signal

TIMEOUT = 10
BINARY = "/home/nbaffou/dev/tlspuffin/target/release/tlspuffin"
TRACES_FILE = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_4/batches/batch_01.txt"
OUTPUT_FILE = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_4/batches/batch_01.json"


def read_traces() -> List[str]:
    """Read trace paths from input file."""
    with open(TRACES_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def run_command(cmd: List[str], timeout: int = TIMEOUT) -> Optional[Dict[str, Any]]:
    """Run a command and return parsed JSON output, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/home/nbaffou/dev/tlspuffin"
        )
        # Check both stdout and stderr for JSON output (commands may exit with non-zero but still output JSON)
        output = result.stdout.strip() or result.stderr.strip()
        if output:
            # Filter out non-JSON output lines (e.g., warnings)
            # Find the first '[' or '{' to skip any preamble
            start_idx = -1
            for i, c in enumerate(output):
                if c in '[{':
                    start_idx = i
                    break
            if start_idx >= 0:
                output = output[start_idx:]
                return json.loads(output)
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        return None


def extract_diff_types(obj: Dict[str, Any]) -> List[str]:
    """Extract top-level keys from object."""
    return list(obj.keys()) if obj else []


def extract_status_info(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Extract status information from diff output."""
    result = {}
    if "Status" in obj and obj["Status"]:
        status = obj["Status"]
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

    return result


def extract_knowledge_diff(obj: Dict[str, Any]) -> Optional[str]:
    """Extract knowledge difference from diff output."""
    if "Knowledges" not in obj or not obj["Knowledges"]:
        return None

    kn = obj["Knowledges"]
    if "InnerDifference" in kn and kn["InnerDifference"]:
        inner = kn["InnerDifference"]
        type_name = inner.get("type_name", "Unknown")
        diff = inner.get("diff", "")
        diff_short = diff[:100] if diff else ""
        return f"Inner[{type_name}]:{diff_short}"

    if "DifferentTypes" in kn and kn["DifferentTypes"]:
        dt = kn["DifferentTypes"]
        first_type = dt.get("first_type", "Unknown")
        second_type = dt.get("second_type", "Unknown")
        return f"DifferentTypes[{first_type}][{second_type}]"

    return None


def extract_claim_diff(obj: Dict[str, Any]) -> Optional[str]:
    """Extract claim difference from diff output."""
    if "Claims" not in obj or not obj["Claims"]:
        return None

    claims = obj["Claims"]
    if "DifferentTypes" in claims and claims["DifferentTypes"]:
        dt = claims["DifferentTypes"]
        first_type = dt.get("first_type", "Unknown")
        second_type = dt.get("second_type", "Unknown")
        return f"DifferentTypes[{first_type}][{second_type}]"

    if "InnerDifference" in claims and claims["InnerDifference"]:
        inner = claims["InnerDifference"]
        diff = inner.get("diff", "")
        diff_short = diff[:80] if diff else ""
        return f"Inner:{diff_short}"

    return None


def extract_tls_version(exec_json: Optional[Dict[str, Any]]) -> Optional[str]:
    """Extract TLS version from display-execute output."""
    if not exec_json:
        return None
    try:
        exec_data = exec_json.get("execution", {})
        agents = exec_data.get("agents", [])
        if agents:
            return agents[0].get("protocol_config", {}).get("tls_version")
    except (KeyError, IndexError, TypeError):
        pass
    return None


def extract_executed_until(exec_json: Optional[Dict[str, Any]]) -> Optional[int]:
    """Extract executed_until from display-execute output."""
    if not exec_json:
        return None
    try:
        return exec_json.get("execution", {}).get("executed_until")
    except (KeyError, TypeError):
        pass
    return None


def extract_failing_recipe(exec_json: Optional[Dict[str, Any]], eu: Optional[int]) -> Optional[str]:
    """Extract failing input recipe from display-execute output."""
    if not exec_json or eu is None:
        return None
    try:
        exec_data = exec_json.get("execution", {})
        steps = exec_data.get("steps", [])
        if 0 <= eu < len(steps):
            step = steps[eu]
            action = step.get("action")
            if isinstance(action, dict) and "Input" in action:
                recipe = action["Input"].get("recipe", "")
                return recipe[:300] if recipe else None
    except (KeyError, IndexError, TypeError):
        pass
    return None


def extract_claims(exec_json: Optional[Dict[str, Any]]) -> List[str]:
    """Extract and flatten all claims from display-execute output."""
    if not exec_json:
        return []

    claims = []
    try:
        exec_data = exec_json.get("execution", {})
        steps = exec_data.get("steps", [])
        for step in steps:
            step_claims = step.get("claims", [])
            if isinstance(step_claims, list):
                for claim in step_claims:
                    if isinstance(claim, str):
                        claims.append(claim[:150])
    except (KeyError, IndexError, TypeError):
        pass

    return claims


def extract_knowledge_types(exec_json: Optional[Dict[str, Any]]) -> List[str]:
    """Extract knowledge types from display-execute output."""
    if not exec_json:
        return []

    types = set()
    try:
        exec_data = exec_json.get("execution", {})
        steps = exec_data.get("steps", [])
        for step in steps:
            knowledges = step.get("knowledges", [])
            if isinstance(knowledges, list):
                for kn_str in knowledges:
                    if isinstance(kn_str, str):
                        # Extract type name: first word before '{' or '('
                        match = re.match(r'(\w+)', kn_str)
                        if match:
                            type_name = match.group(1)
                            types.add(type_name)
    except (KeyError, IndexError, TypeError):
        pass

    # Return up to 10 distinct types
    return sorted(list(types))[:10]


def process_trace(trace_path: str) -> Dict[str, Any]:
    """Process a single trace and extract all required information."""
    result = {"trace": trace_path}

    # Step 1: differential-execute
    diff_cmd = [
        BINARY,
        "differential-execute",
        "--json",
        "openssl340",
        "libressl421",
        trace_path
    ]
    diff_output_raw = run_command(diff_cmd)

    if diff_output_raw is None:
        result["error"] = "execution_failed"
        for key in ["tls_version", "diff_types", "ossl_error", "libre_error",
                    "ossl_steps", "libre_steps", "total_steps", "first_to_fail",
                    "knowledge_diff", "claim_diff", "failing_input_recipe_ossl",
                    "failing_input_recipe_libre", "claims_ossl", "claims_libre",
                    "knowledge_types_ossl", "knowledge_types_libre"]:
            result[key] = None
        return result

    # The differential-execute returns an array; take the first element
    diff_output = diff_output_raw[0] if isinstance(diff_output_raw, list) and len(
        diff_output_raw) > 0 else diff_output_raw

    # Extract diff information
    result["diff_types"] = extract_diff_types(diff_output)
    status_info = extract_status_info(diff_output)
    result.update(status_info)
    result["knowledge_diff"] = extract_knowledge_diff(diff_output)
    result["claim_diff"] = extract_claim_diff(diff_output)

    # Step 2: display-execute on OSSL
    ossl_cmd = [
        BINARY,
        "--put", "openssl340",
        "display-execute",
        "--json",
        "-t", "-k", "-c",
        trace_path
    ]
    ossl_output = run_command(ossl_cmd)

    # Step 3: display-execute on LibreSSL
    libre_cmd = [
        BINARY,
        "--put", "libressl421",
        "display-execute",
        "--json",
        "-t", "-k", "-c",
        trace_path
    ]
    libre_output = run_command(libre_cmd)

    # Extract TLS version (from either output)
    if result.get("tls_version") is None:
        result["tls_version"] = extract_tls_version(ossl_output) or extract_tls_version(libre_output)

    # Extract OSSL info
    eu_ossl = extract_executed_until(ossl_output)
    result["failing_input_recipe_ossl"] = extract_failing_recipe(ossl_output, eu_ossl)
    result["claims_ossl"] = extract_claims(ossl_output)
    result["knowledge_types_ossl"] = extract_knowledge_types(ossl_output)

    # Extract LibreSSL info
    eu_libre = extract_executed_until(libre_output)
    result["failing_input_recipe_libre"] = extract_failing_recipe(libre_output, eu_libre)
    result["claims_libre"] = extract_claims(libre_output)
    result["knowledge_types_libre"] = extract_knowledge_types(libre_output)

    return result


def main():
    traces = read_traces()
    print(f"Processing {len(traces)} traces...", file=sys.stderr)

    results = []
    for i, trace in enumerate(traces, 1):
        print(f"[{i}/{len(traces)}] Processing {trace}...", file=sys.stderr)
        result = process_trace(trace)
        results.append(result)

    # Write output
    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Output written to {OUTPUT_FILE}", file=sys.stderr)


if __name__ == "__main__":
    main()
