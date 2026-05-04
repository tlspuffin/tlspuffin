#!/usr/bin/env python3
import subprocess
import json
import sys
import re
from pathlib import Path
from typing import Optional, Any, Dict, List

# Configuration
BINARY = "./target/release/tlspuffin"
OSSL = "openssl340"
LIBRE = "libressl421"
WORKDIR = Path("/home/nbaffou/dev/tlspuffin")
TIMEOUT = 10


def run_command(cmd: List[str], timeout: int = TIMEOUT) -> tuple[bool, str]:
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=str(WORKDIR),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        # For JSON commands, stderr may contain logs but stdout should have JSON
        output = result.stdout if result.stdout else result.stderr
        return True, output
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)


def extract_diff_info(json_str: str) -> Dict[str, Any]:
    """Extract info from differential-execute JSON output."""
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

    try:
        data = json.loads(json_str)
        # data is a list of 1 or 2 objects
        if not isinstance(data, list) or len(data) < 1:
            return result

        first_obj = data[0]

        # Extract diff_types
        result["diff_types"] = list(first_obj.keys())

        # Handle Status
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

        # Handle Knowledges
        if "Knowledges" in first_obj:
            know_obj = first_obj["Knowledges"]
            if "InnerDifference" in know_obj:
                diff = know_obj["InnerDifference"].get("diff", "")
                type_name = know_obj["InnerDifference"].get("type_name", "Unknown")
                result["knowledge_diff"] = f"Inner[{type_name}]:{diff[:100]}"
            elif "DifferentTypes" in know_obj:
                dt = know_obj["DifferentTypes"]
                first_type = dt.get("first_type", "?")
                second_type = dt.get("second_type", "?")
                result["knowledge_diff"] = f"DifferentTypes[{first_type}][{second_type}]"

        # Handle Claims
        if "Claims" in first_obj:
            claims_obj = first_obj["Claims"]
            if "DifferentTypes" in claims_obj:
                dt = claims_obj["DifferentTypes"]
                first_type = dt.get("first_type", "?")
                second_type = dt.get("second_type", "?")
                result["claim_diff"] = f"DifferentTypes[{first_type}][{second_type}]"
            elif "InnerDifference" in claims_obj:
                diff = claims_obj["InnerDifference"].get("diff", "")
                result["claim_diff"] = f"Inner:{diff[:80]}"

    except json.JSONDecodeError:
        pass

    return result


def extract_display_info(json_str: str, put_name: str) -> Dict[str, Any]:
    """Extract info from display-execute JSON output."""
    result = {
        "tls_version": None,
        "eu": None,
        "failing_input_recipe": None,
        "claims": [],
        "knowledge_types": [],
    }

    # Try to extract JSON from output (it may be mixed with logs)
    try:
        # Find the JSON part (starts with '{' or '[')
        json_start = json_str.find('{')
        if json_start == -1:
            json_start = json_str.find('[')
        if json_start == -1:
            return result

        # Find the closing bracket
        json_end = json_str.rfind('}')
        if json_end == -1:
            json_end = json_str.rfind(']')
        if json_end == -1:
            return result

        json_str = json_str[json_start:json_end + 1]
        data = json.loads(json_str)
        execution = data.get("execution", {})

        # Get TLS version
        agents = execution.get("agents", [])
        if agents:
            result["tls_version"] = agents[0].get("protocol_config", {}).get("tls_version")

        # Get executed_until
        eu = execution.get("executed_until")
        result["eu"] = eu

        # Get failing_input_recipe
        steps = execution.get("steps", [])
        if eu is not None and 0 <= eu < len(steps):
            step = steps[eu]
            action = step.get("action")
            if isinstance(action, dict) and "Input" in action:
                recipe = action["Input"].get("recipe", "")
                result["failing_input_recipe"] = recipe[:300] if recipe else None

        # Collect claims
        claims_set = []
        for step in steps:
            claims = step.get("claims", [])
            for claim in claims:
                if isinstance(claim, str):
                    claims_set.append(claim[:150])
        result["claims"] = claims_set

        # Collect knowledge types
        types_set = set()
        for step in steps:
            knowledges = step.get("knowledges", [])
            for know in knowledges:
                if isinstance(know, str):
                    # Extract type name: first word before '{' or '('
                    match = re.match(r"(\w+)", know)
                    if match:
                        type_name = match.group(1)
                        types_set.add(type_name)
        result["knowledge_types"] = sorted(list(types_set))[:10]

    except json.JSONDecodeError:
        pass

    return result


def process_trace(trace_path: str) -> Dict[str, Any]:
    """Process a single trace."""
    output = {
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

    # 1. Run differential-execute
    cmd = [BINARY, "differential-execute", "--json", OSSL, LIBRE, trace_path]
    success, diff_output = run_command(cmd)

    if not success:
        output["error"] = "timeout" if "TIMEOUT" in diff_output else "execution_failed"
        return output

    # Extract diff info
    diff_info = extract_diff_info(diff_output)
    output.update(diff_info)

    # 2. Run display-execute for OSSL
    cmd_ossl = [BINARY, "--put", OSSL, "display-execute", "--json", "-t", "-k", "-c", trace_path]
    success_ossl, ossl_output = run_command(cmd_ossl)

    if success_ossl:
        ossl_info = extract_display_info(ossl_output, OSSL)
        output["tls_version"] = ossl_info["tls_version"]
        output["failing_input_recipe_ossl"] = ossl_info["failing_input_recipe"]
        output["claims_ossl"] = ossl_info["claims"]
        output["knowledge_types_ossl"] = ossl_info["knowledge_types"]

    # 3. Run display-execute for LibreSSL
    cmd_libre = [BINARY, "--put", LIBRE, "display-execute", "--json", "-t", "-k", "-c", trace_path]
    success_libre, libre_output = run_command(cmd_libre)

    if success_libre:
        libre_info = extract_display_info(libre_output, LIBRE)
        output["failing_input_recipe_libre"] = libre_info["failing_input_recipe"]
        output["claims_libre"] = libre_info["claims"]
        output["knowledge_types_libre"] = libre_info["knowledge_types"]

    return output


def main():
    # Read traces from stdin or file
    trace_list = []
    with open("/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_3/batches/batch_03.txt") as f:
        for line in f:
            line = line.strip()
            if line:
                trace_list.append(line)

    print(f"Processing {len(trace_list)} traces...", file=sys.stderr)

    results = []
    for i, trace in enumerate(trace_list):
        print(f"[{i + 1}/{len(trace_list)}] Processing {trace}...", file=sys.stderr)
        result = process_trace(trace)
        results.append(result)

    # Write output
    output_file = Path("/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_3/batches/batch_03.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results written to {output_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
