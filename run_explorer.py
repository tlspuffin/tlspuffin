#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

BINARY = "./target/release/tlspuffin"
PUT1 = "openssl340"
PUT2 = "libressl421"
WORK_DIR = Path("/home/nbaffou/dev/tlspuffin")

def run_cmd(cmd: list, timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout, or None on timeout/error."""
    try:
        result = subprocess.run(
            cmd,
            cwd=WORK_DIR,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        print(f"Error running {cmd}: {e}", file=sys.stderr)
        return None

def extract_diff_data(json_output: str) -> dict:
    """Extract diff_types, status info, and differences from differential-execute JSON."""
    try:
        data = json.loads(json_output)
        result = {}

        if not isinstance(data, list) or len(data) == 0:
            return {}

        first_obj = data[0]
        diff_types = list(first_obj.keys())
        result["diff_types"] = diff_types

        # Extract Status info
        if "Status" in first_obj:
            status = first_obj["Status"]
            result["ossl_error"] = status.get("first_status", None)
            result["libre_error"] = status.get("second_status", None)
            result["ossl_steps"] = status.get("first_executed_steps", None)
            result["libre_steps"] = status.get("second_executed_steps", None)
            result["total_steps"] = status.get("total_step", None)

            # Determine first_to_fail
            ossl_steps = result.get("ossl_steps")
            libre_steps = result.get("libre_steps")
            if ossl_steps is not None and libre_steps is not None:
                if ossl_steps < libre_steps:
                    result["first_to_fail"] = PUT1
                elif libre_steps < ossl_steps:
                    result["first_to_fail"] = PUT2
                else:
                    result["first_to_fail"] = "same"

        # Extract knowledge differences
        if "Knowledges" in first_obj:
            knowledges = first_obj["Knowledges"]
            if isinstance(knowledges, dict):
                if "InnerDifference" in knowledges:
                    inner_diff = knowledges["InnerDifference"]
                    type_name = inner_diff.get("type_name", "Unknown")
                    diff_text = str(inner_diff.get("diff", ""))[:100]
                    result["knowledge_diff"] = f"Inner[{type_name}]:{diff_text}"
                elif "DifferentTypes" in knowledges:
                    diff_types_info = knowledges["DifferentTypes"]
                    first_type = diff_types_info.get("first_type", "Unknown")
                    second_type = diff_types_info.get("second_type", "Unknown")
                    result["knowledge_diff"] = f"DifferentTypes[{first_type}][{second_type}]"

        # Extract claim differences
        if "Claims" in first_obj:
            claims = first_obj["Claims"]
            if isinstance(claims, dict):
                if "DifferentTypes" in claims:
                    diff_types_info = claims["DifferentTypes"]
                    first_type = diff_types_info.get("first_type", "Unknown")
                    second_type = diff_types_info.get("second_type", "Unknown")
                    result["claim_diff"] = f"DifferentTypes[{first_type}][{second_type}]"
                elif "InnerDifference" in claims:
                    inner_diff = claims["InnerDifference"]
                    diff_text = str(inner_diff.get("diff", ""))[:80]
                    result["claim_diff"] = f"Inner:{diff_text}"

        return result
    except json.JSONDecodeError:
        return {}

def extract_display_data(json_output: str, put: str) -> dict:
    """Extract display-execute data from JSON output."""
    try:
        data = json.loads(json_output)
        result = {}

        # Extract TLS version and executed_until
        if "execution" in data:
            exe = data["execution"]

            # TLS version
            if "agents" in exe and len(exe["agents"]) > 0:
                agent = exe["agents"][0]
                if "protocol_config" in agent:
                    tls_version = agent["protocol_config"].get("tls_version", None)
                    result["tls_version"] = tls_version

            # Executed until
            eu = exe.get("executed_until", None)
            result["executed_until"] = eu

            # Failing input recipe
            recipe = None
            if eu is not None and "steps" in exe:
                steps = exe["steps"]
                if 0 <= eu < len(steps):
                    step = steps[eu]
                    if "action" in step and isinstance(step["action"], dict):
                        if "Input" in step["action"]:
                            recipe_full = step["action"]["Input"].get("recipe", None)
                            if recipe_full:
                                recipe = recipe_full[:300]
            result["failing_input_recipe"] = recipe

            # Claims (flatten all claims from all steps, truncate to 150 chars each)
            claims = []
            if "steps" in exe:
                for step in exe["steps"]:
                    if "claims" in step and isinstance(step["claims"], list):
                        for claim in step["claims"]:
                            claim_str = str(claim)[:150]
                            claims.append(claim_str)
            result["claims"] = claims

            # Knowledge types (extract first word before { or ( from each knowledge string)
            knowledge_types = set()
            if "steps" in exe:
                for step in exe["steps"]:
                    if "knowledges" in step and isinstance(step["knowledges"], list):
                        for knowledge in step["knowledges"]:
                            knowledge_str = str(knowledge)
                            # Extract first word before { or (
                            for sep in ['{', '(']:
                                if sep in knowledge_str:
                                    knowledge_str = knowledge_str.split(sep)[0]
                            knowledge_str = knowledge_str.strip()
                            if knowledge_str:
                                knowledge_types.add(knowledge_str)

            # Limit to 10 distinct types
            result["knowledge_types"] = sorted(list(knowledge_types))[:10]

        return result
    except json.JSONDecodeError:
        return {}

def process_trace(trace_path: str) -> dict:
    """Process a single trace and return structured data."""
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
        "claims_ossl": None,
        "claims_libre": None,
        "knowledge_types_ossl": None,
        "knowledge_types_libre": None,
    }

    print(f"Processing {trace_path}...", file=sys.stderr)

    # Step 1: differential-execute
    diff_cmd = [BINARY, "differential-execute", "--json", PUT1, PUT2, trace_path]
    diff_output = run_cmd(diff_cmd)

    if diff_output:
        diff_data = extract_diff_data(diff_output)
        result.update(diff_data)
    else:
        result["error"] = "differential_failed"
        return result

    # Step 2: display-execute on OSSL
    ossl_cmd = [BINARY, "--put", PUT1, "display-execute", "--json", "-t", "-k", "-c", trace_path]
    ossl_output = run_cmd(ossl_cmd)

    if ossl_output:
        ossl_data = extract_display_data(ossl_output, PUT1)
        if "tls_version" in ossl_data and ossl_data["tls_version"] and not result.get("tls_version"):
            result["tls_version"] = ossl_data["tls_version"]
        result["failing_input_recipe_ossl"] = ossl_data.get("failing_input_recipe")
        result["claims_ossl"] = ossl_data.get("claims")
        result["knowledge_types_ossl"] = ossl_data.get("knowledge_types")

    # Step 3: display-execute on LibreSSL
    libre_cmd = [BINARY, "--put", PUT2, "display-execute", "--json", "-t", "-k", "-c", trace_path]
    libre_output = run_cmd(libre_cmd)

    if libre_output:
        libre_data = extract_display_data(libre_output, PUT2)
        if "tls_version" in libre_data and libre_data["tls_version"] and not result.get("tls_version"):
            result["tls_version"] = libre_data["tls_version"]
        result["failing_input_recipe_libre"] = libre_data.get("failing_input_recipe")
        result["claims_libre"] = libre_data.get("claims")
        result["knowledge_types_libre"] = libre_data.get("knowledge_types")

    return result

def main():
    # Read trace list from batch_01.txt
    batch_file = WORK_DIR / "triaging-orchestration/state/round_2/batches/batch_01.txt"
    traces = []

    with open(batch_file) as f:
        for line in f:
            line = line.strip()
            if line:
                traces.append(line)

    print(f"Processing {len(traces)} traces...", file=sys.stderr)

    results = []
    for i, trace in enumerate(traces, 1):
        print(f"[{i}/{len(traces)}] {trace}", file=sys.stderr)
        result = process_trace(trace)
        results.append(result)

    # Write output JSON
    output_file = WORK_DIR / "triaging-orchestration/state/round_2/batches/batch_01.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Results written to {output_file}", file=sys.stderr)

if __name__ == "__main__":
    main()
