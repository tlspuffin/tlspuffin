#!/usr/bin/env python3
import json
import subprocess
import sys
import os
import re
from pathlib import Path

os.chdir("/home/nbaffou/dev/tlspuffin")

traces = [
    "objective/20260428-214210430-81a30cbb7e042fa3.trace",
    "objective/20260428-214214147-d775465c2f7c0cfd.trace",
    "objective/20260428-214218191-d4015e4e5fdf6196.trace",
    "objective/20260428-214221332-bad820e7801479dc.trace",
    "objective/20260428-214224956-2f3d778375f1e901.trace",
    "objective/20260428-214229111-6a3bd381627f6b3a.trace",
    "objective/20260428-214232683-a900fbc49b017ca4.trace",
    "objective/20260428-214236759-c2606f93f699b494.trace",
    "objective/20260428-214239808-d2073d33a803f591.trace",
    "objective/20260428-214244850-1ae072a71b7f5de0.trace",
    "objective/20260428-214249209-1286749525e25745.trace",
    "objective/20260428-214252625-95fca3d7f30742cf.trace",
    "objective/20260428-214256798-e86a0f3692cea501.trace",
    "objective/20260428-214300844-b8755b8330a04543.trace",
    "objective/20260428-214305505-8d0af3d91aafb5d6.trace",
    "objective/20260428-214308219-b34b2ea477b5f688.trace",
    "objective/20260428-214312357-11f4e949207c4825.trace",
    "objective/20260428-214315298-4709392d2099e0f8.trace",
    "objective/20260428-214318638-9f1589dd60a96d7f.trace",
    "objective/20260428-214322599-abf7f524c536f7ae.trace",
    "objective/20260428-214325963-3d7e309602b2d433.trace",
    "objective/20260428-214329877-d4e1c94b6501b67c.trace",
    "objective/20260428-214333368-f68d716db175936c.trace",
    "objective/20260428-214336420-2003de85a412a3df.trace",
    "objective/20260428-214340688-0f0035faaf21b9a4.trace",
    "objective/20260428-214344492-778bbfacaa6c6daa.trace",
    "objective/20260428-214348567-8649a248b4cbd8d4.trace",
    "objective/20260428-214352485-f5d357cba05f746f.trace",
    "objective/20260428-214356278-0965996ea6d98be3.trace",
    "objective/20260428-214359285-902c319d0f3bfcfe.trace",
]

output_file = "triaging-orchestration/state/round_1/batches/batch_04.json"
results = []

def run_cmd(cmd, timeout=10):
    """Run command with timeout, return output regardless of return code."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout if result.stdout else None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def extract_json(output):
    """Extract JSON from command output."""
    if not output:
        return None
    try:
        return json.loads(output)
    except:
        return None

def extract_diff_types(diff_json):
    """Extract diff_types from differential-execute JSON."""
    if not isinstance(diff_json, list) or len(diff_json) == 0:
        return None
    first_obj = diff_json[0]
    if not isinstance(first_obj, dict):
        return None
    return list(first_obj.keys())

def extract_status_info(diff_json):
    """Extract Status info from differential-execute JSON."""
    if not isinstance(diff_json, list) or len(diff_json) == 0:
        return {}
    first_obj = diff_json[0]
    if "Status" not in first_obj:
        return {}
    status = first_obj["Status"]

    result = {}
    if "first_status" in status:
        result["ossl_error"] = status["first_status"]
    if "second_status" in status:
        result["libre_error"] = status["second_status"]
    if "first_executed_steps" in status:
        result["ossl_steps"] = status["first_executed_steps"]
    if "second_executed_steps" in status:
        result["libre_steps"] = status["second_executed_steps"]
    if "total_step" in status:
        result["total_steps"] = status["total_step"]

    # Determine first_to_fail
    if "ossl_steps" in result and "libre_steps" in result:
        if result["ossl_steps"] < result["libre_steps"]:
            result["first_to_fail"] = "openssl340"
        elif result["libre_steps"] < result["ossl_steps"]:
            result["first_to_fail"] = "libressl421"
        else:
            result["first_to_fail"] = "same"

    return result

def extract_knowledge_diff(diff_json):
    """Extract knowledge_diff from differential-execute JSON."""
    if not isinstance(diff_json, list) or len(diff_json) == 0:
        return None
    first_obj = diff_json[0]
    if "Knowledges" not in first_obj:
        return None

    knowledges = first_obj["Knowledges"]
    if isinstance(knowledges, dict):
        if "InnerDifference" in knowledges:
            diff = str(knowledges["InnerDifference"])[:100]
            type_name = "Unknown"
            return f"Inner[{type_name}]:{diff}"
        elif "DifferentTypes" in knowledges:
            dt = knowledges["DifferentTypes"]
            if isinstance(dt, dict) and "First" in dt and "Second" in dt:
                first_type = str(dt["First"])[:50]
                second_type = str(dt["Second"])[:50]
                return f"DifferentTypes[{first_type}][{second_type}]"

    return None

def extract_claim_diff(diff_json):
    """Extract claim_diff from differential-execute JSON."""
    if not isinstance(diff_json, list) or len(diff_json) == 0:
        return None
    first_obj = diff_json[0]
    if "Claims" not in first_obj:
        return None

    claims = first_obj["Claims"]
    if isinstance(claims, dict):
        if "DifferentTypes" in claims:
            dt = claims["DifferentTypes"]
            if isinstance(dt, dict) and "First" in dt and "Second" in dt:
                first_type = str(dt["First"])[:50]
                second_type = str(dt["Second"])[:50]
                return f"DifferentTypes[{first_type}][{second_type}]"
        elif "InnerDifference" in claims:
            diff = str(claims["InnerDifference"])[:80]
            return f"Inner:{diff}"

    return None

def extract_display_info(display_json, eu_key="executed_until"):
    """Extract info from display-execute JSON."""
    result = {}

    if not display_json:
        return result

    if "execution" not in display_json:
        return result

    exec_obj = display_json["execution"]

    # Extract TLS version
    if "agents" in exec_obj and len(exec_obj["agents"]) > 0:
        agent = exec_obj["agents"][0]
        if "protocol_config" in agent and "tls_version" in agent["protocol_config"]:
            tls_ver = agent["protocol_config"]["tls_version"]
            result["tls_version"] = tls_ver

    # Extract executed_until
    if "executed_until" in exec_obj:
        result["executed_until"] = exec_obj["executed_until"]

    # Extract failing input recipe
    if "executed_until" in exec_obj:
        eu = exec_obj["executed_until"]
        if "steps" in exec_obj and eu < len(exec_obj["steps"]):
            step = exec_obj["steps"][eu]
            if "action" in step and isinstance(step["action"], dict) and "Input" in step["action"]:
                recipe = str(step["action"]["Input"].get("recipe", ""))[:300]
                result["failing_input_recipe"] = recipe

    # Extract claims
    claims_list = []
    if "steps" in exec_obj:
        for step in exec_obj["steps"]:
            if "claims" in step and isinstance(step["claims"], list):
                for claim in step["claims"]:
                    claim_str = str(claim)[:150]
                    claims_list.append(claim_str)
    result["claims"] = claims_list

    # Extract knowledge types
    knowledge_types = set()
    if "steps" in exec_obj:
        for step in exec_obj["steps"]:
            if "knowledges" in step and isinstance(step["knowledges"], list):
                for kn in step["knowledges"]:
                    kn_str = str(kn)
                    # Extract first word before { or (
                    match = re.match(r'(\w+)', kn_str)
                    if match:
                        knowledge_types.add(match.group(1))

    result["knowledge_types"] = list(knowledge_types)[:10]

    return result

# Process each trace
for i, trace_path in enumerate(traces, 1):
    print(f"Processing trace {i}/30: {trace_path}", file=sys.stderr)

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
    cmd = f"./target/release/tlspuffin differential-execute --json openssl340 libressl421 {trace_path}"
    diff_output = run_cmd(cmd)
    diff_json = extract_json(diff_output)

    if diff_json:
        # Extract diff_types
        result["diff_types"] = extract_diff_types(diff_json)

        # Extract status info
        status_info = extract_status_info(diff_json)
        result.update(status_info)

        # Extract knowledge and claim diffs
        result["knowledge_diff"] = extract_knowledge_diff(diff_json)
        result["claim_diff"] = extract_claim_diff(diff_json)
    else:
        if diff_output is None:
            result["error"] = "timeout"
        else:
            result["error"] = "differential_execute_failed"

    # Step 2: Display execute for OSSL
    cmd = f"./target/release/tlspuffin --put openssl340 display-execute --json -t -k -c {trace_path}"
    display_ossl = run_cmd(cmd)
    display_ossl_json = extract_json(display_ossl)

    if display_ossl_json:
        display_info = extract_display_info(display_ossl_json)
        if "tls_version" in display_info:
            result["tls_version"] = display_info["tls_version"]
        if "failing_input_recipe" in display_info:
            result["failing_input_recipe_ossl"] = display_info["failing_input_recipe"]
        if "claims" in display_info:
            result["claims_ossl"] = display_info["claims"]
        if "knowledge_types" in display_info:
            result["knowledge_types_ossl"] = display_info["knowledge_types"]

    # Step 3: Display execute for LibreSSL
    cmd = f"./target/release/tlspuffin --put libressl421 display-execute --json -t -k -c {trace_path}"
    display_libre = run_cmd(cmd)
    display_libre_json = extract_json(display_libre)

    if display_libre_json:
        display_info = extract_display_info(display_libre_json)
        if "failing_input_recipe" in display_info:
            result["failing_input_recipe_libre"] = display_info["failing_input_recipe"]
        if "claims" in display_info:
            result["claims_libre"] = display_info["claims"]
        if "knowledge_types" in display_info:
            result["knowledge_types_libre"] = display_info["knowledge_types"]

    results.append(result)

# Write output
os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"Results written to {output_file}", file=sys.stderr)
