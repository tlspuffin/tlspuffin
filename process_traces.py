#!/usr/bin/env python3
import subprocess
import json
import re
import sys
from pathlib import Path

# List of traces to process
traces = [
    "objective/20260428-225813278-d1c0d65ff822da71.trace",
    "objective/20260428-225836338-9d8a962ad48c847c.trace",
    "objective/20260428-225907129-30832b69f43c1a87.trace",
    "objective/20260428-225937891-dad477e91c9acfcf.trace",
    "objective/20260428-230010062-85ca7686d09abf86.trace",
    "objective/20260428-230039139-ab7258c09aa64db7.trace",
    "objective/20260428-230115452-108193cc56caca73.trace",
    "objective/20260428-230146194-396ddb5486276781.trace",
    "objective/20260428-230220159-86d1ec211246936c.trace",
    "objective/20260428-230252966-1562b274b9165093.trace",
    "objective/20260428-230333273-07f340b067ec8428.trace",
    "objective/20260428-230353270-e933379b4d96a8c3.trace",
    "objective/20260428-230409551-df78ce51dd50b6b9.trace",
    "objective/20260428-230434816-9b39ad21baf17075.trace",
    "objective/20260428-230512280-1aa8fcb6e5bac445.trace",
    "objective/20260428-230542087-9369bd8e0f8cfb2d.trace",
    "objective/20260428-230618913-bd508f23e2cde2d4.trace",
    "objective/20260428-230704009-cbe1f036596c785c.trace",
    "objective/20260428-230743609-067704d5be843bf7.trace",
    "objective/20260428-230815366-5ebbf16b4d0c8fab.trace",
    "objective/20260428-230842797-b17b48d84d02a626.trace",
    "objective/20260428-230918512-21e1b03bdfe510b4.trace",
    "objective/20260428-230959323-40f247ceaf4c3afd.trace",
    "objective/20260428-231037758-e2f920fe43d2d889.trace",
    "objective/20260428-231136004-bb75af6b18093239.trace",
    "objective/20260428-231208580-132ff3962161373c.trace",
    "objective/20260428-231232983-2794199cb6e3cd0e.trace",
    "objective/20260428-231333990-4dfe4d30663149cc.trace",
    "objective/20260428-231400628-3bb7cde9f19a3714.trace",
    "objective/20260428-231447528-8bbc70b571e7c82e.trace",
]

def extract_diff_info(diff_json):
    """Extract diff information from differential-execute output."""
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
    
    # diff_json is an array of objects. We need the first object
    if not diff_json or not isinstance(diff_json, list) or len(diff_json) == 0:
        return result
    
    first_obj = diff_json[0]
    if not isinstance(first_obj, dict):
        return result
    
    # Get diff_types from keys in the first object
    diff_types = list(first_obj.keys())
    result["diff_types"] = diff_types
    
    # Extract Status info
    if "Status" in first_obj and isinstance(first_obj["Status"], dict):
        status = first_obj["Status"]
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
    
    # Extract Knowledges info
    if "Knowledges" in first_obj and isinstance(first_obj["Knowledges"], dict):
        knowledges = first_obj["Knowledges"]
        if "InnerDifference" in knowledges:
            inner_diff = knowledges["InnerDifference"]
            if isinstance(inner_diff, dict):
                type_name = inner_diff.get("type_name", "Unknown")
                diff_text = str(inner_diff.get("diff", ""))
                result["knowledge_diff"] = f"Inner[{type_name.split('::')[-1]}]:{diff_text[:100]}"
        elif "DifferentTypes" in knowledges:
            dt = knowledges["DifferentTypes"]
            if isinstance(dt, list) and len(dt) >= 2:
                result["knowledge_diff"] = f"DifferentTypes[{dt[0]}][{dt[1]}]"
    
    # Extract Claims info
    if "Claims" in first_obj and isinstance(first_obj["Claims"], dict):
        claims = first_obj["Claims"]
        if "DifferentTypes" in claims:
            dt = claims["DifferentTypes"]
            if isinstance(dt, list) and len(dt) >= 2:
                result["claim_diff"] = f"DifferentTypes[{dt[0]}][{dt[1]}]"
        elif "InnerDifference" in claims:
            inner_diff = claims["InnerDifference"]
            if isinstance(inner_diff, dict):
                diff_text = str(inner_diff.get("diff", ""))
                result["claim_diff"] = f"Inner:{diff_text[:80]}"
    
    return result

def extract_type_names(knowledges_list):
    """Extract type names from knowledge strings."""
    types_set = set()
    for knowledge_str in knowledges_list:
        # Find first word before { or (
        match = re.match(r'(\w+)[\{(\[]', knowledge_str)
        if match:
            types_set.add(match.group(1))
    return list(types_set)[:10]  # Max 10 types

def extract_display_info(display_json, eu_key):
    """Extract display-execute information."""
    result = {
        "tls_version": None,
        "eu": None,
        "failing_input_recipe": None,
        "claims": [],
        "knowledge_types": [],
    }
    
    if not display_json or not isinstance(display_json, dict):
        return result
    
    execution = display_json.get("execution")
    if not execution:
        return result
    
    # Extract TLS version
    agents = execution.get("agents", [])
    if agents and isinstance(agents[0], dict):
        config = agents[0].get("protocol_config", {})
        result["tls_version"] = config.get("tls_version")
    
    # Extract executed_until
    eu = execution.get("executed_until")
    result["eu"] = eu
    
    # Extract failing input recipe
    steps = execution.get("steps", [])
    if eu is not None and 0 <= eu < len(steps):
        step = steps[eu]
        if isinstance(step, dict):
            action = step.get("action")
            if isinstance(action, dict) and "Input" in action:
                recipe = action["Input"].get("recipe", "")
                result["failing_input_recipe"] = recipe[:300]
    
    # Extract claims
    all_claims = []
    for step in steps:
        if isinstance(step, dict):
            step_claims = step.get("claims", [])
            if isinstance(step_claims, list):
                for claim in step_claims:
                    claim_str = str(claim)[:150]
                    all_claims.append(claim_str)
    result["claims"] = all_claims
    
    # Extract knowledge types
    all_knowledges = []
    for step in steps:
        if isinstance(step, dict):
            knowledges = step.get("knowledges", [])
            if isinstance(knowledges, list):
                all_knowledges.extend(knowledges)
    result["knowledge_types"] = extract_type_names(all_knowledges)
    
    return result

def process_trace(trace_path):
    """Process a single trace and return its analysis."""
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
    
    try:
        # Step 1: Differential execute
        cmd = ["./target/release/tlspuffin", "differential-execute", "--json", "openssl340", "libressl421", trace_path]
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd="/home/nbaffou/dev/tlspuffin")
        
        # NOTE: differential-execute returns exit code 1 on differences, but that's OK
        # We only care if stdout is valid JSON
        try:
            diff_json = json.loads(output.stdout)
            diff_info = extract_diff_info(diff_json)
            result.update(diff_info)
        except json.JSONDecodeError:
            result["error"] = "diff_json_error"
            return result
        
        # Step 2: Display on OSSL
        cmd = ["./target/release/tlspuffin", "--put", "openssl340", "display-execute", "--json", "-t", "-k", "-c", trace_path]
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd="/home/nbaffou/dev/tlspuffin")
        
        if output.returncode == 0:
            try:
                display_json = json.loads(output.stdout)
                ossl_info = extract_display_info(display_json, "eu")
                result["tls_version"] = ossl_info["tls_version"]
                result["failing_input_recipe_ossl"] = ossl_info["failing_input_recipe"]
                result["claims_ossl"] = ossl_info["claims"]
                result["knowledge_types_ossl"] = ossl_info["knowledge_types"]
            except json.JSONDecodeError:
                pass  # Just skip this PUT if JSON fails
        
        # Step 3: Display on LibreSSL
        cmd = ["./target/release/tlspuffin", "--put", "libressl421", "display-execute", "--json", "-t", "-k", "-c", trace_path]
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd="/home/nbaffou/dev/tlspuffin")
        
        if output.returncode == 0:
            try:
                display_json = json.loads(output.stdout)
                libre_info = extract_display_info(display_json, "eu")
                result["failing_input_recipe_libre"] = libre_info["failing_input_recipe"]
                result["claims_libre"] = libre_info["claims"]
                result["knowledge_types_libre"] = libre_info["knowledge_types"]
            except json.JSONDecodeError:
                pass  # Just skip this PUT if JSON fails
        
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:50]
    
    return result

# Process all traces
results = []
for i, trace in enumerate(traces):
    print(f"Processing {i+1}/{len(traces)}: {trace}", file=sys.stderr)
    result = process_trace(trace)
    results.append(result)

# Write output
output_path = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_2/batches/batch_09.json"
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2)

print(f"Output written to {output_path}", file=sys.stderr)
