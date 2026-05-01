#!/usr/bin/env python3
import subprocess
import json
import sys
import re
from pathlib import Path

def extract_json_output(cmd_output):
    """Extract JSON from command output"""
    try:
        lines = cmd_output.strip().split('\n')
        json_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith('{') or line.strip().startswith('['):
                json_start = i
                break
        if json_start is not None:
            json_str = '\n'.join(lines[json_start:])
            return json.loads(json_str)
    except Exception as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
    return None

def run_command(cmd, timeout=10):
    """Run command with timeout"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.returncode
    except subprocess.TimeoutExpired:
        return None, -1
    except Exception as e:
        print(f"Error running command: {e}", file=sys.stderr)
        return None, -1

def extract_type_name(knowledge_str):
    """Extract type name from knowledge string"""
    match = re.match(r'^(\w+)', knowledge_str)
    if match:
        return match.group(1)
    return None

def process_trace(trace_path):
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
        "knowledge_types_libre": []
    }

    # Step 1: Differential execute
    cmd = f"./target/release/tlspuffin differential-execute --json openssl340 libressl421 {trace_path}"
    output, rc = run_command(cmd, timeout=10)

    if output is None or rc != 0:
        result["error"] = "timeout" if rc == -1 else "execution_failed"
        return result

    diff_json = extract_json_output(output)
    if not diff_json:
        result["error"] = "execution_failed"
        return result

    # Extract diff info
    if isinstance(diff_json, dict):
        diff_types = list(diff_json.keys())
        result["diff_types"] = diff_types

        if "Status" in diff_json:
            status_obj = diff_json["Status"]
            result["ossl_error"] = status_obj.get("first_status")
            result["libre_error"] = status_obj.get("second_status")
            result["ossl_steps"] = status_obj.get("first_executed_steps")
            result["libre_steps"] = status_obj.get("second_executed_steps")
            result["total_steps"] = status_obj.get("total_step")

            if result["ossl_steps"] is not None and result["libre_steps"] is not None:
                if result["ossl_steps"] < result["libre_steps"]:
                    result["first_to_fail"] = "openssl340"
                elif result["libre_steps"] < result["ossl_steps"]:
                    result["first_to_fail"] = "libressl421"
                else:
                    result["first_to_fail"] = "same"

        if "Knowledges" in diff_json:
            kn_obj = diff_json["Knowledges"]
            if "InnerDifference" in kn_obj:
                diff_str = str(kn_obj["InnerDifference"]).replace('"', '')[:100]
                result["knowledge_diff"] = f"Inner[...]: {diff_str}"
            elif "DifferentTypes" in kn_obj:
                dt = kn_obj["DifferentTypes"]
                first_type = list(dt.keys())[0] if dt else "unknown"
                second_type = list(dt[first_type].keys())[0] if dt and first_type in dt and dt[first_type] else "unknown"
                result["knowledge_diff"] = f"DifferentTypes[{first_type}][{second_type}]"

        if "Claims" in diff_json:
            cl_obj = diff_json["Claims"]
            if "DifferentTypes" in cl_obj:
                dt = cl_obj["DifferentTypes"]
                first_type = list(dt.keys())[0] if dt else "unknown"
                second_type = list(dt[first_type].keys())[0] if dt and first_type in dt and dt[first_type] else "unknown"
                result["claim_diff"] = f"DifferentTypes[{first_type}][{second_type}]"
            elif "InnerDifference" in cl_obj:
                diff_str = str(cl_obj["InnerDifference"])[:80]
                result["claim_diff"] = f"Inner: {diff_str}"

    # Step 2: Display execute on OSSL
    cmd_ossl = f"./target/release/tlspuffin --put openssl340 display-execute --json -t -k -c {trace_path}"
    output_ossl, rc_ossl = run_command(cmd_ossl, timeout=10)

    if output_ossl and rc_ossl == 0:
        ossl_json = extract_json_output(output_ossl)
        if ossl_json and "execution" in ossl_json:
            exec_obj = ossl_json["execution"]

            # Extract TLS version
            if "agents" in exec_obj and len(exec_obj["agents"]) > 0:
                agent = exec_obj["agents"][0]
                if "protocol_config" in agent and "tls_version" in agent["protocol_config"]:
                    result["tls_version"] = agent["protocol_config"]["tls_version"]

            # Extract executed_until
            eu_ossl = exec_obj.get("executed_until")

            # Extract failing input recipe
            if eu_ossl is not None and "steps" in exec_obj:
                if eu_ossl < len(exec_obj["steps"]):
                    step = exec_obj["steps"][eu_ossl]
                    if "action" in step and isinstance(step["action"], dict) and "Input" in step["action"]:
                        recipe = step["action"]["Input"].get("recipe", "")
                        if recipe:
                            result["failing_input_recipe_ossl"] = recipe[:300]

            # Extract claims
            claims_list = []
            if "steps" in exec_obj:
                for step in exec_obj["steps"]:
                    if "claims" in step and step["claims"]:
                        for claim in step["claims"]:
                            claim_str = str(claim)[:150]
                            claims_list.append(claim_str)
            result["claims_ossl"] = claims_list

            # Extract knowledge types
            types_set = set()
            if "steps" in exec_obj:
                for step in exec_obj["steps"]:
                    if "knowledges" in step and step["knowledges"]:
                        for kn in step["knowledges"]:
                            kn_str = str(kn)
                            type_name = extract_type_name(kn_str)
                            if type_name:
                                types_set.add(type_name)
            result["knowledge_types_ossl"] = list(types_set)[:10]

    # Step 3: Display execute on LibreSSL
    cmd_libre = f"./target/release/tlspuffin --put libressl421 display-execute --json -t -k -c {trace_path}"
    output_libre, rc_libre = run_command(cmd_libre, timeout=10)

    if output_libre and rc_libre == 0:
        libre_json = extract_json_output(output_libre)
        if libre_json and "execution" in libre_json:
            exec_obj = libre_json["execution"]

            # Extract executed_until
            eu_libre = exec_obj.get("executed_until")

            # Extract failing input recipe
            if eu_libre is not None and "steps" in exec_obj:
                if eu_libre < len(exec_obj["steps"]):
                    step = exec_obj["steps"][eu_libre]
                    if "action" in step and isinstance(step["action"], dict) and "Input" in step["action"]:
                        recipe = step["action"]["Input"].get("recipe", "")
                        if recipe:
                            result["failing_input_recipe_libre"] = recipe[:300]

            # Extract claims
            claims_list = []
            if "steps" in exec_obj:
                for step in exec_obj["steps"]:
                    if "claims" in step and step["claims"]:
                        for claim in step["claims"]:
                            claim_str = str(claim)[:150]
                            claims_list.append(claim_str)
            result["claims_libre"] = claims_list

            # Extract knowledge types
            types_set = set()
            if "steps" in exec_obj:
                for step in exec_obj["steps"]:
                    if "knowledges" in step and step["knowledges"]:
                        for kn in step["knowledges"]:
                            kn_str = str(kn)
                            type_name = extract_type_name(kn_str)
                            if type_name:
                                types_set.add(type_name)
            result["knowledge_types_libre"] = list(types_set)[:10]

    return result

def main():
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

    results = []
    for i, trace in enumerate(traces, 1):
        print(f"[{i}/30] Processing {trace}...", file=sys.stderr)
        try:
            result = process_trace(trace)
            results.append(result)
        except Exception as e:
            print(f"Exception processing {trace}: {e}", file=sys.stderr)
            results.append({
                "trace": trace,
                "error": "exception",
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
                "knowledge_types_libre": []
            })

    # Write output
    output_path = "triaging-orchestration/state/round_2/batches/batch_09.json"
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Results written to {output_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
