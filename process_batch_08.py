#!/usr/bin/env python3
import json
import subprocess
import sys
import re
from pathlib import Path


def run_cmd(cmd, timeout=30):
    """Execute command with timeout, return stdout or None on failure"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout,
                                cwd="/home/nbaffou/dev/tlspuffin")
        # Return stdout regardless of exit code - we'll validate JSON separately
        return result.stdout if result.stdout else None
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        return None


def extract_diff_data(json_str):
    """Extract diff_types, ossl_error, libre_error, steps from differential-execute output"""
    try:
        data = json.loads(json_str)
        result = {
            "diff_types": list(data[0].keys()) if isinstance(data, list) and len(data) > 0 else [],
            "ossl_error": None,
            "libre_error": None,
            "ossl_steps": None,
            "libre_steps": None,
            "total_steps": None,
            "first_to_fail": None,
            "knowledge_diff": None,
            "claim_diff": None
        }

        if isinstance(data, list) and len(data) > 0:
            obj = data[0]

            # Extract Status info
            if "Status" in obj:
                result["ossl_error"] = obj.get("first_status", None)
                result["libre_error"] = obj.get("second_status", None)
                ossl_steps = obj.get("first_executed_steps", 0)
                libre_steps = obj.get("second_executed_steps", 0)
                result["ossl_steps"] = ossl_steps
                result["libre_steps"] = libre_steps
                result["total_steps"] = obj.get("total_step", None)

                # Determine first_to_fail
                if ossl_steps < libre_steps:
                    result["first_to_fail"] = "openssl340"
                elif libre_steps < ossl_steps:
                    result["first_to_fail"] = "libressl421"
                else:
                    result["first_to_fail"] = "same"

            # Extract Knowledges info
            if "Knowledges" in obj:
                diff = obj["Knowledges"]
                if "InnerDifference" in diff:
                    inner = diff["InnerDifference"]
                    type_name = inner.get("type_name", "Unknown")
                    diff_str = str(inner.get("diff", ""))[:100]
                    result["knowledge_diff"] = f"Inner[{type_name}]:{diff_str}"
                elif "DifferentTypes" in diff:
                    dt = diff["DifferentTypes"]
                    first_type = dt.get("first_type", "Unknown")
                    second_type = dt.get("second_type", "Unknown")
                    result["knowledge_diff"] = f"DifferentTypes[{first_type}][{second_type}]"

            # Extract Claims info
            if "Claims" in obj:
                diff = obj["Claims"]
                if "DifferentTypes" in diff:
                    dt = diff["DifferentTypes"]
                    first_type = dt.get("first_type", "Unknown")
                    second_type = dt.get("second_type", "Unknown")
                    result["claim_diff"] = f"DifferentTypes[{first_type}][{second_type}]"
                elif "InnerDifference" in diff:
                    inner = diff["InnerDifference"]
                    diff_str = str(inner.get("diff", ""))[:80]
                    result["claim_diff"] = f"Inner:{diff_str}"

        return result
    except:
        return None


def extract_display_data(json_str, executed_until=None):
    """Extract tls_version, claims, knowledge_types from display-execute output"""
    try:
        data = json.loads(json_str)
        execution = data.get("execution", {})

        result = {
            "tls_version": None,
            "eu": execution.get("executed_until", None),
            "failing_input_recipe": None,
            "claims": [],
            "knowledge_types": []
        }

        # Extract tls_version
        agents = execution.get("agents", [])
        if agents and "protocol_config" in agents[0]:
            result["tls_version"] = agents[0]["protocol_config"].get("tls_version", None)

        # Extract failing_input_recipe and claims/knowledge_types from steps
        steps = execution.get("steps", [])
        eu = execution.get("executed_until", 0)

        if eu < len(steps) and eu >= 0:
            step = steps[eu]
            action = step.get("action", {})
            if isinstance(action, dict) and "Input" in action:
                recipe = action["Input"].get("recipe", "")
                result["failing_input_recipe"] = recipe[:300]

        # Flatten all claims
        all_claims = []
        for step in steps:
            claims = step.get("claims", [])
            if isinstance(claims, list):
                for claim in claims:
                    if isinstance(claim, str):
                        all_claims.append(claim[:150])
                    else:
                        all_claims.append(str(claim)[:150])
        result["claims"] = all_claims

        # Extract knowledge types
        knowledge_types_set = set()
        for step in steps:
            knowledges = step.get("knowledges", [])
            if isinstance(knowledges, list):
                for knowledge in knowledges:
                    if isinstance(knowledge, str):
                        # Extract first word before { or (
                        match = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', knowledge)
                        if match:
                            knowledge_types_set.add(match.group(1))

        result["knowledge_types"] = sorted(list(knowledge_types_set))[:10]

        return result
    except:
        return None


traces = [
    "objective/20260428-230403952-7c60fc0fcd39f044.trace",
    "objective/20260428-230431674-54d911f4fd526360.trace",
    "objective/20260428-230522812-b99d844dbff583c3.trace",
    "objective/20260428-230554595-28cf55fb284ca99b.trace",
    "objective/20260428-230634375-c6a499b37b43b277.trace",
    "objective/20260428-230737896-c42d59b6aa3f70a8.trace",
    "objective/20260428-230823756-d07b961c0e90bccb.trace",
    "objective/20260428-230900707-0b816edd53bb55fd.trace",
    "objective/20260428-230941756-01b6e6b88fbd06ca.trace",
    "objective/20260428-231017101-95f1db63423748ee.trace",
    "objective/20260428-231106421-071892b3c4c28ce2.trace",
    "objective/20260428-231202574-7c2e1786be0480bd.trace",
    "objective/20260428-231247231-eaf15a931ff4f033.trace",
    "objective/20260428-231342329-4cb2345ac98fc4cf.trace",
    "objective/20260428-231428036-e88aa15d6a1a894a.trace",
    "objective/20260428-231514030-0dd47797dec48c1e.trace",
    "objective/20260428-231548419-91e74429093bc870.trace",
    "objective/20260428-231645722-22a7aa54a47ac888.trace",
    "objective/20260428-231746036-de093374a7eaad9f.trace",
    "objective/20260428-231811148-06fec25adc383d14.trace",
    "objective/20260428-231858783-a62e1229f2e87ce3.trace",
    "objective/20260428-232003908-550685cd76a12564.trace",
    "objective/20260428-232121007-d4ea64708fbf9a64.trace",
    "objective/20260428-232233043-437044ded4ee50eb.trace",
    "objective/20260428-232401665-763f51d902e74de6.trace",
    "objective/20260428-232520173-96acbd4493621ecc.trace",
    "objective/20260428-232656626-e174c97ac2a0f0dd.trace",
    "objective/20260428-232806116-42c4d82c1a0e3d86.trace",
    "objective/20260428-232915774-cea5d2713b38c6f4.trace",
    "objective/20260428-233048245-a2559fed44d67aa7.trace",
]

results = []

for i, trace in enumerate(traces, 1):
    print(f"Processing [{i}/30]: {trace}", file=sys.stderr)
    sys.stderr.flush()

    entry = {"trace": trace}

    # Step 1: differential-execute
    cmd_diff = f"./target/release/tlspuffin differential-execute --json openssl340 libressl421 {trace}"
    diff_output = run_cmd(cmd_diff, timeout=30)

    if diff_output:
        diff_data = extract_diff_data(diff_output)
        if diff_data:
            entry.update(diff_data)
        else:
            entry["error"] = "diff_parse_failed"
    else:
        entry["error"] = "diff_timeout"

    # Step 2: display-execute on OSSL
    cmd_ossl = f"./target/release/tlspuffin --put openssl340 display-execute --json -t -k -c {trace}"
    ossl_output = run_cmd(cmd_ossl, timeout=30)

    if ossl_output:
        ossl_data = extract_display_data(ossl_output)
        if ossl_data:
            if "tls_version" not in entry or entry.get("tls_version") is None:
                entry["tls_version"] = ossl_data["tls_version"]
            entry["eu_ossl"] = ossl_data["eu"]
            entry["failing_input_recipe_ossl"] = ossl_data["failing_input_recipe"]
            entry["claims_ossl"] = ossl_data["claims"]
            entry["knowledge_types_ossl"] = ossl_data["knowledge_types"]
        else:
            entry["eu_ossl"] = None
            entry["failing_input_recipe_ossl"] = None
            entry["claims_ossl"] = None
            entry["knowledge_types_ossl"] = None
    else:
        entry["eu_ossl"] = None
        entry["failing_input_recipe_ossl"] = None
        entry["claims_ossl"] = None
        entry["knowledge_types_ossl"] = None

    # Step 3: display-execute on LibreSSL
    cmd_libre = f"./target/release/tlspuffin --put libressl421 display-execute --json -t -k -c {trace}"
    libre_output = run_cmd(cmd_libre, timeout=30)

    if libre_output:
        libre_data = extract_display_data(libre_output)
        if libre_data:
            entry["eu_libre"] = libre_data["eu"]
            entry["failing_input_recipe_libre"] = libre_data["failing_input_recipe"]
            entry["claims_libre"] = libre_data["claims"]
            entry["knowledge_types_libre"] = libre_data["knowledge_types"]
        else:
            entry["eu_libre"] = None
            entry["failing_input_recipe_libre"] = None
            entry["claims_libre"] = None
            entry["knowledge_types_libre"] = None
    else:
        entry["eu_libre"] = None
        entry["failing_input_recipe_libre"] = None
        entry["claims_libre"] = None
        entry["knowledge_types_libre"] = None

    results.append(entry)

# Write output
output_file = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_4/batches/batch_08.json"
Path(output_file).parent.mkdir(parents=True, exist_ok=True)

with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"Results written to {output_file}", file=sys.stderr)
