#!/usr/bin/env python3
import json
import subprocess
import sys
import re
from pathlib import Path

TRACES = [
    "objective/20260428-233157659-2cabc7e87a84712f.trace",
    "objective/20260428-233330365-f334240e7a57201d.trace",
    "objective/20260428-233531343-9dc1c559d3605f45.trace",
    "objective/20260428-233807992-88f1fa099a1f3fb4.trace",
    "objective/20260428-234117869-3a9a21bea670ebda.trace",
    "objective/20260428-234338395-08193bb9c71d659c.trace",
    "objective/20260428-234622538-ca8e19d2ff3a61f2.trace",
    "objective/20260428-235052671-9cb6cb0970af345d.trace",
    "objective/20260428-235328761-8b2660ab7dec0766.trace",
    "objective/20260428-235616032-d78a9c6c80d2e028.trace",
    "objective/20260428-235829300-1a67f6bc399efa85.trace",
    "objective/20260429-000041424-321ac2bef7e3a4c5.trace",
    "objective/20260429-000238099-2acd97f74c443380.trace",
    "objective/20260429-000620323-e5b96d002c93b679.trace",
    "objective/20260429-001158641-cd0a491945cf1027.trace",
    "objective/20260429-001829975-a928146bc53add7b.trace",
    "objective/20260429-003207719-0edbcfec7d526625.trace",
    "objective/20260429-004744105-c941b9109a3cb281.trace",
    "objective/20260429-012221923-1c69b5d1078840a3.trace",
    "objective/20260429-054316999-ff4e037dcbe66cc4.trace",
    "objective/20260429-190156312-f42350c4712ab37e.trace",
]

OUTPUT_FILE = "triaging-orchestration/state/round_4/batches/batch_09.json"


def extract_json(output, timeout=False):
    """Extract JSON from stdout, handling potential errors."""
    if timeout:
        return None
    try:
        # Find JSON object in output
        start = output.find('{')
        if start == -1:
            return None
        end = output.rfind('}') + 1
        if end == 0:
            return None
        return json.loads(output[start:end])
    except json.JSONDecodeError:
        return None


def run_differential_execute(trace):
    """Run differential-execute and extract diff information."""
    try:
        cmd = ["./target/release/tlspuffin", "differential-execute", "--json", "openssl340", "libressl421", trace]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        data = extract_json(result.stdout)

        if not data:
            return {"error": "json_parse_failed"}

        output = {"diff_types": list(data.keys())}

        if "Status" in data:
            output["ossl_error"] = data.get("Status", {}).get("first_status")
            output["libre_error"] = data.get("Status", {}).get("second_status")
            output["ossl_steps"] = data.get("Status", {}).get("first_executed_steps")
            output["libre_steps"] = data.get("Status", {}).get("second_executed_steps")
            output["total_steps"] = data.get("Status", {}).get("total_step")

            ossl_steps = output["ossl_steps"]
            libre_steps = output["libre_steps"]
            if ossl_steps is not None and libre_steps is not None:
                if ossl_steps < libre_steps:
                    output["first_to_fail"] = "openssl340"
                elif libre_steps < ossl_steps:
                    output["first_to_fail"] = "libressl421"
                else:
                    output["first_to_fail"] = "same"
            else:
                output["first_to_fail"] = None

        if "Knowledges" in data:
            knowledges = data.get("Knowledges", {})
            if "InnerDifference" in knowledges:
                diff_text = str(knowledges["InnerDifference"])
                output[
                    "knowledge_diff"] = f"Inner[{knowledges['InnerDifference'].get('type_name', 'Unknown')}]:{diff_text[:100]}"
            elif "DifferentTypes" in knowledges:
                dt = knowledges["DifferentTypes"]
                output[
                    "knowledge_diff"] = f"DifferentTypes[{dt.get('first_type', 'Unknown')}][{dt.get('second_type', 'Unknown')}]"

        if "Claims" in data:
            claims = data.get("Claims", {})
            if "DifferentTypes" in claims:
                dt = claims["DifferentTypes"]
                output[
                    "claim_diff"] = f"DifferentTypes[{dt.get('first_type', 'Unknown')}][{dt.get('second_type', 'Unknown')}]"
            elif "InnerDifference" in claims:
                diff_text = str(claims["InnerDifference"])
                output["claim_diff"] = f"Inner:{diff_text[:80]}"

        return output
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def run_display_execute(put, trace):
    """Run display-execute and extract information."""
    try:
        cmd = ["./target/release/tlspuffin", "--put", put, "display-execute", "--json", "-t", "-k", "-c", trace]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        data = extract_json(result.stdout)

        if not data:
            return None

        execution = data.get("execution", {})
        agents = execution.get("agents", [])

        output = {}

        # Extract tls_version
        if agents and len(agents) > 0:
            proto_config = agents[0].get("protocol_config", {})
            output["tls_version"] = proto_config.get("tls_version")

        # Extract executed_until
        output["executed_until"] = execution.get("executed_until")

        # Extract failing_input_recipe
        eu = execution.get("executed_until")
        steps = execution.get("steps", [])
        output["failing_input_recipe"] = None
        if eu is not None and eu < len(steps):
            step = steps[eu]
            action = step.get("action")
            if isinstance(action, dict) and "Input" in action:
                recipe = action["Input"].get("recipe", "")
                output["failing_input_recipe"] = recipe[:300] if recipe else None

        # Extract claims - flatten all claims from all steps
        claims_list = []
        for step in steps:
            step_claims = step.get("claims", [])
            for claim in step_claims:
                claim_str = str(claim)[:150]
                claims_list.append(claim_str)
        output["claims"] = claims_list

        # Extract knowledge types - first word before { or (
        knowledge_types = set()
        for step in steps:
            knowledges = step.get("knowledges", [])
            for knowledge in knowledges:
                knowledge_str = str(knowledge)
                # Extract first word before { or (
                match = re.match(r'([a-zA-Z_]\w*)', knowledge_str)
                if match:
                    knowledge_types.add(match.group(1))
        output["knowledge_types"] = list(knowledge_types)[:10]

        return output
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        return None


def process_trace(trace):
    """Process a single trace and return result object."""
    result = {"trace": trace}

    # Step 1: Differential execute
    diff_data = run_differential_execute(trace)
    if "error" in diff_data:
        result["error"] = diff_data["error"]
        result.update({
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
        })
        return result

    # Copy diff results
    result["diff_types"] = diff_data.get("diff_types")
    result["ossl_error"] = diff_data.get("ossl_error")
    result["libre_error"] = diff_data.get("libre_error")
    result["ossl_steps"] = diff_data.get("ossl_steps")
    result["libre_steps"] = diff_data.get("libre_steps")
    result["total_steps"] = diff_data.get("total_steps")
    result["first_to_fail"] = diff_data.get("first_to_fail")
    result["knowledge_diff"] = diff_data.get("knowledge_diff")
    result["claim_diff"] = diff_data.get("claim_diff")

    # Step 2: Display execute on OSSL
    ossl_data = run_display_execute("openssl340", trace)
    if ossl_data:
        result["tls_version"] = ossl_data.get("tls_version")
        result["failing_input_recipe_ossl"] = ossl_data.get("failing_input_recipe")
        result["claims_ossl"] = ossl_data.get("claims", [])
        result["knowledge_types_ossl"] = ossl_data.get("knowledge_types", [])
    else:
        result["tls_version"] = None
        result["failing_input_recipe_ossl"] = None
        result["claims_ossl"] = None
        result["knowledge_types_ossl"] = None

    # Step 3: Display execute on LibreSSL
    libre_data = run_display_execute("libressl421", trace)
    if libre_data:
        result["failing_input_recipe_libre"] = libre_data.get("failing_input_recipe")
        result["claims_libre"] = libre_data.get("claims", [])
        result["knowledge_types_libre"] = libre_data.get("knowledge_types", [])
    else:
        result["failing_input_recipe_libre"] = None
        result["claims_libre"] = None
        result["knowledge_types_libre"] = None

    return result


def main():
    results = []
    for i, trace in enumerate(TRACES, 1):
        print(f"Processing {i}/{len(TRACES)}: {trace}")
        result = process_trace(trace)
        results.append(result)

    # Write output
    output_path = Path(OUTPUT_FILE)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
