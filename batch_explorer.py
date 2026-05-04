#!/usr/bin/env python3
import json
import subprocess
import sys
import os
from pathlib import Path


def run_cmd(cmd, timeout=10):
    """Execute command and return output or None on timeout/error"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout,
                                cwd="/home/nbaffou/dev/tlspuffin")
        # Ignore return code - commands may return 1 but still produce output
        return result.stdout if result.stdout else None
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        return None


def extract_json(output):
    """Extract JSON from command output - find the first { and match closing }"""
    try:
        # Find the first JSON object opening
        start = output.find('{')
        if start == -1:
            return None

        # Now find the matching closing brace
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(output)):
            c = output[i]
            if escape:
                escape = False
                continue
            if c == '\\':
                escape = True
                continue
            if c == '"' and not escape:
                in_string = not in_string
                continue
            if not in_string:
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(output[start:i + 1])
                        except:
                            return None
        return None
    except:
        return None


def extract_diff_types(data):
    """Extract diff_types from first object in list"""
    if isinstance(data, list) and len(data) > 0:
        return list(data[0].keys())
    elif isinstance(data, dict):
        return list(data.keys())
    return []


def extract_status_info(data):
    """Extract status and step info from diff result"""
    if isinstance(data, list) and len(data) > 0:
        data = data[0]

    if not isinstance(data, dict) or 'Status' not in data:
        return None

    status = data['Status']
    result = {
        'ossl_error': status.get('first_status'),
        'libre_error': status.get('second_status'),
        'ossl_steps': status.get('first_executed_steps'),
        'libre_steps': status.get('second_executed_steps'),
        'total_steps': status.get('total_step'),
    }

    # Determine first_to_fail
    if result['ossl_steps'] is not None and result['libre_steps'] is not None:
        if result['ossl_steps'] < result['libre_steps']:
            result['first_to_fail'] = 'openssl340'
        elif result['libre_steps'] < result['ossl_steps']:
            result['first_to_fail'] = 'libressl421'
        else:
            result['first_to_fail'] = 'same'

    return result


def extract_knowledge_diff(data):
    """Extract knowledge_diff from first object"""
    if isinstance(data, list) and len(data) > 0:
        data = data[0]

    if not isinstance(data, dict) or 'Knowledges' not in data:
        return None

    k = data['Knowledges']
    if 'InnerDifference' in k:
        diff_str = str(k['InnerDifference']).replace("'", '"')[:100]
        type_name = k.get('InnerDifference', {}).get('type_name', 'Unknown') if isinstance(k.get('InnerDifference'),
                                                                                           dict) else 'Unknown'
        return f"Inner[{type_name}]:{diff_str}"
    elif 'DifferentTypes' in k:
        dt = k['DifferentTypes']
        first_type = dt.get('first_type', 'Unknown') if isinstance(dt, dict) else 'Unknown'
        second_type = dt.get('second_type', 'Unknown') if isinstance(dt, dict) else 'Unknown'
        return f"DifferentTypes[{first_type}][{second_type}]"

    return None


def extract_claim_diff(data):
    """Extract claim_diff from first object"""
    if isinstance(data, list) and len(data) > 0:
        data = data[0]

    if not isinstance(data, dict) or 'Claims' not in data:
        return None

    c = data['Claims']
    if 'DifferentTypes' in c:
        dt = c['DifferentTypes']
        first_type = dt.get('first_type', 'Unknown') if isinstance(dt, dict) else 'Unknown'
        second_type = dt.get('second_type', 'Unknown') if isinstance(dt, dict) else 'Unknown'
        return f"DifferentTypes[{first_type}][{second_type}]"
    elif 'InnerDifference' in c:
        diff_str = str(c['InnerDifference'])[:80]
        return f"Inner:{diff_str}"

    return None


def extract_display_info(json_data, put_name):
    """Extract display-execute info for a PUT"""
    try:
        if not isinstance(json_data, dict) or 'execution' not in json_data:
            return {
                'tls_version': None,
                'eu': None,
                'failing_input_recipe': None,
                'claims': [],
                'knowledge_types': []
            }

        exec_data = json_data['execution']

        # Extract TLS version
        tls_version = None
        if 'agents' in exec_data and len(exec_data['agents']) > 0:
            tls_version = exec_data['agents'][0].get('protocol_config', {}).get('tls_version')

        # Extract executed_until
        eu = exec_data.get('executed_until')

        # Extract failing_input_recipe
        failing_recipe = None
        if eu is not None and 'steps' in exec_data:
            if 0 <= eu < len(exec_data['steps']):
                step = exec_data['steps'][eu]
                if 'action' in step and isinstance(step['action'], dict) and 'Input' in step['action']:
                    recipe = step['action']['Input'].get('recipe', '')[:300]
                    failing_recipe = recipe if recipe else None

        # Extract claims
        claims = []
        if 'steps' in exec_data:
            for step in exec_data['steps']:
                if 'claims' in step and isinstance(step['claims'], list):
                    for claim in step['claims']:
                        claim_str = str(claim)[:150]
                        claims.append(claim_str)

        # Extract knowledge types
        knowledge_types = set()
        if 'steps' in exec_data:
            for step in exec_data['steps']:
                if 'knowledges' in step and isinstance(step['knowledges'], list):
                    for knowledge in step['knowledges']:
                        knowledge_str = str(knowledge)
                        # Extract first word before { or (
                        type_name = knowledge_str.split('{')[0].split('(')[0].strip()
                        if type_name:
                            knowledge_types.add(type_name)

        return {
            'tls_version': tls_version,
            'eu': eu,
            'failing_input_recipe': failing_recipe,
            'claims': claims,
            'knowledge_types': list(knowledge_types)[:10]
        }
    except:
        return {
            'tls_version': None,
            'eu': None,
            'failing_input_recipe': None,
            'claims': [],
            'knowledge_types': []
        }


def process_trace(trace_path):
    """Process a single trace"""
    result = {
        'trace': trace_path,
        'tls_version': None,
        'diff_types': [],
        'ossl_error': None,
        'libre_error': None,
        'ossl_steps': None,
        'libre_steps': None,
        'total_steps': None,
        'first_to_fail': None,
        'knowledge_diff': None,
        'claim_diff': None,
        'failing_input_recipe_ossl': None,
        'failing_input_recipe_libre': None,
        'claims_ossl': [],
        'claims_libre': [],
        'knowledge_types_ossl': [],
        'knowledge_types_libre': []
    }

    # Extract just the filename from the trace path (in case it includes "objective/")
    trace_filename = trace_path.split('/')[-1]
    full_trace_path = f"objective/{trace_filename}"

    # Step 1: Run differential-execute
    cmd = f"./target/release/tlspuffin differential-execute --json openssl340 libressl421 {full_trace_path}"
    diff_output = run_cmd(cmd, timeout=15)

    if diff_output:
        diff_json = extract_json(diff_output)
        if diff_json:
            result['diff_types'] = extract_diff_types(diff_json)

            status_info = extract_status_info(diff_json)
            if status_info:
                result.update(status_info)

            result['knowledge_diff'] = extract_knowledge_diff(diff_json)
            result['claim_diff'] = extract_claim_diff(diff_json)

    # Step 2: Run display-execute on OSSL
    cmd_ossl = f"./target/release/tlspuffin --put openssl340 display-execute --json -t -k -c {full_trace_path}"
    ossl_output = run_cmd(cmd_ossl, timeout=15)

    if ossl_output:
        ossl_json = extract_json(ossl_output)
        if ossl_json:
            ossl_info = extract_display_info(ossl_json, 'openssl340')
            result['tls_version'] = ossl_info['tls_version'] or result['tls_version']
            result['failing_input_recipe_ossl'] = ossl_info['failing_input_recipe']
            result['claims_ossl'] = ossl_info['claims']
            result['knowledge_types_ossl'] = ossl_info['knowledge_types']

    # Step 3: Run display-execute on LibreSSL
    cmd_libre = f"./target/release/tlspuffin --put libressl421 display-execute --json -t -k -c {full_trace_path}"
    libre_output = run_cmd(cmd_libre, timeout=15)

    if libre_output:
        libre_json = extract_json(libre_output)
        if libre_json:
            libre_info = extract_display_info(libre_json, 'libressl421')
            result['failing_input_recipe_libre'] = libre_info['failing_input_recipe']
            result['claims_libre'] = libre_info['claims']
            result['knowledge_types_libre'] = libre_info['knowledge_types']

    return result


def main():
    trace_list = [
        "objective/20260428-221402089-fdf7c36ee2f45a83.trace",
        "objective/20260428-221427724-dc3e068025232339.trace",
        "objective/20260428-221448088-c20fed83958ef116.trace",
        "objective/20260428-221506329-30b67c7f67f9dae5.trace",
        "objective/20260428-221527080-42949639c270e288.trace",
        "objective/20260428-221555009-a7a2647344a9fc3c.trace",
        "objective/20260428-221613575-6d7d1a2e65820afa.trace",
        "objective/20260428-221638245-b4a16a20da7adeee.trace",
        "objective/20260428-221658958-1dca4d139a2445f2.trace",
        "objective/20260428-221719898-a61f8bdf45b54ac7.trace",
        "objective/20260428-221737599-308f163da54459bf.trace",
        "objective/20260428-221759475-ef12591b1d6c6c14.trace",
        "objective/20260428-221817137-a14ee1ffd2de744b.trace",
        "objective/20260428-221830244-426b185b8552ec00.trace",
        "objective/20260428-221851332-4de186fada9ffc61.trace",
        "objective/20260428-221907099-4ac07e4ba6390c50.trace",
        "objective/20260428-221928486-21e81d0e711d32a3.trace",
        "objective/20260428-221945224-65d6f9bbbb644d92.trace",
        "objective/20260428-221959742-09d151909051604d.trace",
        "objective/20260428-222023147-005adaee6630b492.trace",
        "objective/20260428-222036722-911171f869386890.trace",
        "objective/20260428-222059168-7293ddc8a97de0c4.trace",
        "objective/20260428-222122750-ce91e729244e087d.trace",
        "objective/20260428-222135261-e533181a3ba70d13.trace",
        "objective/20260428-222148067-de44ad14bd94b81c.trace",
        "objective/20260428-222208033-a3e32fec426d8fdd.trace",
        "objective/20260428-222228515-cce7422276d0e642.trace",
        "objective/20260428-222254372-64d5adf514161775.trace",
        "objective/20260428-222311731-35a8b18b83bcdfcb.trace",
        "objective/20260428-222329483-e5de77d0a8b24148.trace",
    ]

    results = []
    for i, trace in enumerate(trace_list, 1):
        print(f"Processing {i}/30: {trace}", file=sys.stderr)
        result = process_trace(trace)
        results.append(result)
        sys.stderr.flush()

    # Write output JSON
    output_file = "triaging-orchestration/state/round_4/batches/batch_04.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Results written to {output_file}", file=sys.stderr)


if __name__ == '__main__':
    main()
