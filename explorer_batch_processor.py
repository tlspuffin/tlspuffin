#!/usr/bin/env python3

import json
import subprocess
import sys
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKDIR = "/home/nbaffou/dev/tlspuffin"
BINARY = f"{WORKDIR}/target/release/tlspuffin"
BATCH_STATE_DIR = f"{WORKDIR}/triaging-orchestration/state/round_3/batches"

def run_cmd(cmd: List[str], timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout or None on timeout/failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=WORKDIR)
        return result.stdout
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        print(f"Error running command: {e}", file=sys.stderr)
        return None

def extract_diff_info(json_str: str) -> Dict[str, Any]:
    """Extract info from differential-execute JSON output."""
    result = {}
    try:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            return result

        # Get top-level keys
        result['diff_types'] = list(data.keys())

        # Extract Status info if present
        if 'Status' in data:
            status_obj = data['Status']
            if isinstance(status_obj, dict):
                result['ossl_error'] = status_obj.get('first_status')
                result['libre_error'] = status_obj.get('second_status')
                result['ossl_steps'] = status_obj.get('first_executed_steps')
                result['libre_steps'] = status_obj.get('second_executed_steps')
                result['total_steps'] = status_obj.get('total_step')

                # Compute first_to_fail
                ossl_steps = result.get('ossl_steps')
                libre_steps = result.get('libre_steps')
                if ossl_steps is not None and libre_steps is not None:
                    if ossl_steps < libre_steps:
                        result['first_to_fail'] = "openssl340"
                    elif libre_steps < ossl_steps:
                        result['first_to_fail'] = "libressl421"
                    else:
                        result['first_to_fail'] = "same"

        # Extract Knowledges info if present
        if 'Knowledges' in data:
            know_obj = data['Knowledges']
            if isinstance(know_obj, dict):
                if 'InnerDifference' in know_obj:
                    inner = know_obj['InnerDifference']
                    if isinstance(inner, dict):
                        type_name = inner.get('type_name', '')
                        diff_text = inner.get('diff', '')[:100]
                        result['knowledge_diff'] = f"Inner[{type_name}]:{diff_text}"
                elif 'DifferentTypes' in know_obj:
                    diff_types = know_obj['DifferentTypes']
                    if isinstance(diff_types, dict):
                        first_type = diff_types.get('first_type', '')
                        second_type = diff_types.get('second_type', '')
                        result['knowledge_diff'] = f"DifferentTypes[{first_type}][{second_type}]"

        # Extract Claims info if present
        if 'Claims' in data:
            claims_obj = data['Claims']
            if isinstance(claims_obj, dict):
                if 'DifferentTypes' in claims_obj:
                    diff_types = claims_obj['DifferentTypes']
                    if isinstance(diff_types, dict):
                        first_type = diff_types.get('first_type', '')
                        second_type = diff_types.get('second_type', '')
                        result['claim_diff'] = f"DifferentTypes[{first_type}][{second_type}]"
                elif 'InnerDifference' in claims_obj:
                    inner = claims_obj['InnerDifference']
                    if isinstance(inner, dict):
                        diff_text = inner.get('diff', '')[:80]
                        result['claim_diff'] = f"Inner:{diff_text}"
    except json.JSONDecodeError:
        pass

    return result

def extract_display_info(json_str: str, put_name: str) -> Dict[str, Any]:
    """Extract info from display-execute JSON output."""
    result = {}
    try:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            return result

        execution = data.get('execution', {})
        if not isinstance(execution, dict):
            return result

        # Get TLS version
        agents = execution.get('agents', [])
        if agents and isinstance(agents[0], dict):
            protocol_config = agents[0].get('protocol_config', {})
            tls_version = protocol_config.get('tls_version')
            result[f'tls_version'] = tls_version

        # Get executed_until
        eu = execution.get('executed_until')
        result[f'eu_{put_name}'] = eu

        # Get failing_input_recipe
        steps = execution.get('steps', [])
        if eu is not None and 0 <= eu < len(steps):
            step = steps[eu]
            if isinstance(step, dict):
                action = step.get('action')
                if isinstance(action, dict) and 'Input' in action:
                    input_obj = action['Input']
                    if isinstance(input_obj, dict):
                        recipe = input_obj.get('recipe', '')
                        result[f'failing_input_recipe_{put_name}'] = recipe[:300]

        # Get claims
        claims_list = []
        for step in steps:
            if isinstance(step, dict):
                step_claims = step.get('claims', [])
                if isinstance(step_claims, list):
                    for claim in step_claims:
                        claim_str = str(claim)[:150]
                        if claim_str not in claims_list:
                            claims_list.append(claim_str)
        result[f'claims_{put_name}'] = claims_list

        # Get knowledge types
        knowledge_types = set()
        for step in steps:
            if isinstance(step, dict):
                knowledges = step.get('knowledges', [])
                if isinstance(knowledges, list):
                    for knowledge in knowledges:
                        know_str = str(knowledge)
                        # Extract type name (first word before { or ()
                        type_name = know_str.split('{')[0].split('(')[0].strip()
                        if type_name:
                            knowledge_types.add(type_name)

        # Limit to 10 types
        result[f'knowledge_types_{put_name}'] = list(knowledge_types)[:10]

    except json.JSONDecodeError:
        pass

    return result

def process_trace(trace_path: str) -> Dict[str, Any]:
    """Process a single trace through all commands."""
    result = {
        'trace': trace_path,
        'tls_version': None,
        'diff_types': None,
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

    # Step 1: differential-execute
    diff_cmd = [BINARY, 'differential-execute', '--json', 'openssl340', 'libressl421', trace_path]
    diff_output = run_cmd(diff_cmd)

    if diff_output:
        diff_info = extract_diff_info(diff_output)
        result.update(diff_info)
    else:
        result['error'] = 'differential_execute_failed'
        return result

    # Step 2: display-execute on OSSL
    ossl_cmd = [BINARY, '--put', 'openssl340', 'display-execute', '--json', '-t', '-k', '-c', trace_path]
    ossl_output = run_cmd(ossl_cmd)

    if ossl_output:
        ossl_info = extract_display_info(ossl_output, 'ossl')
        result.update(ossl_info)
        if 'tls_version' in ossl_info:
            result['tls_version'] = ossl_info['tls_version']

    # Step 3: display-execute on LibreSSL
    libre_cmd = [BINARY, '--put', 'libressl421', 'display-execute', '--json', '-t', '-k', '-c', trace_path]
    libre_output = run_cmd(libre_cmd)

    if libre_output:
        libre_info = extract_display_info(libre_output, 'libre')
        result.update(libre_info)

    return result

def read_batch_file(batch_file: str) -> List[str]:
    """Read trace paths from a batch file."""
    traces = []
    try:
        with open(batch_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    traces.append(line)
    except Exception as e:
        print(f"Error reading {batch_file}: {e}", file=sys.stderr)
    return traces

def process_batch(batch_num: int):
    """Process a single batch and write output JSON."""
    batch_file = f"{BATCH_STATE_DIR}/batch_{batch_num:02d}.txt"
    output_file = f"{BATCH_STATE_DIR}/batch_{batch_num:02d}.json"

    print(f"Processing batch {batch_num:02d}...")

    traces = read_batch_file(batch_file)
    print(f"  Found {len(traces)} traces")

    results = []
    for i, trace in enumerate(traces):
        print(f"  [{i+1}/{len(traces)}] {trace}")
        trace_result = process_trace(trace)
        results.append(trace_result)

    # Write output
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"  Wrote {output_file}")

def main():
    # Process batches 0-9
    for batch_num in range(10):
        process_batch(batch_num)

    print("All batches processed!")

if __name__ == '__main__':
    main()
