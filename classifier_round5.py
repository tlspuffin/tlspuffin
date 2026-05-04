#!/usr/bin/env python3
"""
Round 5 Classifier - Analyzes differential execution traces from batches
and groups them into buckets based on behaviors.
"""

import json
import os
from typing import Dict, List, Any, Tuple
from collections import defaultdict


def load_batches(batch_files: List[str]) -> List[Dict[str, Any]]:
    """Load and combine all batch files."""
    all_traces = []
    for batch_file in batch_files:
        try:
            with open(batch_file, 'r') as f:
                batch_data = json.load(f)
                all_traces.extend(batch_data)
        except FileNotFoundError:
            print(f"Warning: {batch_file} not found")
    return all_traces


def load_existing_buckets(existing_file: str) -> Tuple[List[Dict], int]:
    """Load existing buckets and return them with next ID number."""
    try:
        with open(existing_file, 'r') as f:
            buckets = json.load(f)
        if buckets:
            last_id = int(buckets[-1]['id'].replace('B', ''))
            return buckets, last_id
        return [], 0
    except FileNotFoundError:
        return [], 0


def is_valid_trace(trace: Dict) -> bool:
    """Check if trace should be processed (not error traces)."""
    error_field = trace.get('error')
    if error_field:
        return False
    diff_types = trace.get('diff_types')
    if not diff_types or diff_types == [] or diff_types == []:
        return False
    if trace.get('tls_version') is None:
        return False
    return True


def extract_fn_symbol(recipe: str) -> str:
    """Extract the main function symbol from a recipe."""
    if not recipe:
        return ""
    # Extract first function name
    if recipe.startswith('fn_'):
        match = recipe.split('(')[0]
        return match
    return ""


def extract_error_substring(error: str, max_len: int = 50) -> str:
    """Extract a distinctive substring from error message."""
    if not error:
        return ""
    # Get first line of error
    first_line = error.split('\n')[0]
    # Remove SSL_ERROR prefix if present
    if 'error:' in first_line:
        parts = first_line.split('error:')
        if len(parts) > 1:
            error_code = parts[-1].strip()[:max_len]
            return error_code
    return first_line[:max_len]


def group_traces(traces: List[Dict]) -> Dict[str, List[Dict]]:
    """Group traces by behavior patterns."""
    groups = defaultdict(list)

    for trace in traces:
        if not is_valid_trace(trace):
            continue

        tls_version = trace.get('tls_version')
        diff_types = trace.get('diff_types', [])
        first_to_fail = trace.get('first_to_fail')
        knowledge_diff = trace.get('knowledge_diff')
        claim_diff = trace.get('claim_diff')
        ossl_error = trace.get('ossl_error')
        libre_error = trace.get('libre_error')
        ossl_recipe = trace.get('failing_input_recipe_ossl', '')
        libre_recipe = trace.get('failing_input_recipe_libre', '')

        # Normalize tls_version for grouping (handle "Both")
        if tls_version == "Both":
            # Create groups for both V1_2 and V1_3
            for version in ["V1_2", "V1_3"]:
                group_key = create_group_key(
                    version, first_to_fail, diff_types,
                    knowledge_diff, claim_diff, ossl_error,
                    libre_error, ossl_recipe, libre_recipe
                )
                groups[group_key].append(trace)
        else:
            group_key = create_group_key(
                tls_version, first_to_fail, diff_types,
                knowledge_diff, claim_diff, ossl_error,
                libre_error, ossl_recipe, libre_recipe
            )
            groups[group_key].append(trace)

    return groups


def create_group_key(tls_version, first_to_fail, diff_types, knowledge_diff,
                     claim_diff, ossl_error, libre_error, ossl_recipe, libre_recipe):
    """Create a unique key for grouping similar traces."""
    # For Status diffs
    if diff_types == ["Status"]:
        error_substring = ""
        if first_to_fail == "openssl340" and ossl_error:
            error_substring = extract_error_substring(ossl_error)
        elif first_to_fail == "libressl421" and libre_error:
            error_substring = extract_error_substring(libre_error)

        fn_symbol = ""
        if first_to_fail == "openssl340":
            fn_symbol = extract_fn_symbol(ossl_recipe)
        else:
            fn_symbol = extract_fn_symbol(libre_recipe)

        return f"Status_{tls_version}_{first_to_fail}_{error_substring}_{fn_symbol}"

    # For Knowledge diffs
    elif "Knowledges" in diff_types:
        if knowledge_diff:
            # Extract the key part of the diff
            if "Inner[" in knowledge_diff:
                # Extract what's between the Description()
                if "Different(" in knowledge_diff:
                    start = knowledge_diff.find("Different(")
                    end = knowledge_diff.find(")", start)
                    diff_part = knowledge_diff[start:end + 1]
                    return f"Knowledge_{tls_version}_{diff_part}"
                elif "DifferentTypes[" in knowledge_diff:
                    start = knowledge_diff.find("DifferentTypes[")
                    end = knowledge_diff.find("]", start)
                    diff_part = knowledge_diff[start:end + 1]
                    return f"Knowledge_{tls_version}_{diff_part}"
        return f"Knowledge_{tls_version}_{knowledge_diff[:50]}"

    # For Claim diffs
    elif "Claims" in diff_types:
        if claim_diff:
            if "DifferentTypes[" in claim_diff:
                start = claim_diff.find("DifferentTypes[")
                end = claim_diff.find("]", claim_diff.find("]", start) + 1)
                diff_part = claim_diff[start:end + 1]
                return f"Claim_{tls_version}_{diff_part}"
        return f"Claim_{tls_version}_{claim_diff[:50]}"

    return f"Unknown_{tls_version}"


def generate_buckets(groups: Dict[str, List[Dict]], existing_buckets: List[Dict],
                     next_id: int) -> List[Dict]:
    """Generate new buckets from groups with >= 3 traces."""
    new_buckets = []

    for group_key, traces in groups.items():
        # Skip small groups
        if len(traces) < 3:
            continue

        # Get representative trace
        trace = traces[0]

        # Check for duplicate (similar to existing)
        is_duplicate = check_duplicate(trace, existing_buckets)
        if is_duplicate:
            continue

        bucket = create_bucket(
            group_key, traces, next_id + len(new_buckets) + 1, 5
        )
        new_buckets.append(bucket)

    return new_buckets


def check_duplicate(trace: Dict, existing_buckets: List[Dict]) -> bool:
    """Check if trace already matches an existing bucket."""
    tls_version = trace.get('tls_version')
    diff_types = trace.get('diff_types', [])
    knowledge_diff = trace.get('knowledge_diff')

    for existing in existing_buckets:
        existing_summary = existing.get('criteria_summary', '')
        # Simple heuristic: check if key patterns match
        if tls_version and tls_version in existing_summary:
            if any(dt in existing_summary for dt in diff_types):
                if knowledge_diff and knowledge_diff[:30] in existing_summary:
                    return True
    return False


def create_bucket(group_key: str, traces: List[Dict], bucket_id: int, round_num: int) -> Dict:
    """Create a bucket from a group of traces."""
    trace = traces[0]  # Representative trace

    tls_version = trace.get('tls_version')
    diff_types = trace.get('diff_types', [])
    first_to_fail = trace.get('first_to_fail')
    knowledge_diff = trace.get('knowledge_diff')
    claim_diff = trace.get('claim_diff')
    ossl_error = trace.get('ossl_error')
    libre_error = trace.get('libre_error')
    ossl_recipe = trace.get('failing_input_recipe_ossl')
    libre_recipe = trace.get('failing_input_recipe_libre')

    # Build folder name
    if diff_types == ["Status"]:
        folder_base = f"tls{tls_version[2]}_status"
        if first_to_fail == "openssl340":
            folder_base += "_ossl"
        else:
            folder_base += "_libre"
        error_part = extract_error_substring(ossl_error if first_to_fail == "openssl340" else libre_error, 20)
        error_part = error_part.replace(" ", "_").lower()
        folder_name = f"{folder_base}_{error_part}_round{round_num}/"
    elif "Knowledges" in diff_types:
        folder_base = f"tls{tls_version[2]}_knowledge"
        if knowledge_diff and "Different(" in knowledge_diff:
            start = knowledge_diff.find("Different(")
            end = knowledge_diff.find(")", start)
            diff_part = knowledge_diff[start + 10:end].replace(", ", "_").lower()
            folder_name = f"{folder_base}_diff_{diff_part}_round{round_num}/"
        else:
            folder_name = f"{folder_base}_round{round_num}/"
    elif "Claims" in diff_types:
        folder_base = f"tls{tls_version[2]}_claim"
        folder_name = f"{folder_base}_round{round_num}/"
    else:
        folder_name = f"round{round_num}_bucket_{bucket_id}/"

    # Build criteria summary
    criteria_parts = [f"tls_version={tls_version}"]
    if first_to_fail:
        criteria_parts.append(f"first_to_fail={first_to_fail}")
    if diff_types == ["Status"]:
        if ossl_error:
            criteria_parts.append(f"ossl_error contains '{extract_error_substring(ossl_error, 30)}'")
        if libre_error:
            criteria_parts.append(f"libre_error contains '{extract_error_substring(libre_error, 30)}'")
    elif knowledge_diff:
        criteria_parts.append(f"knowledge_diff={knowledge_diff[:60]}")
    elif claim_diff:
        criteria_parts.append(f"claim_diff={claim_diff[:60]}")

    criteria_summary = " + ".join(criteria_parts)

    # Build description
    description = f"Behavior in round {round_num}: "
    if diff_types == ["Status"]:
        if first_to_fail == "openssl340":
            description += f"OpenSSL 3.4.0 fails with '{extract_error_substring(ossl_error, 40)}' error in TLS {tls_version}."
        else:
            description += f"LibreSSL 4.2.1 fails with '{extract_error_substring(libre_error, 40)}' error in TLS {tls_version}."
    elif knowledge_diff:
        description += f"Knowledge difference: {knowledge_diff[:80]}"
    elif claim_diff:
        description += f"Claim difference: {claim_diff[:80]}"

    # Representative traces
    representative_traces = [t.get('trace', '') for t in traces[:3]]

    # Build Python condition
    python_condition = build_condition(trace, tls_version, diff_types,
                                       first_to_fail, ossl_error, libre_error,
                                       ossl_recipe, libre_recipe, knowledge_diff, claim_diff)

    return {
        "id": f"B{bucket_id:03d}",
        "round_discovered": round_num,
        "folder_name": folder_name,
        "description": description,
        "criteria_summary": criteria_summary,
        "python_condition": python_condition,
        "representative_traces": representative_traces,
        "tag": None,
        "rfc_section": None,
        "rfc_quote": None
    }


def build_condition(trace, tls_version, diff_types, first_to_fail,
                    ossl_error, libre_error, ossl_recipe, libre_recipe,
                    knowledge_diff, claim_diff):
    """Build Python condition for matching traces."""
    conditions = []

    # Add TLS version check
    conditions.append(f'CheckAgentC(["protocol_config", "tls_version"], "{tls_version}")')

    if diff_types == ["Status"]:
        # Status diff condition
        if first_to_fail == "openssl340":
            error_substr = extract_error_substring(ossl_error, 40)
            conditions.append(f'StatusC(OSSL, in_error="{error_substr}", first_to_fail=True)')
            if ossl_recipe:
                fn_sym = extract_fn_symbol(ossl_recipe)
                if fn_sym:
                    conditions.append(f'TermContainsC(OSSL, "{fn_sym}", last_input_executed=True)')
        else:
            error_substr = extract_error_substring(libre_error, 40)
            conditions.append(f'StatusC(LIBRE, in_error="{error_substr}", first_to_fail=True)')
            if libre_recipe:
                fn_sym = extract_fn_symbol(libre_recipe)
                if fn_sym:
                    conditions.append(f'TermContainsC(LIBRE, "{fn_sym}", last_input_executed=True)')
    elif "Knowledges" in diff_types:
        if knowledge_diff and "Different(" in knowledge_diff:
            start = knowledge_diff.find("Different(")
            end = knowledge_diff.find(")", start)
            diff_part = knowledge_diff[start + 10:end]
            conditions.append(f'InnerKnowledgeC("{diff_part}")')
    elif "Claims" in diff_types:
        if claim_diff and "DifferentTypes[" in claim_diff:
            conditions.append(f'DifferentClaimC()')

    if len(conditions) == 1:
        # Only TLS version
        return conditions[0]
    elif len(conditions) > 1:
        return f"AllC(\n    {', '.join(conditions)}\n)"
    else:
        return "NoDiffC()"


def main():
    batch_files = [
        "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_5/batches/batch_00.json",
        "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_5/batches/batch_01.json",
        "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_5/batches/batch_02.json",
        "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_5/batches/batch_03.json",
        "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_5/batches/batch_04.json",
        "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_5/batches/batch_05.json",
        "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_5/batches/batch_06.json",
    ]

    existing_buckets_file = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/buckets_draft.json"
    output_file = "/home/nbaffou/dev/tlspuffin/triaging-orchestration/state/round_5/classifier_output.json"

    # Load data
    print("Loading traces...")
    traces = load_batches(batch_files)
    print(f"Loaded {len(traces)} total traces")

    existing_buckets, next_id = load_existing_buckets(existing_buckets_file)
    print(f"Found {len(existing_buckets)} existing buckets, starting from ID {next_id + 1}")

    # Group and generate buckets
    print("Grouping traces...")
    groups = group_traces(traces)
    print(f"Found {len(groups)} groups")

    valid_groups = {k: v for k, v in groups.items() if len(v) >= 3}
    print(f"Found {len(valid_groups)} groups with >= 3 traces")

    print("Generating buckets...")
    new_buckets = generate_buckets(valid_groups, existing_buckets, next_id)
    print(f"Generated {len(new_buckets)} new buckets")

    # Write output
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(new_buckets, f, indent=2)

    print(f"Output written to {output_file}")


if __name__ == '__main__':
    main()
