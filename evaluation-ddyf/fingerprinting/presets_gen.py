#!/usr/bin/env python3

import os
import sys
import difflib

WOLFSSL_VERSIONS = [
    "5.0.0", "5.1.0", "5.1.1", "5.2.0", "5.2.1", "5.3.0", "5.4.0", "5.5.0",
    "5.5.1", "5.5.2", "5.5.3", "5.5.4", "5.6.0", "5.6.2", "5.6.3", "5.6.4",
    "5.6.6", "5.7.0", "5.7.2", "5.7.4", "5.7.6", "5.8.0", "5.8.2", "5.8.4",
    "5.9.0", "5.9.1"
]

OPENSSL_VERSIONS = [
    "3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.0.5", "3.0.6", "3.0.7", "3.0.8", "3.0.9", "3.0.10", "3.0.11", "3.0.12", "3.0.13", "3.0.14", "3.0.15", "3.0.16", "3.0.17", "3.0.18", "3.0.19", "3.0.20",
    "3.1.0", "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8",
    "3.2.0", "3.2.1", "3.2.2", "3.2.3", "3.2.4",
    "3.2.5", "3.2.6",
    "3.3.0", "3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.3.5", "3.3.6", "3.3.7",
    "3.4.0", "3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5",
    "3.5.0", "3.5.1", "3.5.2", "3.5.3", "3.5.4", "3.5.5", "3.5.6",
    "3.6.0", "3.6.1", "3.6.2"
]

def generate_wolfssl(content):
    blocks_added = 0
    for version in WOLFSSL_VERSIONS:
        name_ver = version.replace(".", "")
        block_name = f"[wolfssl{name_ver}]"
        if block_name in content: continue

        v_parts = [int(x) for x in version.split(".")]
        fix_line = 'fix = ["AllowClaim"]' if v_parts >= [5, 5, 0] else ''

        new_block = f"""
{block_name}
sources = {{ repo = "https://github.com/wolfSSL/wolfssl.git", branch = "v{version}-stable", version = "{version}" }}
builder = {{ type = "builtin", name = "wolfssl" }}
sancov = true
{fix_line}
"""
        content += new_block
        blocks_added += 1
    return content, blocks_added

def generate_openssl(content):
    blocks_added = 0
    for version in OPENSSL_VERSIONS:
        name_ver = version.replace(".", "")
        block_name = f"[openssl{name_ver}]"
        if block_name in content: continue

        new_block = f"""
{block_name}
sources = {{ repo = "https://github.com/openssl/openssl.git", branch = "openssl-{version}", version = "{version}" }}
builder = {{ type = "builtin", name = "openssl" }}
sancov = true
"""
        content += new_block
        blocks_added += 1
    return content, blocks_added

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ["wolfssl", "openssl"]:
        print("Usage: ./presets_gen.py [wolfssl|openssl]")
        return

    vendor = sys.argv[1]
    presets_file = f"puffin-build/vendors/{vendor}/presets.toml"
    
    if not os.path.exists(presets_file):
        print(f"Error: {presets_file} not found.")
        return

    with open(presets_file, "r") as f:
        content = f.read()

    original_content = content

    if vendor == "wolfssl":
        content, blocks_added = generate_wolfssl(content)
    else:
        content, blocks_added = generate_openssl(content)

    if blocks_added > 0:
        with open(presets_file, "w") as f:
            f.write(content)
        
        diff = difflib.unified_diff(
            original_content.splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile='presets.toml.orig',
            tofile='presets.toml'
        )
        print("".join(diff))
        print(f"Added {blocks_added} blocks for {vendor}.")
    else:
        print(f"No new blocks added for {vendor}, all present.")

if __name__ == "__main__":
    main()
