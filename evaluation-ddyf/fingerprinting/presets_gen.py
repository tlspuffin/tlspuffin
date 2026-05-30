#!/usr/bin/env python3

import os
import re

VERSIONS = [
    "5.0.0", "5.1.0", "5.1.1", "5.2.0", "5.2.1", "5.3.0", "5.4.0", "5.5.0",
    "5.5.1", "5.5.2", "5.5.3", "5.5.4", "5.6.0", "5.6.2", "5.6.3", "5.6.4",
    "5.6.6", "5.7.0", "5.7.2", "5.7.4", "5.7.6", "5.8.0", "5.8.2", "5.8.4",
    "5.9.0", "5.9.1"
]

PRESETS_FILE = "puffin-build/vendors/wolfssl/presets.toml"

def main():
    if not os.path.exists(PRESETS_FILE):
        print(f"Error: {PRESETS_FILE} not found.")
        return

    with open(PRESETS_FILE, "r") as f:
        content = f.read()

    original_content = content
    blocks_added = 0

    for version in VERSIONS:
        # Convert version to string format for name, e.g. "5.0.0" -> "500", "5.5.4" -> "554"
        name_ver = version.replace(".", "")
        block_name = f"[wolfssl{name_ver}]"

        if block_name in content:
            continue

        v_parts = [int(x) for x in version.split(".")]
        if v_parts >= [5, 5, 0]:
            fix_line = 'fix = ["AllowClaim"]'
        else:
            fix_line = ''

        new_block = f"""
{block_name}
sources = {{ repo = "https://github.com/wolfSSL/wolfssl.git", branch = "v{version}-stable", version = "{version}" }}
builder = {{ type = "builtin", name = "wolfssl" }}
sancov = true
{fix_line}
"""
        content += new_block
        blocks_added += 1

    if blocks_added > 0:
        with open(PRESETS_FILE, "w") as f:
            f.write(content)
        
        import difflib
        diff = difflib.unified_diff(
            original_content.splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile='presets.toml.orig',
            tofile='presets.toml'
        )
        print("".join(diff))
        print(f"Added {blocks_added} blocks.")
    else:
        print("No new blocks added, all present.")

if __name__ == "__main__":
    main()
