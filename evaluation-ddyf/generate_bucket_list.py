"""
Generate BUCKET_LIST.md for a DDYF triaging campaign.

Usage:
    python -m evaluation-ddyf.generate_bucket_list <campaign_folder>

Example:
    python -m evaluation-ddyf.generate_bucket_list triaging-openssl-libressl-04-28

Reads:
  - evaluation-ddyf/sort_objectives_*.py  → bucket order and [TAG] comments
  - <campaign>/SUMMARY_BUCKETS.md         → canonical status (first-occurrence)
  - objective/<bucket>/                   → live trace counts

Writes:
  - <campaign>/BUCKET_LIST.md

Status canonical-source rule:
  SUMMARY_BUCKETS.md first-occurrence wins over the triaging script [TAG] comment.
  A bucket tagged [BENIGN] in the script but placed in §4 Bugs in the summary
  gets status "Bug" in BUCKET_LIST.md. Buckets with no [TAG] default to "BENIGN".
"""

import re
import os
import sys
import datetime


def _find_triaging_script(base_dir="."):
    for name in sorted(os.listdir(os.path.join(base_dir, "evaluation-ddyf"))):
        if name.startswith("sort_objectives_") and name.endswith(".py"):
            return os.path.join(base_dir, "evaluation-ddyf", name)
    raise FileNotFoundError("No sort_objectives_*.py found in evaluation-ddyf/")


def _put_names(script_text):
    m1 = re.search(r'FIRST_PUT\s*=\s*"(\w+)"', script_text)
    m2 = re.search(r'SECOND_PUT\s*=\s*"(\w+)"', script_text)
    p1 = re.sub(r"\d+", "", m1.group(1)) if m1 else "put1"
    p2 = re.sub(r"\d+", "", m2.group(1)) if m2 else "put2"
    return p1, p2


def _bucket_order(script_text):
    return [m.group(1) for m in re.finditer(r'\n\s+"([\w_]+)/"\s*:', script_text)]


def _summary_status_map(summary_path):
    """First-occurrence wins. Returns {bucket_name: status_string}."""
    section_map = {1: "CVE", 2: "CVE candidate", 3: "RFC", 4: "Bug", 5: "BENIGN"}
    status = {}
    section = None
    try:
        text = open(summary_path).read()
    except FileNotFoundError:
        return {}
    for line in text.splitlines():
        m_sec = re.match(r"^##\s+(\d+)\.", line)
        if m_sec:
            sec_num = int(m_sec.group(1))
            section = section_map.get(sec_num)
        if section:
            m_bucket = re.match(r"\|\s*`([\w_]+)`", line)
            if m_bucket and m_bucket.group(1) not in status:
                status[m_bucket.group(1)] = section
    return status


def _summary_desc_map(summary_path):
    """Extract one-line descriptions from summary table rows."""
    descs = {}
    in_section = False
    try:
        text = open(summary_path).read()
    except FileNotFoundError:
        return {}
    for line in text.splitlines():
        if re.match(r"^##\s+[1-5]\.", line):
            in_section = True
        elif re.match(r"^##\s+[6-9]", line):
            in_section = False
        if not in_section:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 4:
            bm = re.match(r"`([\w_]+)`", parts[1])
            if bm:
                raw = parts[-2] if parts[-1] == "" else parts[-1]
                desc = re.sub(r"\[.*?\]\(.*?\)", "", raw).strip()
                if desc and not desc.startswith("*See") and not desc.startswith("—"):
                    if bm.group(1) not in descs:
                        descs[bm.group(1)] = desc[:105]
    return descs


def _count_traces(bucket_name, objective_dir="objective"):
    path = os.path.join(objective_dir, bucket_name)
    if not os.path.isdir(path):
        return 0
    return sum(1 for f in os.listdir(path) if f.endswith(".trace"))


def generate(campaign_folder, base_dir="."):
    campaign_folder = campaign_folder.rstrip("/")
    script_path = _find_triaging_script(base_dir)
    script_text = open(script_path).read()

    put1, put2 = _put_names(script_text)
    buckets = _bucket_order(script_text)

    summary_path = os.path.join(base_dir, campaign_folder, "SUMMARY_BUCKETS.md")
    status_map = _summary_status_map(summary_path)
    desc_map = _summary_desc_map(summary_path)

    default_descs = {
        "no_errors": "No observable difference; trace-replay artefact (non-deterministic execution)",
    }

    order = {"CVE": 0, "CVE candidate": 1, "RFC": 2, "Bug": 3, "BENIGN": 4}

    rows = []
    for bname in buckets:
        count = _count_traces(bname, os.path.join(base_dir, "objective"))
        status = status_map.get(bname, "BENIGN")
        desc = desc_map.get(bname, default_descs.get(bname, "—"))
        rows.append((bname, status, count, desc))

    rows.sort(key=lambda r: (order.get(r[1], 9), -r[2]))

    total_classified = sum(r[2] for r in rows)
    today = datetime.date.today().strftime("%m-%d")

    lines = [
        f"# Bucket List — {put1.capitalize()} vs {put2.capitalize()}, {today}",
        "",
        f"**Total buckets:** {len(rows)}  "
        f"**Total traces classified:** {total_classified:,}",
        "",
        "| Bucket | Status | Traces | Root cause (one line) |",
        "|---|---|---|---|",
    ]
    for bname, status, count, desc in rows:
        lines.append(f"| `{bname}` | {status} | {count} | {desc} |")

    out_path = os.path.join(base_dir, campaign_folder, "BUCKET_LIST.md")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Written: {out_path} ({len(rows)} rows, {total_classified:,} traces)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    generate(sys.argv[1])
