# Naming Conventions

Single source of truth for naming buckets, bug reports, reproducers, and bucket comments. Applies throughout v3.

---

## Campaign folder

Every campaign's output artifacts live in a single dated folder at the repo root:

```
triaging-<put1>-<put2>-MM-DD/
```

where `<put1>` and `<put2>` are the PUT identifiers with all digit characters removed (e.g., `openssl340` → `openssl`, `libressl421` → `libressl`), and `MM-DD` is the campaign start date.

Example: `triaging-openssl-libressl-05-18/`

All paths in this document that reference `BUGS/`, `audit/`, `BUCKET_LIST.md`, `SUMMARY_BUCKETS.md`, or `CAMPAIGN_REPORT.md` are **relative to the campaign folder**. Traces and metadata logs stay in `objective/`. The triaging script lives in `evaluation-ddyf/` (for execution) **and** is copied into the campaign folder at the end of Phase 4f as an archival snapshot.

---

## The root-name rule

Every finding has a **root name** — a short, lowercase, underscore-separated identifier that names the root cause of the bug.

Example root names:
- `libressl_record_overflow_bypass`
- `libressl_wrong_cipher_acceptance`
- `openssl_missing_ext_wrong_alert`
- `libressl_hrr_key_share_bad_group`

The root name appears in **three artifacts**, with consistent prefixes/suffixes:

| Artifact | Naming pattern | Example |
|---|---|---|
| Bug report | `<campaign>/BUGS/<root_name>.md` | `triaging-openssl-libressl-05-18/BUGS/libressl_record_overflow_bypass.md` |
| Reproducer | `<campaign>/BUGS/reproduce_<root_name>.py` | `triaging-openssl-libressl-05-18/BUGS/reproduce_libressl_record_overflow_bypass.py` |
| Bucket folder | `objective/<bucket_name>/` (see below for relationship) | `objective/libre_record_overflow_bypass/` |
| Bucket list | `<campaign>/BUCKET_LIST.md` | `triaging-openssl-libressl-05-18/BUCKET_LIST.md` |

The bucket name is allowed to be a **shorter form** of the root name (drop the implementation prefix's redundant suffix, abbreviate "libressl" → "libre" / "openssl" → "ossl" as is common in fuzzing campaigns), but must be unambiguous and always cross-referenced in the bucket comment.

---

## Cross-references

### Bug report header

Every `<campaign>/BUGS/<root_name>.md` must contain a line near the top:

```markdown
**Bucket(s):** `objective/<bucket_name_1>/` (N1 traces), `objective/<bucket_name_2>/` (N2 traces)
**Reproducer:** `BUGS/reproduce_<root_name>.py`
```

(The `BUGS/` prefix in the Reproducer line is relative to the campaign folder.)

### Reproducer docstring

The first line of the reproducer's docstring must reference the bug report:

```python
"""
Reproducer: <one-line root cause>

Companion bug report: BUGS/<root_name>.md
...
"""
```

### Triaging script bucket comment

Every bucket comment in `evaluation-ddyf/sort_objectives_ossl_libre.py` must reference its bug report:

```python
# -------------------------------------------------------------------------
# [RFC] <bucket_name>
#
# <one-line description>
# Bug report: BUGS/<root_name>.md
# Reproducer: BUGS/reproduce_<root_name>.py
# -------------------------------------------------------------------------
```

If a bug report covers multiple buckets, each of those bucket comments references the same report.

---

## Bucket-to-report cardinality

| Case | Cardinality | Example |
|---|---|---|
| One bucket = one root cause | 1 bucket → 1 report | `libre_record_overflow_bypass` → `libressl_record_overflow_bypass.md` |
| Multiple buckets share one root cause | N buckets → 1 report | Silent-abort family: 8 buckets → `libressl_server_unexpected_msg_silent.md` |
| One bucket has two co-occurring root causes | 1 bucket → 2 reports | Discouraged; if a single bucket genuinely has two co-occurring causes, write two reports and have both reference the same bucket |

A bug report **cannot** cover zero buckets (would be a hypothetical bug, not a finding). If you discover a bug during reproducer testing that has no corresponding bucket (like `openssl_s_server_quiet_null_deref` in this campaign), state explicitly in the report: "discovered outside the triaging pipeline."

---

## Allowed abbreviations

For brevity in bucket names where the implementation is otherwise clear from context:

| Long | Short |
|---|---|
| `libressl` | `libre` |
| `openssl` | `ossl` |
| `client_hello` | `ch` |
| `server_hello` | `sh` |
| `hello_retry_request` | `hrr` |
| `extension` | `ext` |
| `signature_algorithms` | `sigalgs` |
| `supported_groups` | `groups` |
| `key_share` | `ks` |

**Bug reports always use the long form** (`libressl_*.md`, `openssl_*.md`). Bucket names may use the short form when needed for length.

---

## BUCKET_LIST.md status — canonical source rule

`BUCKET_LIST.md` status for each bucket is derived from **`SUMMARY_BUCKETS.md` first-occurrence** (the first numbered section — §1 CVE, §2 CVE candidate, §3 RFC, §4 Bug, §5 BENIGN — where the bucket appears). This is the canonical authority.

The triaging script's `[TAG]` comment (`[RFC]`, `[BENIGN]`, etc.) is the *classification tag* written during Phase 2, but `SUMMARY_BUCKETS.md` can promote a bucket (e.g., a `[BENIGN]`-tagged bucket placed in §4 Bugs when a non-RFC defect is discovered). `BUCKET_LIST.md` must match `SUMMARY_BUCKETS.md`, not the triaging script tag.

**Exceptions / edge cases:**
- Buckets without any `[TAG]` in the triaging script (e.g., housekeeping `no_errors/` with `NoDiffC()`) default to `BENIGN` in `BUCKET_LIST.md`.
- A bucket that appears in multiple sections of `SUMMARY_BUCKETS.md` (e.g., a cross-reference entry in §5 BENIGN for a bucket primarily in §4 Bug) takes the status from the **first** section where it appears.

Use `evaluation-ddyf/generate_bucket_list.py` to automate this derivation correctly.

---

## What "consistent" means at the end of the campaign

When the campaign closes, the Auditor will run this check (let `C` = campaign folder). Every row of this table must hold:

```
For every C/BUGS/<X>.md file:
  - There exists C/BUGS/reproduce_<X>.py
  - The report's "Bucket(s):" line lists at least one bucket
  - Every listed bucket folder exists under objective/
  - Every listed bucket folder is non-empty (≥ 1 trace)
  - The bucket comment in sort_objectives_ossl_libre.py references BUGS/<X>.md

For every C/BUGS/reproduce_<X>.py file:
  - There exists C/BUGS/<X>.md
  - The reproducer docstring references BUGS/<X>.md

For every non-empty bucket objective/<B>/:
  - The bucket comment in sort_objectives_ossl_libre.py references some BUGS/<X>.md
  - That C/BUGS/<X>.md exists and lists <B> as a covered bucket

For every bucket name in BUCKET_LIST.md and SUMMARY_BUCKETS.md:
  - The name matches exactly one non-empty directory under objective/

For every empty bucket in sort_objectives_ossl_libre.py:
  - It is removed before campaign close
```

---

## Sanity-check script

A simple shell snippet to run at end of Phase 4 (set `C` to the campaign folder first):

```bash
C="triaging-openssl-libressl-$(date +%m-%d)"   # or whatever the campaign folder is

# Every report has a reproducer
for f in ${C}/BUGS/*.md; do
  base=$(basename "$f" .md)
  [ -f "${C}/BUGS/reproduce_${base}.py" ] || echo "MISSING reproducer for $f"
done

# Every reproducer has a report
for f in ${C}/BUGS/reproduce_*.py; do
  base=$(basename "$f" .py | sed 's/^reproduce_//')
  [ -f "${C}/BUGS/${base}.md" ] || echo "MISSING report for $f"
done

# Every non-empty bucket appears in some bug report
for b in objective/*/; do
  name=$(basename "$b")
  count=$(find "$b" -name "*.trace" | wc -l)
  [ "$count" -eq 0 ] && continue
  grep -rl "objective/${name}/" ${C}/BUGS/*.md > /dev/null 2>&1 \
    || echo "BUCKET $name has $count traces but no bug report references it"
done

# Every bucket appears in BUCKET_LIST.md
for b in objective/*/; do
  name=$(basename "$b")
  count=$(find "$b" -name "*.trace" | wc -l)
  [ "$count" -eq 0 ] && continue
  grep -q "${name}" ${C}/BUCKET_LIST.md \
    || echo "BUCKET $name missing from BUCKET_LIST.md"
done

# Every BENIGN bucket is at least listed in SUMMARY_BUCKETS.md
for b in $(grep -B1 "^\s*\"\([^\"]*\)\":" evaluation-ddyf/sort_objectives_ossl_libre.py \
           | grep -B1 "\[BENIGN\]" | grep "^\s*\"" | sed 's/[^"]*"\([^"]*\)\/?".*/\1/'); do
  grep -q "$b" ${C}/SUMMARY_BUCKETS.md || echo "BENIGN bucket $b not in SUMMARY_BUCKETS.md"
done
```
