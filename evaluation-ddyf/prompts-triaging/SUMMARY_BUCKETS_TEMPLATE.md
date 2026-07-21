# SUMMARY_BUCKETS.md — Template

This file documents the mandatory `SUMMARY_BUCKETS.md` artifact produced at end of Phase 4. Write the actual file at `<campaign>/SUMMARY_BUCKETS.md` (inside the campaign folder, e.g., `triaging-openssl-libressl-05-18/SUMMARY_BUCKETS.md`).

**Also write `<campaign>/BUCKET_LIST.md`** — a dedicated minimal flat table produced *before* SUMMARY_BUCKETS.md, containing only: bucket name, status (CVE-candidate / RFC / Bug / BENIGN), trace count, and a one-line root cause. Template:

```markdown
# Bucket List — <PUT1> vs <PUT2>, MM-DD

| Bucket | Status | Traces | Root cause (one line) |
|---|---|---|---|
| `alert_illegal_param_vs_decode_err` | BENIGN | 3666 | Alert-code divergence; RFC 8446 §6 allows both codes |
| `libre_record_overflow_bypass` | RFC | 32 | Plaintext record skips SSL3_RT_MAX_PLAIN_LENGTH check |
| ... | ... | ... | ... |
```

`BUCKET_LIST.md` is the machine-readable index (no prose, no sub-sections). `SUMMARY_BUCKETS.md` is the narrative summary with links and RFC citations.

The summary is a single flat table grouping all non-empty buckets by severity category. It is the campaign's at-a-glance reference. The detailed bug-to-bucket mapping (both directions) lives in `CAMPAIGN_REPORT.md`; `SUMMARY_BUCKETS.md` is the flat view.

---

## Template

```markdown
# Summary of Buckets — <PUT1> vs <PUT2> Campaign

**Campaign date:** YYYY-MM-DD
**Total traces:** N
**Coverage:** Q (% classified)

---

## Legend

- **CVE candidate** — empirically verified bug with a defensible CVSS framing and a documented upstream filing path. Includes (a) `[VULN]` findings that pass all 5 Security Gates *and* (b) findings that fail one or more Gates but nevertheless have a verified end-to-end PoC, a non-zero CVSS under at least one framing, and a recommended path to upstream disclosure / CVE assignment. **Does not require an already-assigned CVE number** — only confirmed *filing potential*.
- **RFC violation** — `[RFC]` with documented MUST/MUST NOT violation but no confirmed CVE-filing potential
- **Bug (non-RFC)** — internal API defects, CLI tool defects, or implementation defects that do not violate an RFC MUST clause; no CVE-filing path identified
- **BENIGN** — spec-permitted differences (alert-code variation, timing, message coalescing)

> A bucket lives in §1 if it has CVE-filing potential, regardless of whether the strict 5-gate `[VULN]` test passes. The strict gate test is still recorded in the bug report (Security Gate Results section); §1 inclusion only requires:
>   (i) **empirical end-to-end verification** of the defect (a working PoC),
>   (ii) **at least one CVSS framing with non-zero score** (e.g., compounded with another peer-side bug, or under specific deployment conditions), and
>   (iii) **an explicit disclosure path** documented in the report (upstream contact identified, draft email or filing plan ready).
>
> Bugs that fail (i)–(iii) stay in §2 (`[RFC]`) or §3 (non-RFC bug) per the existing taxonomy.

---

## 1. CVE candidates

| Bucket / source | Traces | Bug report | CVSS (framing) | Status | One-line summary |
|---|---|---|---|---|---|
| `<bucket_name>` | N | [BUGS/<name>.md](BUGS/<name>.md) | X.X (Severity) under <framing>; lower framings noted | not yet disclosed / draft sent YYYY-MM-DD / CVE-YYYY-NNNNN assigned / declined by vendor | One-line summary of the defect and its strongest framing |

*(empty if no buckets meet criteria (i)–(iii). Do not list "none"; state explicitly: "No buckets in this campaign meet CVE-candidate criteria; closest candidates investigated and reasons for non-promotion are documented in §6 of each respective bug report.")*

---

## 2. RFC violations

| Bucket | Traces | Bug report | RFC | One-line root cause |
|---|---|---|---|---|
| `<bucket_name>` | N | [BUGS/<name>.md](BUGS/<name>.md) | RFC XXXX §X.Y | ... |

---

## 3. Bugs (non-RFC)

| Bucket / source | Traces | Bug report | CVSS | One-line root cause |
|---|---|---|---|---|
| `<bucket_name>` or "discovered during reproducer testing" | N or N/A | [BUGS/<name>.md](BUGS/<name>.md) | X.X (Severity) | ... |

---

## 4. BENIGN differences

| Bucket | Traces | Category | Spec basis |
|---|---|---|---|
| `<bucket_name>` | N | Alert-code divergence / Timing / Leniency / Other | RFC XXXX §X.Y allows this |

---

## Totals

| Category | Buckets | Bucket % | Traces | Trace % |
|---|---|---|---|---|
| CVE *(strict `[VULN]`, passes all 5 Security Gates)* | N | N/totalBuckets | T | T/totalTraces |
| CVE candidate *(empirical PoC + non-zero CVSS framing + drafted disclosure)* | N | N/totalBuckets | T | T/totalTraces |
| RFC violation | N | N/totalBuckets | T | T/totalTraces |
| Bug (non-RFC) | N | N/totalBuckets | T | T/totalTraces |
| BENIGN | N | N/totalBuckets | T | T/totalTraces |
| Non-triaged | — | — | 0 (must be 0) | 0% |
| **Total** | **N** | **100%** | **T** | **100%** |

**Both ratios are mandatory.** The "Bucket %" column counts buckets toward the category total (so a campaign with 1 CVE bucket and 60 BENIGN buckets shows the CVE share as 1/61 ≈ 1.6% even if the CVE bucket dominates traces). This balances the trace-fraction view (where a single CVE bucket might be a fraction of a percent of traces but still the single most important finding).

**Canonical category order across all triaging docs:** CVE → CVE candidate → RFC violation → Bug (non-RFC) → BENIGN → Non-triaged. Use this order in §1–§5 of `SUMMARY_BUCKETS.md`, in the Totals table here, in `BUCKET_LIST.md` (with rows grouped and sorted by category in this order, then by descending trace count within each category), and in the campaign-level `CAMPAIGN_REPORT.md` Classification Summary. Do not introduce ad-hoc orderings; this canonical order makes cross-document audits mechanical.

---

## Coverage check

All non-empty buckets in `evaluation-ddyf/sort_objectives_ossl_libre.py` appear in exactly one row above. All empty buckets have been deleted from the script (see `NAMING_CONVENTIONS.md` cleanup rule).

---

## 5. Speculative attack paths and research notes  *(OPTIONAL)*

> **Status:** Speculative — not CVE claims. No CVSS scores. Not aggregated into the totals above.

Findings that fail the Security Gate in isolation but have a sketched path to exploitation are recorded here (or in their respective bug reports under Section 10). Useful as "Future work" / "Discussion" material for the academic paper.

| # | Title | Components | Conjectured impact | What's missing to verify |
|---|---|---|---|---|
| S1 | <short title> | `bucket_a`, `bucket_b` | <one-line impact> | <specific evidence needed> |
| S2 | ... | ... | ... | ... |

Omit Section 5 entirely if no speculative paths are worth recording. Do not list "none" — just delete the heading.
```

---

## Rules for filling in this template

### Rule A — Every non-empty bucket appears in exactly one section

A bucket cannot be both "CVE candidate" and "RFC violation" — CVE-candidate classification supersedes RFC if both apply. Pick the most severe classification and put the bucket in that section.

Specifically, the precedence order is:
1. **CVE candidate** (meets all three §1 inclusion criteria) — promote out of §2/§3 into §1.
2. **RFC violation** (documented MUST/MUST NOT, but no CVE-filing path) — keep in §2.
3. **Bug (non-RFC)** (implementation defect, no RFC clause violated, no CVE-filing path) — keep in §3.
4. **BENIGN** — §4.

When promoting a bucket, leave a one-line cross-reference in its original section: `*(<bucket_name> — N traces — promoted to §1 CVE candidates; see above.)*`

### Rule B — BENIGN buckets are listed even if they have no bug report

BENIGN differences don't need bug reports, but they must still appear in section 4 with a one-line spec basis explaining why they are permitted.

### Rule C — Non-triaged count must be 0

If the triaging script has a non-triaged catch-all bucket and it contains traces, the campaign is not complete. Either:
- Investigate the residual traces and create a bucket for them
- Confirm they are flaky / non-deterministic and put them in a BENIGN `no_errors` or `flaky` bucket

### Rule D — Bucket names match the triaging script exactly

Copy bucket names verbatim from `evaluation-ddyf/sort_objectives_ossl_libre.py`. Do not abbreviate or paraphrase.

### Rule E — Bug-report links use repo-relative paths

`[BUGS/<name>.md](BUGS/<name>.md)` — not absolute paths, not external URLs.

### Rule F — Trace counts come from the live filesystem

Run `find objective/<bucket>/ -name "*.trace" | wc -l` for each bucket; do not rely on stale counts from earlier runs.

---

## Worked example  *(from the OpenSSL-vs-LibreSSL campaign)*

```markdown
# Summary of Buckets — OpenSSL 3.4.0 vs LibreSSL 4.2.1

**Campaign date:** YYYY-MM-DD – YYYY-MM-DD
**Total traces:** 20,975
**Coverage:** 99.98% classified (4 non-triaged in residual catch-all)

## 1. CVE candidates

*(none — all candidates investigated and refuted, OR no buckets meet criteria (i)–(iii); see Legend)*

## 2. RFC violations

| Bucket | Traces | Bug report | RFC | One-line root cause |
|---|---|---|---|---|
| `libre_record_overflow_bypass` | 32 | [BUGS/libressl_record_overflow_bypass.md](BUGS/libressl_record_overflow_bypass.md) | RFC 5246 §6.2.1 | Plaintext record path skips `SSL3_RT_MAX_PLAIN_LENGTH` check |
| `libre_v12_sh_v13_cipher_zero_keys` | 8 | [BUGS/libressl_wrong_cipher_acceptance.md](BUGS/libressl_wrong_cipher_acceptance.md) | RFC 8446 §4.1.3 | Client accepts TLS 1.3 cipher in TLS 1.2 ServerHello |
| `ossl_alert_silent_server_unexpected_msg` | 146 | [BUGS/libressl_server_unexpected_msg_silent.md](BUGS/libressl_server_unexpected_msg_silent.md) | RFC 5246 §7.2.2 | TLS 1.2 server lacks pre-flight state-machine guard |
| ... | ... | ... | ... | ... |

## 3. Bugs (non-RFC)

| Bucket / source | Traces | Bug report | CVSS | One-line root cause |
|---|---|---|---|---|
| `libre_finished_claim_silent_ossl` | 2128 | [BUGS/libressl_callback_ordering_defect.md](BUGS/libressl_callback_ordering_defect.md) | 2.7 (Low) | `msg_callback` fires before message-type validation in TLS 1.3 path |
| Discovered during reproducer testing | N/A | [BUGS/openssl_s_server_quiet_null_deref.md](BUGS/openssl_s_server_quiet_null_deref.md) | 5.3 (Medium) | `s_server -quiet` null function pointer on any ClientHello |

## 4. BENIGN differences

| Bucket | Traces | Category | Spec basis |
|---|---|---|---|
| `alert_illegal_param_vs_decode_err` | 3666 | Alert-code divergence | RFC 8446 §6 — alert code selection is implementation-defined |
| `no_errors` | 463 | Flaky / non-deterministic | No observable difference; trace replay artefact |
| ... | ... | ... | ... |

## Totals

| Category | Buckets | Bucket % | Traces | Trace % |
|---|---|---|---|---|
| CVE | 0 | 0.0% | 0 | 0.0% |
| CVE candidate | 0 | 0.0% | 0 | 0.0% |
| RFC violation | 21 | 35.0% | 3,525 | 16.8% |
| Bug (non-RFC) | 1 (+1 external) | 1.7% | 2,128 | 10.1% |
| BENIGN | 38 | 63.3% | 15,318 | 73.0% |
| Non-triaged | — | — | 4 | <0.1% |
| **Total** | **60** | **100%** | **20,975** | **100%** |
```
