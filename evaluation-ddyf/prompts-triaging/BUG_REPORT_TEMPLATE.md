# Bug Report Template — v3

**One report per root cause.** If multiple buckets share the same missing source-code check, write one report covering all of them.

Cross-references that must appear (see `NAMING_CONVENTIONS.md`):
- Bug report at `BUGS/<root_name>.md`
- Reproducer at `BUGS/reproduce_<root_name>.py`
- All covered buckets listed in the "Bucket(s)" header line

---

```markdown
# [Implementation] [Version] — [One-line root cause]

**Bucket(s):** `objective/<bucket_a>/` (N1 traces), `objective/<bucket_b>/` (N2 traces)
**Reproducer:** `BUGS/reproduce_<root_name>.py`
**Affected version:** [Implementation] [Version]
**Compared against:** [Other implementation] [Version]
**Classification:** [RFC | BENIGN | VULN | Application defect]
**CVSS v3.1:** [score] ([severity]) — `AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X`
**CVE:** [Not warranted | Under assessment | CVE-XXXX-XXXXX]

---

## 1. Summary

One paragraph: what the vulnerable implementation does wrong, what the correct implementation does, and why it matters. State explicitly whether a handshake completes and whether authenticated data is exchanged.

For RFC violations with CVSS 0.0: say so plainly here.

---

## 2. Security Gate Results

Required even for RFC/BENIGN findings — documents *why* the finding is not a CVE.

| Gate | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Finished claim in vulnerable PUT? | YES / NO | `0/N` or specific claim text |
| 2 | Finished from agent processing attacker input? | YES / NO / N/A | agent ID + `outbound` + `server_random` check |
| 3 | Derived keys non-zero? | YES / NO / N/A | hex of `handshake_secret` or "all zeros" |
| 4 | All defense layers absent? | YES / NO / N/A | each layer enumerated, present/absent |
| 5 | End-to-end attack constructible? | YES / NO / N/A | concrete scenario or disqualifier |

**Stopped at:** Gate N (first NO).

### 2.1 Harness-artefact check  *(mandatory if any Gate references metadata field values)*

Before treating a `metadata_*.log` field value (e.g., `handshake_secret`, `master_secret`, `chosen_cipher`, `available_ciphers`) as evidence of in-library state, confirm it isn't a tlspuffin harness artefact:

1. **Locate the populating code** in `tlspuffin/harness/<put>/src/put.c` (or `tlspuffin-claims/`). For LibreSSL, look at `fill_claim()` and its conditional branches on `claim->version.data`.
2. **Confirm unconditional population** on the code path being analyzed. If the harness only fills the field under specific conditions (e.g., only on TLS 1.3 claims), values reported on *other* code paths are zero-initialised struct fields, not real cryptographic state.
3. **Cross-reference with the actual library state** when the trace's interpretation hinges on a key/secret value. A small C harness calling `SSL_SESSION_get_master_key` / `SSL_SESSION_get_id` / `SSL_CIPHER_get_id` on a comparable handshake is sufficient.

**Past failure example:** `libre_v12_sh_v13_cipher_zero_keys` was initially read as "client derives session keys entirely from client_random (all-zero `handshake_secret`)". This was a harness artefact — `fill_claim` at `tlspuffin/harness/libressl/src/put.c:697-707` populates TLS 1.3 secret slots only on the `CLAIM_TLS_VERSION_V1_3` branch, leaving them zero on the v1.2 path. No real crypto happens with zero keys. See `BUGS/libressl_wrong_cipher_acceptance.md` §"Speculative Attack Paths" for the full refutation.

---

## 3. Triggering scenario

Specify exactly what the attacker sends and what state the target reaches. Use tlspuffin function-symbol names where applicable. Reference the bucket's representative trace(s).

---

## 4. Root cause

### [Vulnerable implementation] — the defect

File:line in `vendor/`. Quote the relevant source. Explain what is missing or wrong.

### [Correct implementation] — the reference

File:line in `vendor/`. The equivalent check that the other PUT has.

---

## 5. RFC requirement

Quote the exact MUST/MUST NOT clause verbatim, with section and line number. Specify whether RFC 5246 (TLS 1.2) or RFC 8446 (TLS 1.3) applies.

For non-RFC defects (application-level, API contract): state "not an RFC violation" and explain the implicit contract being broken.

---

## 5a. Upstream-build confirmation  *(mandatory for Track 1 and Track 2 findings; see `SECURITY_GATE.md` Gate 0)*

Demonstrate the defect is not a DDYF fuzz-fork artefact. Verify against the canonical upstream tree (e.g., `github.com/libressl/openbsd` for LibreSSL, `github.com/openssl/openssl` for OpenSSL) at the version corresponding to the vendored build, plus current `master`/`main`.

| Site | Vendor build | Upstream `<tag>` | Upstream `master` | Status |
|---|---|---|---|---|
| `src/lib/libssl/<file>.c` line(s) ... — quote the defect | line N in our build | line M in upstream tag | line K in upstream master | Present / Fixed in <version> / Modified |

State explicitly whether any DDYF patch (`puffin-build/vendors/<lib>/*.cmake`, `vendor/<lib>/src/vendor/patches/`) touches the affected file. If yes, escalate before promoting.

---

## 5b. Comparator-implementation evidence  *(mandatory for defaults / config-default findings)*

For findings that depend on a default-value choice or an API-surface decision, document what the comparator implementation does. Cite specific commits / versions / dates.

| Aspect | This implementation | Comparator implementation | Divergence date / commit |
|---|---|---|---|
| Default value of option X | <value> | <value> | <year>, commit `<sha>` (`<title>`) |
| Macro Y composition | <expansion> | <expansion> | ... |

If the comparator made an analogous fix (e.g., OpenSSL flipped the default in 3.0 via commit `72d2670`), cite the commit URL and the years-since-fix. This is the single most compelling piece of evidence for Track 2 promotion under Framing B (developer trap).

---

## 5c. Documentation acknowledgement  *(mandatory if the issue is acknowledged in upstream docs)*

If the affected function's man page, API doc, or release notes already flag the security implications, quote the relevant text verbatim with a URL. This neutralises any "the maintainers didn't know" framing in the disclosure conversation.

Example (renegotiation): "LibreSSL's `SSL_CTX_set_options(3)` man page on `man.openbsd.org` states: *'The option `SSL_OP_LEGACY_SERVER_CONNECT` is currently set by default even though it has security implications [...]'*"

---

## 5c-bis. Maintainer history  *(mandatory for defaults / config-default findings being promoted to CVE candidate; see `SECURITY_GATE.md` Gate 0 step 6)*

Pre-empt the "we knew it, we accept the trade-off" maintainer pushback by documenting the team's prior deliberation on this code area. Use the following sub-checks:

**Commit history**

```sh
gh api -X GET "search/commits" -f q="repo:<org>/<repo> <option-name>" \
  -H "Accept: application/vnd.github.cloak-preview" \
  --jq '.items[] | "\(.commit.author.date) \(.sha[0:8]) \(.commit.message | split("\n")[0])"'
```

Walk the chronological log for: prior strict-by-default choices the team made for related options, prior audits of the macro the option lives in, recent commits adding *new* options without flipping this one. Each row in your evidence table should cite SHA, date, sign-off, and one-line significance.

**Discussion archives**

- For OpenBSD-tree projects: `marc.info` for `openbsd-tech@` and `libressl@` archives.
- For GitHub-tree projects: `gh api -X GET "search/issues" -f q="repo:<org>/<repo> <term>"`.

If a public thread exists where the team explicitly considered and rejected the change, **cite the thread URL** and explain what *new* evidence (variant unknown at the time, comparator-implementation precedent that postdates the thread, real-world impact survey) justifies a re-examination.

**Template for the bug-report subsection** (worked example: `libressl_unsafe_renegotiation.md` §"LibreSSL maintainer history"):

```markdown
### Maintainer history — the default is deliberate, not an oversight

| Date | Commit | Author / sign-off | Significance |
|---|---|---|---|
| YYYY-MM-DD | `<sha[0:8]>` | `ok <name>@` | One-line significance for the finding |
| ... | ... | ... | ... |

#### What this means for the disclosure framing

This report does NOT ask the team to fix something they have not
considered. It asks them to revisit the <year>-era trade-off in light
of:

1. <New fact 1 not available at the time>
2. <New fact 2>

The disclosure email in `disclosure/email_<root>.md` §<N> contains the
same acknowledgement worded for the upstream audience.
```

**If no maintainer-history evidence is found** after a good-faith search, state so explicitly ("No mailing-list threads or commit messages discussing this default were found between <year> and <today>") — this is also useful information for the disclosure: it tells the maintainers the issue has simply not come up before.

---

## 5d. Real-world impact survey  *(mandatory for Track 2 promotion under Framing B)*

For defaults / API-surface findings, survey major consumers via GitHub code search (`gh api search/code -f q="<term>"`) and document who works around the unsafe default and who doesn't. Five to ten rows is enough.

| Project | Clears the option / applies the workaround? | Notes |
|---|---|---|
| <project> | Yes / No | <one-line context> |

The renegotiation report's §"Real-world TLS clients linked against LibreSSL do not clear the option" table is the worked example.

---

## 5e. Variant matrix  *(mandatory for Track 2 promotion)*

For Track 2 findings, produce a variant matrix exercising at least: default options, hardened (option explicitly cleared), comparator-implementation reference, developer-trap (e.g., `SSL_OP_ALL`), false-safety (e.g., a related option that doesn't actually fix it), and one or two control rows (e.g., a different TLS version that should not be affected).

| # | Variant | Empirically verified | Verdict |
|---|---|---|---|
| V1 | Default-options vulnerable PUT | Yes (`reproduce_*_full.py` row Vn) | BUG |
| V2 | Hardened (option cleared) | Yes | PASS |
| V3 | Comparator reference (OpenSSL/etc.) | Yes | PASS |
| V4 | Developer trap (`SSL_OP_ALL` etc.) | Yes | BUG |
| V5 | False-safety control | Yes | BUG / PASS depending on hypothesis |
| V6 | Version control row | Yes | n/a (orthogonal code path) |

`reproduce_libressl_unsafe_renegotiation_full.py` (V1-V9 matrix) is the worked example.

---

## 6. CVSS v3.1 justification

Each metric with a one-sentence justification. See `CVSS_TLS.md` for guidance.

- **AV:** ... — because [reason]
- **AC:** ... — because [reason]
- ...

Cross-reference the relevant trap from `CVSS_TLS.md` if applicable (e.g., "Trap 4 applies: both PUTs abort → A:N").

---

## 7. Standalone reproducer

```bash
python3 BUGS/reproduce_<root_name>.py
```

Expected output:
```
[paste actual expected trigger line + verdict line — concise]
```

See `REPRODUCER_TEMPLATE.md` for the script structure. If the bug only reproduces in the multi-agent tlspuffin harness and not standalone, the reproducer should print a PASS for the standalone case and reference the bucket traces explicitly — do not pretend either result refutes the other.

---

## 8. Recommended fix

Specific file:line. The minimal change that addresses the immediate defect. Do not propose architectural refactors here.

---

## 9. Evidence references

- Bucket(s): list with trace counts
- Bucket condition: paste the Python `BucketCondition` from `evaluation-ddyf/sort_objectives_ossl_libre.py`
- Vulnerable source: `vendor/...:line`
- Correct source: `vendor/...:line`
- Exhaustive Finished-claim check: `K/N traces show Finished; keys [zero/non-zero]`
- Metadata logs: in `objective/<bucket>/metadata_*.log`

---

## 10. Speculative attack paths  *(OPTIONAL)*

> **Status:** Speculative — not a CVE claim. No CVSS score assigned.

Use this section when the strict Security Gate fails but you can sketch a path to exploitation under specific conditions, see a chained scenario, or notice a fragile assumption in the defense layers. See `SECURITY_GATE.md` "Speculative attack paths" guidance.

### Path 1: <short title>

**Conjectured impact:** what the attacker would achieve

**Mechanism:** step-by-step sketch — what the attacker sends, what state the target reaches, what the attacker gains

**What is missing to verify:**
- specific evidence that would close which gate(s)
- specific deployment / configuration that would need to exist
- specific other finding(s) that would need to combine with this one

**Reason this is not the strict-track CVE:** which gate(s) fail and why current evidence is insufficient

*(Repeat for additional speculative paths.)*

---

> **Omit Section 10 entirely** if you do not have a speculative path worth recording. Do not write empty subsections; do not write "no speculation" — just delete the heading.
```
