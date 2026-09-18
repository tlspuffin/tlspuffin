# DDYF triaging — templates

> **Protocol-agnostic methodology — TLS is the worked example.** The concrete names in this file (`openssl340`/`libressl421`, `tlspuffin`, `sort_objectives_ossl_libre.py`, TLS error strings / RFCs) are the running **TLS example**. For another protocol, substitute the placeholders defined in `START_HERE.md` § Protocol configuration — e.g. SSH: `libssh0114`/`wolfssh`, `sshpuffin`, `ssh/sort_objectives_libssh_wolfssh.py`, RFC 4251-4254.


The Phase-4 output templates, collected into one file (formerly four separate
`*_TEMPLATE.md` files). Each section below is one template; jump to the one you need:

- **Bug report** — structure for every `BUGS/*.md` report.
- **Reproducer** — strict template for minimal standalone `BUGS/reproduce_*.py`.
- **Summary-buckets** — structure for the campaign-wide `SUMMARY_BUCKETS.md` artifact.
- **Investigation prompt** — brief for delegating a targeted source-code investigation to a separate session.


---

## Bug Report Template — v3

**One report per root cause.** If multiple buckets share the same missing source-code check, write one report covering all of them.

Cross-references that must appear (see `NAMING_CONVENTIONS.md`):
- Bug report at `BUGS/<root_name>.md`
- Reproducer at `BUGS/reproduce_<root_name>.py`
- All covered buckets listed in the "Bucket(s)" header line

---

```markdown
## [Implementation] [Version] — [One-line root cause]

**Bucket(s):** `objective/<bucket_a>/` (N1 traces), `objective/<bucket_b>/` (N2 traces)
**Reproducer:** `BUGS/reproduce_<root_name>.py`
**Affected version:** [Implementation] [Version]
**Compared against:** [Other implementation] [Version]
**Classification:** [RFC | BENIGN | VULN | Application defect]
**CVSS v3.1:** [score] ([severity]) — `AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X`
**CVE:** [Not warranted | Under assessment | CVE-XXXX-XXXXX]

---

### 1. Summary

One paragraph: what the vulnerable implementation does wrong, what the correct implementation does, and why it matters. State explicitly whether a handshake completes and whether authenticated data is exchanged.

For RFC violations with CVSS 0.0: say so plainly here.

---

### 2. Security Gate Results

Required even for RFC/BENIGN findings — documents *why* the finding is not a CVE.

| Gate | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Finished claim in vulnerable PUT? | YES / NO | `0/N` or specific claim text |
| 2 | Finished from agent processing attacker input? | YES / NO / N/A | agent ID + `outbound` + `server_random` check |
| 3 | Derived keys non-zero? | YES / NO / N/A | hex of `handshake_secret` or "all zeros" |
| 4 | All defense layers absent? | YES / NO / N/A | each layer enumerated, present/absent |
| 5 | End-to-end attack constructible? | YES / NO / N/A | concrete scenario or disqualifier |

**Stopped at:** Gate N (first NO).

#### 2.1 Harness-artefact check  *(mandatory if any Gate references metadata field values)*

Before treating a `metadata_*.log` field value (e.g., `handshake_secret`, `master_secret`, `chosen_cipher`, `available_ciphers`) as evidence of in-library state, confirm it isn't a tlspuffin harness artefact:

1. **Locate the populating code** in `tlspuffin/harness/<put>/src/put.c` (or `tlspuffin-claims/`). For LibreSSL, look at `fill_claim()` and its conditional branches on `claim->version.data`.
2. **Confirm unconditional population** on the code path being analyzed. If the harness only fills the field under specific conditions (e.g., only on TLS 1.3 claims), values reported on *other* code paths are zero-initialised struct fields, not real cryptographic state.
3. **Cross-reference with the actual library state** when the trace's interpretation hinges on a key/secret value. A small C harness calling `SSL_SESSION_get_master_key` / `SSL_SESSION_get_id` / `SSL_CIPHER_get_id` on a comparable handshake is sufficient.

**Past failure example:** `libre_v12_sh_v13_cipher_zero_keys` was initially read as "client derives session keys entirely from client_random (all-zero `handshake_secret`)". This was a harness artefact — `fill_claim` at `tlspuffin/harness/libressl/src/put.c:697-707` populates TLS 1.3 secret slots only on the `CLAIM_TLS_VERSION_V1_3` branch, leaving them zero on the v1.2 path. No real crypto happens with zero keys. See `BUGS/libressl_wrong_cipher_acceptance.md` §"Speculative Attack Paths" for the full refutation.

---

### 3. Triggering scenario

Specify exactly what the attacker sends and what state the target reaches. Use tlspuffin function-symbol names where applicable. Reference the bucket's representative trace(s).

---

### 4. Root cause

#### [Vulnerable implementation] — the defect

File:line in `vendor/`. Quote the relevant source. Explain what is missing or wrong.

#### [Correct implementation] — the reference

File:line in `vendor/`. The equivalent check that the other PUT has.

---

### 5. RFC requirement

Quote the exact MUST/MUST NOT clause verbatim, with section and line number. Specify whether RFC 5246 (TLS 1.2) or RFC 8446 (TLS 1.3) applies.

For non-RFC defects (application-level, API contract): state "not an RFC violation" and explain the implicit contract being broken.

---

### 5a. Upstream-build confirmation  *(mandatory for Track 1 and Track 2 findings; see `tls/SECURITY_GATE_TLS.md` Gate 0)*

Demonstrate the defect is not a DDYF fuzz-fork artefact. Verify against the canonical upstream tree (e.g., `github.com/libressl/openbsd` for LibreSSL, `github.com/openssl/openssl` for OpenSSL) at the version corresponding to the vendored build, plus current `master`/`main`.

| Site | Vendor build | Upstream `<tag>` | Upstream `master` | Status |
|---|---|---|---|---|
| `src/lib/libssl/<file>.c` line(s) ... — quote the defect | line N in our build | line M in upstream tag | line K in upstream master | Present / Fixed in <version> / Modified |

State explicitly whether any DDYF patch (`puffin-build/vendors/<lib>/*.cmake`, `vendor/<lib>/src/vendor/patches/`) touches the affected file. If yes, escalate before promoting.

---

### 5b. Comparator-implementation evidence  *(mandatory for defaults / config-default findings)*

For findings that depend on a default-value choice or an API-surface decision, document what the comparator implementation does. Cite specific commits / versions / dates.

| Aspect | This implementation | Comparator implementation | Divergence date / commit |
|---|---|---|---|
| Default value of option X | <value> | <value> | <year>, commit `<sha>` (`<title>`) |
| Macro Y composition | <expansion> | <expansion> | ... |

If the comparator made an analogous fix (e.g., OpenSSL flipped the default in 3.0 via commit `72d2670`), cite the commit URL and the years-since-fix. This is the single most compelling piece of evidence for Track 2 promotion under Framing B (developer trap).

---

### 5c. Documentation acknowledgement  *(mandatory if the issue is acknowledged in upstream docs)*

If the affected function's man page, API doc, or release notes already flag the security implications, quote the relevant text verbatim with a URL. This neutralises any "the maintainers didn't know" framing in the disclosure conversation.

Example (renegotiation): "LibreSSL's `SSL_CTX_set_options(3)` man page on `man.openbsd.org` states: *'The option `SSL_OP_LEGACY_SERVER_CONNECT` is currently set by default even though it has security implications [...]'*"

---

### 5c-bis. Maintainer history  *(mandatory for defaults / config-default findings being promoted to CVE candidate; see `tls/SECURITY_GATE_TLS.md` Gate 0 step 6)*

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
#### Maintainer history — the default is deliberate, not an oversight

| Date | Commit | Author / sign-off | Significance |
|---|---|---|---|
| YYYY-MM-DD | `<sha[0:8]>` | `ok <name>@` | One-line significance for the finding |
| ... | ... | ... | ... |

##### What this means for the disclosure framing

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

### 5d. Real-world impact survey  *(mandatory for Track 2 promotion under Framing B)*

For defaults / API-surface findings, survey major consumers via GitHub code search (`gh api search/code -f q="<term>"`) and document who works around the unsafe default and who doesn't. Five to ten rows is enough.

| Project | Clears the option / applies the workaround? | Notes |
|---|---|---|
| <project> | Yes / No | <one-line context> |

The renegotiation report's §"Real-world TLS clients linked against LibreSSL do not clear the option" table is the worked example.

---

### 5e. Variant matrix  *(mandatory for Track 2 promotion)*

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

### 6. CVSS v3.1 justification

Each metric with a one-sentence justification. See `tls/CVSS_TLS.md` for guidance.

- **AV:** ... — because [reason]
- **AC:** ... — because [reason]
- ...

Cross-reference the relevant trap from `tls/CVSS_TLS.md` if applicable (e.g., "Trap 4 applies: both PUTs abort → A:N").

---

### 7. Standalone reproducer

```bash
python3 BUGS/reproduce_<root_name>.py
```

Expected output:
```
[paste actual expected trigger line + verdict line — concise]
```

See `TEMPLATES.md` (Reproducer) for the script structure. If the bug only reproduces in the multi-agent tlspuffin harness and not standalone, the reproducer should print a PASS for the standalone case and reference the bucket traces explicitly — do not pretend either result refutes the other.

---

### 8. Recommended fix

Specific file:line. The minimal change that addresses the immediate defect. Do not propose architectural refactors here.

---

### 9. Evidence references

- Bucket(s): list with trace counts
- Bucket condition: paste the Python `BucketCondition` from `evaluation-ddyf/sort_objectives_ossl_libre.py`
- Vulnerable source: `vendor/...:line`
- Correct source: `vendor/...:line`
- Exhaustive Finished-claim check: `K/N traces show Finished; keys [zero/non-zero]`
- Metadata logs: in `objective/<bucket>/metadata_*.log`

---

### 10. Speculative attack paths  *(OPTIONAL)*

> **Status:** Speculative — not a CVE claim. No CVSS score assigned.

Use this section when the strict Security Gate fails but you can sketch a path to exploitation under specific conditions, see a chained scenario, or notice a fragile assumption in the defense layers. See `tls/SECURITY_GATE_TLS.md` "Speculative attack paths" guidance.

#### Path 1: <short title>

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

---

## When the finding is in the fuzzer/harness itself (not either PUT)

Every template above assumes the bug belongs to one of the two PUTs. Occasionally a differential
diverges because of a defect in the **measurement apparatus** — the `tlspuffin`/`sshpuffin`
harness (`harness/<put>/src/put.c`), the claim oracle, or the triaging tooling — while **both
PUTs behave correctly on the wire**. The canonical SSH example is a claim emitted from a
pre-verification callback while the library still rejects the input (see
`ssh/SECURITY_GATE_SSH.md` Gate 0's harness-vs-library trap). Fill the header differently for
these findings:

- **Classification: `Bug (non-RFC)`.** It is a real defect worth fixing, but not an RFC
  violation and not a PUT vulnerability. It lands in **§3 (Bugs, non-RFC)** of
  `SUMMARY_BUCKETS.md`.
- **CVSS v3.1: `Not applicable`** — state "Not applicable — test-harness/oracle instrumentation
  defect, not a network-facing implementation." Do **not** invent a vector.
- **"Compared against":** the *other harness* (e.g. "the libssh 0.11.4 harness, which gates the
  claim correctly"), **not** the other library version. The point of comparison is which
  harness is right, not which library.
- **"Affected component":** name the harness file:line and say explicitly "**not** <put1>,
  **not** <put2>".
- **Security Gate Results:** run the gate anyway and record where it stops — the harness-vs-
  library check (SSH Gate 0 / the §2.1 Harness-artefact check below) is what *proves* the
  divergence is in the apparatus. Confirm on the wire that the "successful" stack actually sent
  a rejection.
- **RFC requirement:** "Not an RFC violation — RFCs do not constrain test-harness
  instrumentation." Both PUTs are conformant.
- **Naming caution:** a bucket *named* `benign_*` (a common naming family for harness/known
  artefacts) is **not** automatically BENIGN — the `SUMMARY_BUCKETS.md` category is canonical
  over the bucket name/tag (see `NAMING_CONVENTIONS.md` § "BUCKET_LIST.md status — canonical
  source rule"). A `benign_harness_*` bucket whose root cause is a harness defect is category
  **Bug**, not BENIGN.

The worked example is the SSH campaign's `sshpuffin_harness_wolfssh_claim_timing` report (a
premature auth claim fired before wolfSSH's signature check, while wolfSSH itself sent
`USERAUTH_FAILURE` on the wire).

---

## Reproducer Template — Strict

Every bug report in `BUGS/` has a paired reproducer at `BUGS/reproduce_<root_name>.py`. The reproducer must satisfy all rules below.

---

### Hard rules

1. **No absolute paths.** Use repo-relative paths only (`vendor/libressl421/...`, `BUGS/...`). The reproducer must run from the repo root with `python3 BUGS/reproduce_X.py`.
2. **Self-starting.** The reproducer spawns its own server/client via `subprocess.Popen` — it does not depend on a manually started service.
3. **Minimal.** ≤ ~150 lines of executable code (excluding the docstring). Cut anything not strictly needed to trigger the bug and report PASS/FAIL.
4. **Concise output.** Print the trigger summary, the observed result, and the verdict. Do **not** re-paste the bug report's root-cause analysis, RFC quotes, or recommended fix — those live in the `.md` file.
5. **Build/run instructions at the top.** The docstring must specify:
   - How to build the binaries (or where they live in this repo)
   - Required env vars (if any)
   - Exact CLI command to run the reproducer
   - Expected output (PASS / FAIL pattern)
6. **No `-quiet` on `openssl s_server`.** This flag triggers a null-pointer crash in the project's sanitized binary on any ClientHello.

---

### Evidence-layer progression  *(for Track 2 / CVE-candidate findings)*

For findings being considered for CVE-candidate promotion, build evidence layer-by-layer. Each layer answers a more specific question than the previous one. Stop at the layer where the evidence is conclusive for the framing being claimed — don't over-engineer Layer 4 when Layer 2 settles the question.

> **L1 is mandatory even for `[RFC]` findings — not just `[VULN]`/CVE.** A conformance
> claim asserts a *runtime* behaviour of the stock library, so it must be backed by an
> empirical **L1** reproducer (a tiny harness or a fresh-build-over-TCP PoC) that exhibits
> the behaviour against the stock upstream build — never L0 (code citation) alone. Citing
> the source line shows the code *could* behave that way; L1 shows it *does*. The SSH banner
> (#5) and port-echo (#3) findings are the worked example: each has a stock-build TCP PoC,
> not just a `file:line`. `[BENIGN]` findings need only L0 unless they are being argued up
> to `[RFC]`.

| Layer | Question answered | Typical artefact | Effort |
|---|---|---|---|
| **L0** | "Does the affected code exist?" | Inline citations to `file:line` in the bug report; upstream cross-check per `tls/SECURITY_GATE_TLS.md` Gate 0 | Minutes |
| **L1** | "What value does the affected setting take at runtime in stock builds?" | Tiny C harness (10-30 LOC) printing `SSL_CTX_get_options`, macro evaluations, struct-field values; compile against the vendor `libssl.a + libcrypto.a` | ~30 minutes |
| **L2** | "Does a CLI client / server exhibit the bug against a Python-synthesised peer?" | `s_client` or `s_server` invoked via subprocess against a Python TCP listener that crafts the malformed message bytes by hand | ~1-2 hours |
| **L3** | "Does the bug persist when the application explicitly opts into the defaults / when a developer-trap option is set?" | A custom C harness with selectable options (e.g., `argv[1] = "default" / "clear_legacy" / "set_op_all"`) driving the same Python listener as L2 | ~2-3 hours |
| **L4** | "Does the full state machine of the affected role complete the handshake / reach the security-critical step?" | A Python implementation of the relevant TLS state machine (using `pyca/cryptography` primitives) that drives full handshakes with selectable variants — initial connect, mid-session renegotiation, multi-version, etc. | ~1 day for a clean implementation |

**Mapping to the strongest framing being claimed:**

- **Framing A (defect alone) → L0 + L1 sufficient.** The bug is observable at runtime; that's the entire claim.
- **Framing B (developer trap) → L3 required.** Need to show the bypass is re-introduced from a hardened baseline by a common developer action.
- **Framing C (full compound attack) → L4 required.** Need to show the attacker-victim handshake reaches the security-critical step (e.g., the LibreSSL client sends an encrypted Finished record to a synthesised no-RI server).

**Worked example — `BUGS/libressl_unsafe_renegotiation.md` reproducer set:**

| Script | Layer | What it proves |
|---|---|---|
| `reproduce_libressl_unsafe_renegotiation.py` | L2 | `s_client` accepts a no-RI ServerHello; `-no_legacy_server_connect` makes it reject. |
| `reproduce_libressl_unsafe_renegotiation_full.py` | L3 | 9-variant matrix including SSL_OP_ALL developer trap (V5) and SSL_OP_NO_RENEGOTIATION false-safety (V9). |
| `poc_path_alpha.py` | L4 | Full TLS 1.2 ECDHE-RSA-AES128-GCM server flight; the LibreSSL client sends CKE+CCS+encrypted Finished. |
| `poc_mid_session_renegotiation.py` | L4 + AEAD | Full TLS 1.2 server with AES-128-GCM AEAD record I/O; demonstrates mid-session renegotiation variant. |

For a Framing C finding, L4 evidence is what makes the bug report defensible. Without L4, "the client *could* be made to derive keys against a no-RI server" remains an unverified claim. The disclosure email can then attach L4 PoCs on request — see `disclosure/email_<root>.md` for the template.

**Anti-pattern to avoid:** skipping L0-L2 and writing L4 directly. L4 is fragile (custom TLS state machine, easy to get wrong) and slow (hours to debug). If the bug shows up at L2, document it at L2 first and decide whether L3/L4 is needed for the framing being claimed.

---

### Template

```python
#!/usr/bin/env python3
"""
Reproducer: <one-line root cause>

Companion bug report: BUGS/<root_name>.md
Verdict format:
  PASS — implementation matches RFC / no bug observed
  BUG  — RFC violation reproduced

Build/setup:
  - LibreSSL binary already in repo at vendor/libressl421/src/vendor/apps/openssl/openssl
  - OpenSSL binary already in repo at vendor/openssl340/bin/openssl
  - Test cert/key generated on first run at /tmp/<name>_test.{crt,key}
    (this is the only acceptable use of an absolute path — write-only ephemeral test material)
  - No env vars required.

Run:
  python3 BUGS/reproduce_<root_name>.py
"""

import os
import socket
import struct
import subprocess
import time

LIBRESSL = "vendor/libressl421/src/vendor/apps/openssl/openssl"
OPENSSL  = "vendor/openssl340/bin/openssl"
CERT     = "/tmp/ddyf_test.crt"
KEY      = "/tmp/ddyf_test.key"
PORT     = 14600   # pick a unique port per reproducer to avoid collisions when running multiple

ALERTS = {
    0:  "close_notify", 10: "unexpected_message", 22: "record_overflow",
    40: "handshake_failure", 47: "illegal_parameter", 50: "decode_error",
    70: "protocol_version", 80: "internal_error", 109: "missing_extension",
}


def ensure_cert():
    if not os.path.exists(CERT):
        subprocess.run(
            [LIBRESSL, "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", KEY, "-out", CERT,
             "-days", "365", "-nodes", "-subj", "/CN=test"],
            capture_output=True, check=True,
        )


def start_server(binary, port):
    """Start s_server. NEVER pass -quiet (causes null-ptr crash in sanitized OpenSSL)."""
    proc = subprocess.Popen(
        [binary, "s_server",
         "-cert", CERT, "-key", KEY, "-accept", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.4)
    return proc


def build_payload():
    """Craft the specific payload that triggers the bug. Keep this function focused."""
    # ... TLS record construction ...
    return b""


def read_alert(sock, timeout=2.0):
    """Read TLS records until an Alert (0x15) appears; return (alert_code, name) or (None, reason)."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                return None, "connection closed"
            buf += c
            while len(buf) >= 5:
                rt = buf[0]
                rlen = struct.unpack("!H", buf[3:5])[0]
                if len(buf) < 5 + rlen:
                    break
                rec, buf = buf[5:5+rlen], buf[5+rlen:]
                if rt == 0x15 and len(rec) >= 2:
                    return rec[1], ALERTS.get(rec[1], f"unknown({rec[1]})")
    except (socket.timeout, ConnectionResetError):
        return None, "no alert (timeout or reset)"


def test(binary, label, payload):
    proc = start_server(binary, PORT)
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
        s.sendall(payload)
        code, desc = read_alert(s)
        s.close()
    finally:
        proc.terminate()
        proc.wait(timeout=3)
    return code, desc


def main():
    ensure_cert()

    payload = build_payload()
    print(f"Trigger: <one-line description of the payload>")
    print()

    code, desc = test(LIBRESSL, "LibreSSL 4.2.1", payload)
    verdict = "PASS" if code == EXPECTED_LIBRESSL else "BUG"
    print(f"  LibreSSL: alert={code} ({desc}) → {verdict}")

    code, desc = test(OPENSSL, "OpenSSL 3.4.0", payload)
    verdict = "PASS" if code == EXPECTED_OPENSSL else "BUG"
    print(f"  OpenSSL : alert={code} ({desc}) → {verdict}")


EXPECTED_LIBRESSL = 47   # set to the alert code your bug report says LibreSSL should send
EXPECTED_OPENSSL  = 109  # set to the alert code your bug report says OpenSSL  should send

if __name__ == "__main__":
    main()
```

---

### Output format

A reproducer's stdout should look like this — and only this:

```
Trigger: TLS 1.3 ClientHello with key_share but no supported_groups

  LibreSSL: alert=47 (illegal_parameter) → BUG
  OpenSSL : alert=109 (missing_extension) → PASS
```

Do not print the bug description, RFC text, source code paths, or recommendations. Those live in the `.md` report. The reproducer's job is "show me the bug exists" — nothing more.

---

### Common helpers  *(copy as needed, do not import — keep each reproducer self-contained)*

```python
def u8(v): return struct.pack("!B", v)
def u16(v): return struct.pack("!H", v)
def u24(v): return struct.pack("!I", v)[1:]
def lp1(d): return u8(len(d)) + d
def lp2(d): return u16(len(d)) + d
def ext(t, d): return u16(t) + lp2(d)
def tls_record(ct, d): return u8(ct) + u16(0x0303) + u16(len(d)) + d
```

---

### What to do when the bug only reproduces in the tlspuffin harness

If your standalone reproducer shows PASS but the fuzzer traces show BUG, do not delete the reproducer or claim the bug is refuted. Adjust the reproducer to:
1. Run the test it can run (which will show PASS).
2. Print an explicit note that the bug is only triggerable in the multi-agent harness state.
3. Reference the trace bucket and the `metadata_*` logs as proof.

Example output in that case:
```
Trigger: HRR selecting an unoffered group

  LibreSSL standalone : alert=47 (illegal_parameter) → PASS in this scenario
  Note: bug only triggers in tlspuffin multi-agent context with the specific message
        ordering captured in 23 traces (objective/<bucket>/). See:
        objective/<bucket>/metadata_diff_*.log
```

This is honest reporting. Do not pretend the standalone test reproduces a bug it doesn't, and do not pretend the harness traces refute it.

---

### Self-check before committing a reproducer

- [ ] Runs from repo root with `python3 BUGS/reproduce_<name>.py`
- [ ] No absolute paths except `/tmp/...` for ephemeral test material
- [ ] No `-quiet` on `openssl s_server`
- [ ] Self-starts its own server/client
- [ ] ≤ ~150 lines of executable code
- [ ] Output is concise: trigger + verdict only
- [ ] Header docstring lists: how to build binaries, env vars, CLI command, expected output
- [ ] Name matches `BUGS/reproduce_<root_name>.py` where `<root_name>` matches the bug report

---

## SUMMARY_BUCKETS.md — Template

This file documents the mandatory `SUMMARY_BUCKETS.md` artifact produced at end of Phase 4. Write the actual file at `<campaign>/SUMMARY_BUCKETS.md` (inside the campaign folder, e.g., `triaging-openssl-libressl-05-18/SUMMARY_BUCKETS.md`).

**Also write `<campaign>/BUCKET_LIST.md`** — a dedicated minimal flat table produced *before* SUMMARY_BUCKETS.md, containing only: bucket name, status (CVE-candidate / RFC / Bug / BENIGN), trace count, and a one-line root cause. Template:

```markdown
## Bucket List — <PUT1> vs <PUT2>, MM-DD

| Bucket | Status | Traces | Root cause (one line) |
|---|---|---|---|
| `alert_illegal_param_vs_decode_err` | BENIGN | 3666 | Alert-code divergence; RFC 8446 §6 allows both codes |
| `libre_record_overflow_bypass` | RFC | 32 | Plaintext record skips SSL3_RT_MAX_PLAIN_LENGTH check |
| ... | ... | ... | ... |
```

`BUCKET_LIST.md` is the machine-readable index (no prose, no sub-sections). `SUMMARY_BUCKETS.md` is the narrative summary with links and RFC citations.

The summary is a single flat table grouping all non-empty buckets by severity category. It is the campaign's at-a-glance reference. The detailed bug-to-bucket mapping (both directions) lives in `CAMPAIGN_REPORT.md`; `SUMMARY_BUCKETS.md` is the flat view.

---

### Template

```markdown
## Summary of Buckets — <PUT1> vs <PUT2> Campaign

**Campaign date:** YYYY-MM-DD
**Total traces:** N
**Coverage:** Q (% classified)

---

### Legend

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

### 1. CVE candidates

| Bucket / source | Traces | Bug report | CVSS (framing) | Status | One-line summary |
|---|---|---|---|---|---|
| `<bucket_name>` | N | [BUGS/<name>.md](BUGS/<name>.md) | X.X (Severity) under <framing>; lower framings noted | not yet disclosed / draft sent YYYY-MM-DD / CVE-YYYY-NNNNN assigned / declined by vendor | One-line summary of the defect and its strongest framing |

*(empty if no buckets meet criteria (i)–(iii). Do not list "none"; state explicitly: "No buckets in this campaign meet CVE-candidate criteria; closest candidates investigated and reasons for non-promotion are documented in §6 of each respective bug report.")*

---

### 2. RFC violations

| Bucket | Traces | Bug report | RFC | One-line root cause |
|---|---|---|---|---|
| `<bucket_name>` | N | [BUGS/<name>.md](BUGS/<name>.md) | RFC XXXX §X.Y | ... |

---

### 3. Bugs (non-RFC)

| Bucket / source | Traces | Bug report | CVSS | One-line root cause |
|---|---|---|---|---|
| `<bucket_name>` or "discovered during reproducer testing" | N or N/A | [BUGS/<name>.md](BUGS/<name>.md) | X.X (Severity) | ... |

---

### 4. BENIGN differences

| Bucket | Traces | Category | Spec basis |
|---|---|---|---|
| `<bucket_name>` | N | Alert-code divergence / Timing / Leniency / Other | RFC XXXX §X.Y allows this |

---

### Totals

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

### Coverage check

All non-empty buckets in `evaluation-ddyf/sort_objectives_ossl_libre.py` appear in exactly one row above. All empty buckets have been deleted from the script (see `NAMING_CONVENTIONS.md` cleanup rule).

---

### 5. Speculative attack paths and research notes  *(OPTIONAL)*

> **Status:** Speculative — not CVE claims. No CVSS scores. Not aggregated into the totals above.

Findings that fail the Security Gate in isolation but have a sketched path to exploitation are recorded here (or in their respective bug reports under Section 10). Useful as "Future work" / "Discussion" material for the academic paper.

| # | Title | Components | Conjectured impact | What's missing to verify |
|---|---|---|---|---|
| S1 | <short title> | `bucket_a`, `bucket_b` | <one-line impact> | <specific evidence needed> |
| S2 | ... | ... | ... | ... |

Omit Section 5 entirely if no speculative paths are worth recording. Do not list "none" — just delete the heading.
```

---

### Rules for filling in this template

#### Rule A — Every non-empty bucket appears in exactly one section

A bucket cannot be both "CVE candidate" and "RFC violation" — CVE-candidate classification supersedes RFC if both apply. Pick the most severe classification and put the bucket in that section.

Specifically, the precedence order is:
1. **CVE candidate** (meets all three §1 inclusion criteria) — promote out of §2/§3 into §1.
2. **RFC violation** (documented MUST/MUST NOT, but no CVE-filing path) — keep in §2.
3. **Bug (non-RFC)** (implementation defect, no RFC clause violated, no CVE-filing path) — keep in §3.
4. **BENIGN** — §4.

When promoting a bucket, leave a one-line cross-reference in its original section: `*(<bucket_name> — N traces — promoted to §1 CVE candidates; see above.)*`

#### Rule B — BENIGN buckets are listed even if they have no bug report

BENIGN differences don't need bug reports, but they must still appear in section 4 with a one-line spec basis explaining why they are permitted. **A bucket's category is decided by which section it lands in here — not by its name or its `[TAG]`.** A `benign_*`-named bucket whose root cause is a real defect (e.g. a fuzzer/harness bug) is category Bug (§3) and needs a report; do not leave it in §4 because of the name. `NAMING_CONVENTIONS.md` § "BUCKET_LIST.md status — canonical source rule" is the single canonical statement of this precedence.

#### Rule C — Non-triaged count must be 0

If the triaging script has a non-triaged catch-all bucket and it contains traces, the campaign is not complete. Either:
- Investigate the residual traces and create a bucket for them
- Confirm they are flaky / non-deterministic and put them in a BENIGN `no_errors` or `flaky` bucket

#### Rule D — Bucket names match the triaging script exactly

Copy bucket names verbatim from `evaluation-ddyf/sort_objectives_ossl_libre.py`. Do not abbreviate or paraphrase.

#### Rule E — Bug-report links use repo-relative paths

`[BUGS/<name>.md](BUGS/<name>.md)` — not absolute paths, not external URLs.

#### Rule F — Trace counts come from the live filesystem

Run `find objective/<bucket>/ -name "*.trace" | wc -l` for each bucket; do not rely on stale counts from earlier runs.

---

### Worked example  *(from the OpenSSL-vs-LibreSSL campaign)*

```markdown
## Summary of Buckets — OpenSSL 3.4.0 vs LibreSSL 4.2.1

**Campaign date:** YYYY-MM-DD – YYYY-MM-DD
**Total traces:** 20,975
**Coverage:** 100% classified (0 non-triaged; per Rule C the 4 residual replay-flaky traces were placed in the BENIGN `no_errors` bucket, not left in a catch-all)

### 1. CVE candidates

*(none — all candidates investigated and refuted, OR no buckets meet criteria (i)–(iii); see Legend)*

### 2. RFC violations

| Bucket | Traces | Bug report | RFC | One-line root cause |
|---|---|---|---|---|
| `libre_record_overflow_bypass` | 32 | [BUGS/libressl_record_overflow_bypass.md](BUGS/libressl_record_overflow_bypass.md) | RFC 5246 §6.2.1 | Plaintext record path skips `SSL3_RT_MAX_PLAIN_LENGTH` check |
| `libre_v12_sh_v13_cipher_zero_keys` | 8 | [BUGS/libressl_wrong_cipher_acceptance.md](BUGS/libressl_wrong_cipher_acceptance.md) | RFC 8446 §4.1.3 | Client accepts TLS 1.3 cipher in TLS 1.2 ServerHello |
| `ossl_alert_silent_server_unexpected_msg` | 146 | [BUGS/libressl_server_unexpected_msg_silent.md](BUGS/libressl_server_unexpected_msg_silent.md) | RFC 5246 §7.2.2 | TLS 1.2 server lacks pre-flight state-machine guard |
| ... | ... | ... | ... | ... |

### 3. Bugs (non-RFC)

| Bucket / source | Traces | Bug report | CVSS | One-line root cause |
|---|---|---|---|---|
| `libre_finished_claim_silent_ossl` | 2128 | [BUGS/libressl_callback_ordering_defect.md](BUGS/libressl_callback_ordering_defect.md) | 2.7 (Low) | `msg_callback` fires before message-type validation in TLS 1.3 path |
| Discovered during reproducer testing | N/A | [BUGS/openssl_s_server_quiet_null_deref.md](BUGS/openssl_s_server_quiet_null_deref.md) | 5.3 (Medium) | `s_server -quiet` null function pointer on any ClientHello |

### 4. BENIGN differences

| Bucket | Traces | Category | Spec basis |
|---|---|---|---|
| `alert_illegal_param_vs_decode_err` | 3666 | Alert-code divergence | RFC 8446 §6 — alert code selection is implementation-defined |
| `no_errors` | 463 | Flaky / non-deterministic | No observable difference; trace replay artefact |
| ... | ... | ... | ... |

### Totals

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

---

## Investigation Prompt Template

Use this template when delegating a targeted source-code investigation to a separate LLM session. The session receives the finding and the technical question but **not** your reasoning or conclusion — the goal is an independent walk.

---

### When to use this template

Delegate when all three conditions hold:
1. A finding has a speculative path you cannot structurally refute from metadata alone.
2. The path requires reading 200+ lines of vendor source not already in your context.
3. The question is answerable with a clear verdict (see verdict format below).

Do not delegate vague questions ("is this interesting?"). The question must be specific enough that the investigator can answer YES / NO / NEEDS MORE EVIDENCE with a line-of-code citation.

---

### Template

Copy the block below into the investigation session. Fill in all `<placeholder>` fields.

```
### Investigation task: <short title>

#### Context

We have identified a <RFC violation / implementation defect / speculative attack path> in
<PUT name and version> at:
  - Affected source: <file:line in vendor/>
  - Affected function: <function name>

The defect is documented at: <campaign>/BUGS/<root_name>.md

#### Technical question

Does <specific mechanism X> prevent <specific attack Y>?

More precisely:
  - The attacker's position: <what the attacker controls / injects>
  - The conjectured effect: <what state the target PUT reaches>
  - The specific question: does <function/check at file:line> block the path at <step>?

#### What to investigate

1. Read <file1:line_range> and <file2:line_range> in `vendor/<lib>/src/vendor/`.
2. For each gate the attacker must bypass on the conjectured path:
   a. Name the specific line of code.
   b. Name the exact byte-level value the attacker must produce.
   c. Trace that value's source. If it derives from a secret the attacker doesn't have,
      name the gate as REFUTED.
3. Check whether the same check exists in the comparator PUT at <comparator_file:line>.

#### Verdict format

Report your conclusion as exactly one of:

  NOT A BUG — <mechanism X> provably prevents <attack Y>. Key evidence: <file:line>.
  CONFIRMED — <attack Y> is plausible. Gates walked; no refutation found. Next step: <what>.
  NEEDS MORE EVIDENCE — gate <N> is ambiguous; resolving it requires <specific evidence>.

Do not optimize for agreement with any prior analysis. If a gate refutes the path, name
the gate and the line. If a gate is genuinely uncertain, say so.
```

---

### On return: recording the verdict

| Verdict | Action |
|---|---|
| `NOT A BUG` | Add an appendix to the bug report (see `libressl_record_overflow_bypass.md` for example). Apply the stale-claim audit sweep per `ORCHESTRATOR.md`. |
| `CONFIRMED` | Promote the finding per the CVE-candidate track in `tls/SECURITY_GATE_TLS.md`. Update `SUMMARY_BUCKETS.md` §2. |
| `NEEDS MORE EVIDENCE` | Add to the bug report's speculative-paths section with explicit "what is missing to verify" language. |

---

### Worked example

The fragmentation-reassembly investigation from this campaign used the following structure:

- **Technical question:** Does LibreSSL's handshake-message fragment reassembly allocate up to 16 MB based on the raw 24-bit length field, or is it capped before allocation?
- **Source targets:** `vendor/libressl421/src/vendor/ssl/ssl_both.c:320` and `vendor/libressl421/src/vendor/ssl/tls13_handshake_msg.c:148`
- **Verdict received:** `NOT A BUG — TLS 1.2 path capped at s->max_cert_list (100 KB default) at ssl_both.c:328; TLS 1.3 path capped at 256 KB at tls13_handshake_msg.c:148.`
- **Action taken:** Added appendix to `libressl_record_overflow_bypass.md`; updated `CAMPAIGN_REPORT.md` §7.2 Deep Payload Smuggling rejection reason.
