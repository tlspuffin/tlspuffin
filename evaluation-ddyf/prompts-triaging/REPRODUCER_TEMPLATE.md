# Reproducer Template — Strict

Every bug report in `BUGS/` has a paired reproducer at `BUGS/reproduce_<root_name>.py`. The reproducer must satisfy all rules below.

---

## Hard rules

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

## Evidence-layer progression  *(for Track 2 / CVE-candidate findings)*

For findings being considered for CVE-candidate promotion, build evidence layer-by-layer. Each layer answers a more specific question than the previous one. Stop at the layer where the evidence is conclusive for the framing being claimed — don't over-engineer Layer 4 when Layer 2 settles the question.

| Layer | Question answered | Typical artefact | Effort |
|---|---|---|---|
| **L0** | "Does the affected code exist?" | Inline citations to `file:line` in the bug report; upstream cross-check per `SECURITY_GATE.md` Gate 0 | Minutes |
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

## Template

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

## Output format

A reproducer's stdout should look like this — and only this:

```
Trigger: TLS 1.3 ClientHello with key_share but no supported_groups

  LibreSSL: alert=47 (illegal_parameter) → BUG
  OpenSSL : alert=109 (missing_extension) → PASS
```

Do not print the bug description, RFC text, source code paths, or recommendations. Those live in the `.md` report. The reproducer's job is "show me the bug exists" — nothing more.

---

## Common helpers  *(copy as needed, do not import — keep each reproducer self-contained)*

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

## What to do when the bug only reproduces in the tlspuffin harness

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

## Self-check before committing a reproducer

- [ ] Runs from repo root with `python3 BUGS/reproduce_<name>.py`
- [ ] No absolute paths except `/tmp/...` for ephemeral test material
- [ ] No `-quiet` on `openssl s_server`
- [ ] Self-starts its own server/client
- [ ] ≤ ~150 lines of executable code
- [ ] Output is concise: trigger + verdict only
- [ ] Header docstring lists: how to build binaries, env vars, CLI command, expected output
- [ ] Name matches `BUGS/reproduce_<root_name>.py` where `<root_name>` matches the bug report
