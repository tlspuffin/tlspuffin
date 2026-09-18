# SSH-specific triaging prompts

Per-protocol counterpart to `../tls/`. The SSH security-gate and CVSS prompts:

- `SECURITY_GATE_SSH.md` — the SSH `[VULN]` security gate (Gate 0–5, ported from
  `../tls/SECURITY_GATE_TLS.md`; auth/channel-success claim, non-zero exchange hash `H`,
  signature-verification defense layers, and the SSH-specific **harness-vs-library** trap).
- `CVSS_SSH.md` — SSH-context CVSS v3.1 guidance, including the "finding is in sshpuffin
  itself, not either PUT → CVSS Not applicable" case.

An SSH campaign therefore runs the full `[VULN]` / `[RFC]` / `[BENIGN]` track and Phase 3 /
Audit 2, exactly like TLS. The normative reference is RFC 4251–4254 (+ 8308 / 8332 / 5647 /
8709). Most SSH differential findings are RFC-conformance divergences (CVSS 0.0); the gate is
what lets you *demonstrate* that rather than assert it, and its harness-vs-library check is
what distinguishes a real auth-state divergence from a claim-oracle artefact.
