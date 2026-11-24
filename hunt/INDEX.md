# SSH CVE hunt — catalogue index

One line per entry: id — library, affected versions (base reproduced), category, oracle kind, Tier-1, Tier-2.
Re-done on `pr/ssh/ddyf-artifact` (bb8574845); the first versions are on the `cves/CVE-*` branches.

- [CVE-2025-14942](CVE-2025-14942.md) — wolfSSH `<= 1.4.21` (base `wolfssh1421`), auth-bypass (CWE-287), claim oracle ("Authentication bypass", a one-sided client-side flag), **Tier-1: done** (violation on `wolfssh1421-asan-only-CVE-2025-14942`; `-fix-all` and 1.6.0 reject the message), **Tier-2: done** (Q2 organic 5/5 in 34–95 s on 3 cores; Q4 distance 1 from the honest server-attacker seed). `by_puffin=false`.
