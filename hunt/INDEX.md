# SSH CVE hunt — catalogue index

One line per entry: id — library, affected versions (base reproduced), category, oracle kind, Tier-1, Tier-2.
Re-done on `pr/ssh/ddyf-artifact` (bb8574845); the first versions are on the `cves/CVE-*` branches.

- [CVE-2025-14942](CVE-2025-14942.md) — wolfSSH `<= 1.4.21` (base `wolfssh1421`), auth-bypass (CWE-287), claim oracle ("Authentication bypass", a one-sided client-side flag), **Tier-1: done** (violation on `wolfssh1421-asan-only-CVE-2025-14942`; `-fix-all` and 1.6.0 reject the message), **Tier-2: done** (Q2 organic 5/5 in 34–95 s on 3 cores; Q4 distance 1 from the honest server-attacker seed). `by_puffin=false`.
- [CVE-2025-11625](CVE-2025-11625.md) — wolfSSH `<= 1.4.20` (base `wolfssh1420`), auth-bypass (CWE-287), claim oracle ("Host authentication bypass", a one-sided client-side flag), **Tier-1: done** (violation on `wolfssh1420-asan-only-CVE-2025-11625`; 1.4.20 `-fix-all`, 1.4.21 and 1.6.0 reject the NEWKEYS), **Tier-2: done** (Q2 organic 5/5 in 10–23 s on 3 cores; Q4 distance 1 from the honest server-attacker seed). `by_puffin=false`.

## Oracles

- [Entity-authentication oracle](ENTITY-AUTH-ORACLE.md) — approach 1, claim-based invariants checked on wolfSSH and libssh: C1 keyed ⟹ host key checked, C2 user-auth accepted ⟹ keyed (first raised for CVE-2025-11625 and CVE-2025-14942), S1 server authenticated ⟹ harness approved a credential. No false fire on 200 seed runs (10 builds); each invariant shown to fire by mutation tests or by its CVE witness. libssh 0.8.3 lacks the full oracle (support matrix). Approach 2, from the trace and the attacker's knowledge: [plan](ENTITY-AUTH-TRACE-ORACLE-PLAN.md), not implemented.
