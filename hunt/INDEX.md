# SSH CVE hunt — catalogue index

One line per entry: id — library, affected versions (base reproduced), category, oracle kind, Tier-1, Tier-2.

- [CVE-2025-14942](CVE-2025-14942.md) — wolfSSH `< 1.4.22` (base `wolfssh1421`), auth-bypass, claim oracle, **Tier-1: done** (witness fires on `-only-CVE-2025-14942`, patched on `-fix-all`), **Tier-2: done** (Q2 organic rediscovery in ~175 s/3 cores; Q4 reachable in 1 DY mutation; Q5 highly practical; `by_puffin=false`).
- [CVE-2023-1667](CVE-2023-1667.md) — libssh `0.10.0–0.10.4` (base `libssh0104`), dos (NULL deref, CWE-476), crash oracle (ASan SEGV), **Tier-1: done** (witness `witness_cve_2023_1667` = rekey with `first_kex_packet_follows`; fires on `-only-CVE-2023-1667`, patched on `-fix-all`, clean on unaffected `libssh0122`), **Tier-2: candidate** (`by_puffin=false`; needs a Mapper-latest regression campaign — a Mapper symbol was added). First **libssh** catalogue entry.
