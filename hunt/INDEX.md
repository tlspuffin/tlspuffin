# SSH CVE hunt — catalogue index

One line per entry: id — library, affected versions (base reproduced), category, oracle kind, Tier-1, Tier-2.

- [CVE-2025-14942](CVE-2025-14942.md) — wolfSSH `< 1.4.22` (base `wolfssh1421`), auth-bypass, claim oracle, **Tier-1: done** (witness fires on `-only-CVE-2025-14942`, patched on `-fix-all`), **Tier-2: done** (Q2 organic rediscovery in ~175 s/3 cores; Q4 reachable in 1 DY mutation; Q5 highly practical; `by_puffin=false`).
