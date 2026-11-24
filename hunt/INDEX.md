# SSH CVE hunt — catalogue index

One line per entry: id — library, affected versions (base reproduced), category, oracle kind, Tier-1, Tier-2.
Re-done on `pr/ssh/ddyf-artifact` (bb8574845); the first versions are on the `cves/CVE-*` branches.

- [CVE-2023-1667](CVE-2023-1667.md) — libssh `0.9.1–0.9.6 || 0.10.0–0.10.4` (base `libssh0104`), dos (NULL deref, CWE-476), crash oracle (SEGV), **Tier-1: done** (witness = the honest rekey seed with `first_kex_packet_follows` set; crash on `libssh0104-asan-only-CVE-2023-1667`, nothing on `-fix-all` and 0.12.2), **Tier-2: done** (Q2 organic 5/5 in 8–14 s on 3 cores; no mapper symbol added). `by_puffin=false`.
