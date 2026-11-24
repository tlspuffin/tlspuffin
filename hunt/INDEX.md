# SSH CVE hunt — catalogue index

One line per entry: id — library, affected versions (base reproduced), category, oracle kind, Tier-1, Tier-2.
Re-done on `pr/ssh/ddyf-artifact` (bb8574845); the first versions are on the `cves/CVE-*` branches.

- [CVE-2023-1667](CVE-2023-1667.md) — libssh `0.9.1–0.9.6 || 0.10.0–0.10.4` (base `libssh0104`), dos (NULL deref, CWE-476), crash oracle (SEGV), **Tier-1: done** (witness = the honest rekey seed with `first_kex_packet_follows` set; crash on `libssh0104-asan-only-CVE-2023-1667`, nothing on `-fix-all` and 0.12.2), **Tier-2: done** (Q2 organic 5/5 in 8–14 s on 3 cores; no mapper symbol added). `by_puffin=false`.
- [CVE-2021-3634](CVE-2021-3634.md) — libssh `0.9.1–0.9.5` (base `libssh095`), heap over-read on a digest-size-changing rekey (CWE-787, dos), crash oracle (ASan heap-buffer-overflow, `find.asan=true`), **Tier-1: done** (witness = the honest curve25519 rekey seed re-offering `diffie-hellman-group16-sha512`; READ-of-64 in `ssh_packet_set_newkeys` on `libssh095-asan-only-CVE-2021-3634`, nothing on `-fix-all`, the 1667-only builds or 0.12.2), **Tier-2: done** (Q2 organic 5/5 in 12–418 s on 3 cores, no spurious objectives; one mapper atom `fn_algo_dh_group16_sha512`, regression on 0.12.2/1.6.0 clean). `by_puffin=false`.
