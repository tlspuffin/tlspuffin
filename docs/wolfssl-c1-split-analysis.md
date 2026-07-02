# wolfSSL C1 {5.7.6, 5.8.0, 5.8.2}: can it be split? — exhaustive analysis

**Question.** Cluster C1 merges wolfSSL **5.7.6, 5.8.0, 5.8.2**. Can a live-TCP fingerprint
split them, ideally on a **default build + default server config**?

**Vocabulary** (see `wolfssl-cluster-merge-analysis.md`): TCP-DIST = distinguishable in theory
on the wire; PUFFIN-DIST(FFI) = `differential-execute` finds a stable, self-consistent
difference; PUFFIN-DIST(live) = the deployed live-TCP model (stock example server)
distinguishes them.

**Answer, up front.**
- C1 is **TCP-DIST** at the library/FFI level (real, stable differences exist).
- But on a **default build + default (v23, dual-stack) server**, the three versions are
  **wire-identical** on every observable handshake path — confirmed by an exhaustive,
  function-by-function source diff (§3). So there is **no default-config split**.
- The **one** genuine server-observable difference (5.7.6's missing-`signature_algorithms`
  handling) is reachable **only against a TLS-1.3-only server** (§2). Under that config the
  model splits {5.7.6} | {5.8.0, 5.8.2} (a 2-way split). **5.8.0 vs 5.8.2 has no
  server-observable difference on any config found in the diff.**

---

## 1. The FFI-level differences are real but error-path / config-specific

K=6 replay over the full 767-probe corpus (self-consistency filtered):
- 5.7.6 | 5.8.0: **79/767** stable splits — dominated by `Different(IllegalParameter,
  MissingExtension)` (58) + execution-status differences (14, same mechanism).
- 5.8.0 | 5.8.2: **8/767** stable splits — key-share group-negotiation edge cases
  (HelloRetryRequest-vs-Alert; a server key_share echoing an un-offered group).

These are **PUFFIN-DIST(FFI)=YES ⟹ TCP-DIST**. But they were mined under the *uniformised* FFI
config and are triggered by complex multi-step reactive traces; they do **not** replay to a
split over live TCP against the stock server (they yield EMPTY or uniform responses).

## 2. The missing-`signature_algorithms` distinguisher (5.7.6 vs 5.8.0)

wolfSSL 5.8.0 hardened the TLS 1.3 ClientHello required-extension check: on a ClientHello that
omits `signature_algorithms`, 5.7.6 accepts (ServerHello) while 5.8.0/5.8.2 abort with
`missing_extension(109)`. Verified with a purpose-built probe
(`seed_client_attacker13_no_sigalgs`): stable **6/6** split — 5.7.6 ServerHello, 5.8.0/5.8.2
`missing_extension`.

**Reachability is config-dependent — this is the crux of the FFI-vs-live gap:**
- **TLS-1.3-only server** (FFI harness `wolfTLSv1_3_server_method`, or the stock example server
  run with `-v 4`): the divergent check is reached → **splits live**.
- **Default (v23, dual-stack) server**: masked. A pure-1.3 no-sigalgs ClientHello yields a
  version-independent `handshake_failure(40)` *before* the check. Making the ClientHello
  dual-stack does not help — the server then negotiates **TLS 1.2** (verified: ServerHello with
  `ServerKeyExchange`, no `supported_versions`/`key_share`), where absent `signature_algorithms`
  is legal, so all versions accept. No ClientHello shape forces a downgrade-willing v23 server
  onto the 1.3 required-extension path. (Root cause is the server's **TLS method**, not the
  differential-fuzzing uniformisation — the divergence persists with `--fingerprinting`/no
  uniformisation.)

Probes recorded: `seed_client_attacker13_no_sigalgs` (splits on 1.3-only server),
`seed_client_attacker13_no_sigalgs_dualstack` and `seed_client_attacker13_group_mismatch`
(documented **negatives** — do not split; see their docstrings in `tls/seeds.rs`).

## 3. Exhaustive source diff: default-build server behaviour is identical across C1

Compared every server-observable function between 5.7.6 / 5.8.0 / 5.8.2 (filtering out DTLS,
client-side, disabled-feature, and comment lines):

| Server-observable path | 5.7.6→5.8.0 | 5.8.0→5.8.2 |
|---|---|---|
| Server-built messages: `SendTls13ServerHello`, `SendTls13EncryptedExtensions`, `SendTls13Certificate`, `SendTls13CertificateVerify`, `SendTls13Finished`, `SendTls13NewSessionTicket`, `SendTls13CertificateRequest` | identical in default (diffs are ECH/Falcon/DTLS, all off) | identical (diffs are DTLS epoch only) |
| `DoTls13ClientHello` (1.3 CH processing) | sigalgs hardening (§2) + PQC-only condition + `clSuites` refactor (behaviour-preserving) | **identical** |
| `DoClientHello` / `SendServerHello` (TLS 1.2 path) | identical | identical |
| `TLSX_KeyShare_Choose` (group selection / HRR trigger) | `FFHDE`→`FFDHE` rename + PQC-only `ke==NULL &&` condition | pure rename `TLSX_KeyShare_IsSupported`→`TLSX_IsGroupSupported` (same 22 ECC/FFDHE groups) |
| `DoTls13HandShakeMsgType`, `FindPsk`, `CheckPreSharedKeys` | — | DTLS epoch only |
| Record layer `DoDecrypt`/`SanityCheckCipherText` | — | post-handshake refactor (operates on decrypted records) |

**Every** inter-version difference falls in a dimension a remote client on a **default build**
cannot observe:
1. **Disabled-by-default features** — ECH (`HAVE_ECH=0`), Falcon/Kyber/ML-KEM PQC (5.8.0 was
   largely an ECH+PQC release; all compiled out).
2. **DTLS** — not TLS-over-TCP.
3. **Client-side** code — irrelevant when the PUT is the server.
4. **Internal crypto** — key derivation, signatures.
5. **Pure renames** and **config-gated paths** (OCSP `status_request` needs `ocspRespSz>0`
   i.e. an OCSP callback; DH-suite re-init needs configured DH params).

The only escapee is the §2 sigalgs check — and it is masked on a default v23 server.

## 4. Conclusion & options

- **Default build + default server: C1 is a genuine, confirmed merge** — the three versions are
  wire-identical on every observable path. This is now established from the source, not just
  the probe corpus. (This supersedes the earlier note that framed C1 as "the single best lead
  for adding clusters / FFI-provable count ≥ 18".)
- **5.8.0 vs 5.8.2: no server-observable difference on any config** found in the diff — for
  remote fingerprinting they are the same server.
- **The only achievable split is 2-way, {5.7.6} | {5.8.0, 5.8.2}, and only against a
  TLS-1.3-only server** (a common real-world deployment) via `seed_client_attacker13_no_sigalgs`.
  Promoting it into the live model requires running the wolfSSL reference servers TLS-1.3-only
  (`-v 4`); it does not hold against the stock dual-stack default.

**Tooling note.** The `--fingerprinting` CLI flag (threaded via `FuzzerConfig`) disables PUT
uniformisation so campaigns probe each PUT under its real default config; it did not change the
C1 outcome (the gap is the server TLS method, not uniformisation) but is the correct basis for
future stock-reproducible mining.
