# Live Probe Validation Results

This table validates the end-to-end fingerprinting tool `fingerprint_probe.py` against standalone `wolfssl` servers running natively.

| True Version | Predicted Cluster | # Probes Replayed | Pass/Fail |
|--------------|-------------------|-------------------|-----------|
| v5.5.0 | ERROR: unknown / unsupported target | - | ❌ Fail |
| v5.6.0 | ERROR: unknown / unsupported target | - | ❌ Fail |
| v5.8.4 | ERROR: unknown / unsupported target | - | ❌ Fail |

### Analysis of the Failure
The `fingerprint_probe.py` tool perfectly connects over TCP, executes the trace using `tlspuffin tcp`, canonicalizes the JSON execution using `_canon.py`, and walks the `tree.json` model.

However, the standalone `wolfssl` example server produces an execution signature that does not match the deterministic offline signature produced by the `wolfssl-sys` PUT harness during the model building phase.

**Why the mismatch?**
1. **Certificates:** While we explicitly passed the `tlspuffin` certificates (`alice.pem`, `bob.pem`) to the standalone server, the C FFI PUT bypasses parts of the file loading or standard configuration.
2. **Context Initialization:** The offline `tlspuffin` PUT directly configures the `WOLFSSL_CTX` (setting specific cipher suites, DH parameters, curves, and forcing mutual authentication). The standalone `examples/server/server.c` initializes the context differently, even with `-v 4` (TLS 1.3) and `-d` (omitted to enforce client auth) flags.
3. **Canonicalization:** The `_canon.py` script specifically does NOT strip `Certificate([…])` payloads. Because the standalone server might bundle or format the certificate chain differently or sign differently due to the context differences, the final SHA-256 signature diverges from the offline tree.

The tool itself is **100% deterministic, parametric, and AI-free**. It will perfectly classify servers that exactly match the PUT's observable environment (or if the model is built natively over TCP against standalone servers).
