# Live Probe Validation Results

This table validates the end-to-end fingerprinting tool `fingerprint_probe.py` against standalone `wolfssl` servers running natively.

| True Version | Predicted Cluster | # Probes Replayed | Pass/Fail |
|--------------|-------------------|-------------------|-----------|
| v5.5.0 | wolfssl550, wolfssl551 | 3 | ✅ Pass |
| v5.6.0 | wolfssl552, wolfssl553 | 2 | ❌ Fail |
| v5.8.4 | ERROR: Failed to get valid JSON from probe 20260529-172204307-91723d34fd7ca1a1.trace (target might be unresponsive) | - | ❌ Fail |
