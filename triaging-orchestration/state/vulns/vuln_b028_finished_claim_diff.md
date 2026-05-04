# B028: TLS 1.2 Finished Claim Difference

## Sévérité

**MEDIUM**

Justification: While RFC 5246 Section 7.4.9 requires Finished messages, analysis shows LibreSSL's Finished claim
contains null keys (all zeros), indicating incomplete handshake state. This differs from B023 where claims are
completely absent. The null-key Finished is not a valid session, so practical security impact is lower than complete
absence.

## Impact

LibreSSL may report handshake completion via Finished claims while using invalid (all-zero) key material. This
misrepresents session state but does not result in functional TLS connection establishment. Both implementations
ultimately fail the connection after the null-Finished claim, preventing actual secure communication.

## Symptoms

- **Claim difference**: LibreSSL emits `tlspuffin::claims::Finished` with null/zero keys, OpenSSL produces no Finished
  claim
- **TLS version**: TLS 1.2 only
- **Frequency**: ~930 traces (similar source as B023 but different endpoint)
- **Key characteristic**: LibreSSL's Finished claims consistently contain `master_secret = [0, 0, 0, ...]`
- **Pattern**: Occurs when trace injects invalid protocol versions or malformed Finished messages

## Root Cause

LibreSSL processes malformed or out-of-sequence Finished messages, emits claim generation with placeholder/zero keys
before detecting the error. OpenSSL rejects these messages earlier without generating claims. Neither implementation
establishes valid keys, but LibreSSL's claim generation occurs before the final rejection.

## Affected Code

- Component: TLS 1.2 handshake state machine (LibreSSL 4.2.1)
- Module: Finished message claim generation with error handling
- Context: Invalid protocol state (wrong ProtocolVersion, out-of-sequence messages)

## Recommendation

**Monitor, not urgent** - This is benign since the null-key Finished represents no actual session establishment. Both
implementations ultimately fail. No action required for security; however, LibreSSL could optimize claim generation to
skip or mark invalid Finished claims with null keys as non-actionable.
