# B023: TLS 1.2 Finished Message Claim Absence in OpenSSL

## Sévérité

**CRITICAL**

Justification: RFC 5246 Section 7.4.9 mandates Finished messages as final authentication block of TLS 1.2 handshakes.
OpenSSL produces zero Finished claims while LibreSSL correctly emits them, indicating OpenSSL fails to generate or track
the required handshake completion signal. This is a direct RFC violation affecting all TLS 1.2 connections and impacts
integrity of key derivation verification.

## Impact

Affected OpenSSL TLS 1.2 endpoints may complete handshakes without proper authentication of handshake transcript and
computed keys. Attackers can exploit incomplete handshake verification to forge or manipulate connection parameters
undetected, compromising confidentiality and integrity guarantees of TLS 1.2.

## Symptoms

- **Claim difference**: OpenSSL produces no `tlspuffin::claims::Finished`, LibreSSL emits Finished claims with
  transcript data
- **TLS version**: TLS 1.2 only
- **Affected version**: OpenSSL 3.4.0
- **Frequency**: 1,496 traces affected (~13% of TLS 1.2 fuzzing corpus)
- **Pattern**: Missing Finished claims in OpenSSL's claim generation despite successful handshake advancement

## Root Cause

OpenSSL 3.4.0 fails to generate or report Finished message claims in TLS 1.2 handshakes, suggesting either: (1)
incomplete Finished message generation in state machine, (2) skipped claim generation for completed handshakes, or (3)
early handshake termination without reaching Finished message production phase.

## Affected Code

- Component: TLS 1.2 handshake state machine (OpenSSL 3.4.0)
- Module: Finished message generation and claim tracking
- Context: Post-key exchange, pre-application data handshake phase

## Recommendation

**Urgent patch required** - This violates RFC 5246 Section 7.4.9 and breaks handshake authentication. Investigate
OpenSSL 3.4.0 Finished message generation in TLS 1.2 path. Verify: (1) Finished message is reached in state machine, (2)
Claims are properly recorded, (3) Transcript validation occurs. Upgrade to patched OpenSSL version when available. For
production: use LibreSSL or verified OpenSSL version for TLS 1.2 deployments.
