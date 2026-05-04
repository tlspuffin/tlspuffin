# B040: TLS 1.2 close_notify Alert Rejection in OpenSSL

## Sévérité

**HIGH**

Justification: RFC 5246 Section 7.2.1 mandates that close_notify alerts MUST be accepted or ignored at any time during
the connection. OpenSSL 3.4.0 rejects close_notify with an "unexpected message" error, violating RFC 5246 and breaking
graceful connection closure. This prevents proper TLS connection termination and disrupts interoperability with
compliant clients/servers.

## Impact

OpenSSL TLS 1.2 endpoints cannot properly close connections after successful handshakes. Applications unable to
send/receive close_notify alerts must either abruptly terminate connections or force TCP resets, preventing graceful
connection closure and causing compatibility issues with RFC-compliant TLS implementations. Network reliability and
connection cleanup are compromised.

## Symptoms

- **Error message**: "unexpected message" alert when receiving close_notify after successful handshake
- **TLS version**: TLS 1.2 only
- **Affected version**: OpenSSL 3.4.0
- **Trigger condition**: close_notify alert receipt post-handshake completion
- **Frequency**: Reproducible with 3 example traces
- **Pattern**: Immediate rejection instead of graceful acceptance per RFC 5246 Section 7.2.1

## Root Cause

OpenSSL 3.4.0 TLS 1.2 state machine improperly validates message types during connection closure phase. The alert
handling code fails to recognize close_notify as a valid alert type in the post-handshake state, treating it as an
unexpected/invalid message instead of the graceful closure signal mandated by RFC 5246.

## Affected Code

- Component: TLS 1.2 alert processing (OpenSSL 3.4.0)
- Module: Message state validation and alert type handling
- Context: Post-handshake application data phase during connection closure

## Recommendation

**Patch required** - Implement RFC 5246 Section 7.2.1 compliance for close_notify handling. Modify alert processing to
accept close_notify at any time post-handshake and treat it as graceful closure trigger rather than protocol error.
Update test coverage to verify close_notify acceptance in all TLS 1.2 states. Upgrade to patched OpenSSL version when
available.
