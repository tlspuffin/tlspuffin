# B007: OpenSSL 3.4.0 TLS 1.2 Record Layer State Management Failure

## Sévérité
**HIGH**

Justification: OpenSSL 3.4.0 crashes with `records not released` error at the record layer during alert processing. Affects authenticated/encrypted communication channels (post-handshake). Not remote code execution but causes connection termination and potential denial of service via crafted alert sequences.

## Impact
Attackers can force OpenSSL TLS 1.2 endpoints to crash or abort connections by sending close_notify or other alert messages that trigger record layer state cleanup bugs. Affects any TLS 1.2 server using OpenSSL 3.4.0 that processes alerts after successful handshake.

## Symptoms
- **Error message**: `SSL_ERROR_SSL:tls_read_record:records not released:ssl/record/methods/tls_common.c:1129`
- **Secondary error**: `record layer failure:ssl/record/rec_layer_s3.c:693`
- **TLS version**: TLS 1.2 only
- **Triggering input**: Typically `fn_alert_close_notify` or other alert messages
- **Affected version**: OpenSSL 3.4.0
- **Frequency**: ~440 traces out of 20,975 (≈2.1%)

## Root Cause
Internal record state cleanup failure in OpenSSL 3.4.0's TLS record layer when processing alerts. Records are allocated but not properly released before processing subsequent messages, indicating a resource management bug in the record handling pipeline specific to TLS 1.2 alert processing.

## Affected Code
- Component: TLS record layer (tls_read_record, rec_layer_s3.c)
- Function: `tls_read_record` in `ssl/record/methods/tls_common.c`
- Context: Post-handshake alert message handling in TLS 1.2

## Recommendation
**Patch urgently** - File/verify with OpenSSL team. Workaround: upgrade to OpenSSL 3.4.1+ if available. Temporary mitigation: limit alert message handling on affected TLS 1.2 deployments or use alternative implementations (LibreSSL confirmed unaffected).
