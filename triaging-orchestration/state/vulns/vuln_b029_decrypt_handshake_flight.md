# B029: OpenSSL 3.4.0 TLS 1.3 Handshake Decryption Failure

## Sévérité

**HIGH**

Justification: OpenSSL 3.4.0 fails with critical record layer errors during encrypted handshake flight decryption in TLS
1.3, while LibreSSL succeeds. Decryption/MAC failures in cryptographic operations are security-critical and indicate
state management bugs that could lead to authentication bypass or key compromise.

## Impact

Attackers could craft TLS 1.3 handshakes that trigger decryption failures in OpenSSL, causing connection abort or denial
of service. Depending on the underlying cause (key derivation, MAC verification, or record state corruption), this could
potentially be exploited for authentication bypass or cryptographic attacks against OpenSSL 3.4.0 TLS 1.3 endpoints.

## Symptoms

- **Error message**: `SSL_ERROR_SSL:tls_read_record:records not released:ssl/record/methods/tls_common.c:1129`
- **Secondary error**: `record layer failure:ssl/record/rec_layer_s3.c:693`
- **TLS version**: TLS 1.3 only
- **Triggering context**: `fn_decrypt_handshake_flight` with various message combinations
- **Affected version**: OpenSSL 3.4.0
- **Frequency**: Multiple traces with consistent error signature

## Root Cause

OpenSSL 3.4.0 exhibits record state management failure during TLS 1.3 encrypted handshake flight decryption. Records
fail to release properly before processing, indicating potential issues in: (1) cryptographic key state management, (2)
MAC verification logic, or (3) record layer cleanup during handshake message processing.

## Affected Code

- Component: TLS record layer (tls_read_record, rec_layer_s3.c)
- Function: `tls_read_record` in `ssl/record/methods/tls_common.c:1129`
- Context: TLS 1.3 encrypted handshake flight processing

## Recommendation

**Urgent investigation required** - File with OpenSSL security team immediately. Crypto failures require rapid
assessment for CVE implications. Workaround: upgrade to OpenSSL 3.4.1+ if available. Temporary mitigation: deploy
LibreSSL for TLS 1.3 handshakes or restrict to OpenSSL 3.3.x until patch released.
