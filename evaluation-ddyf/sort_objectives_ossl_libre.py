import sys
from .diff_analyzer import (
    BucketCondition,
    NoDiffC,
    AllC,
    AnyC,
    NotC,
    StatusC,
    CheckAgentC,
    TermContainsC,
    ClaimContainsC,
    TermContainsReC,
    StepC,
    InnerKnowledgeC,
    DifferentClaimC,
    KnowledgeContainsC,
    run_triaging,
    KnowledgeDiffC,
)

OSSL = 1
LIBRE = 2
FIRST_PUT = "openssl340"
SECOND_PUT = "libressl421"
PARALLELISM = 20

buckets: dict[str, BucketCondition] = {
    # -------------------------------------------------------------------------
    # HOUSEKEEPING: No observable difference → flaky execution
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Housekeeping bucket, correctly implemented.
    "no_errors/": NoDiffC(),

    # =========================================================================
    # CVE INVESTIGATION & CRITICAL STATE MACHINE FLAWS
    # =========================================================================

    # -------------------------------------------------------------------------
    # [RFC] libre_record_overflow_bypass
    #
    # Behavior: OpenSSL sends RecordOverflow for a certificate chain exceeding
    # the TLS max record size (2^14 bytes). LibreSSL bypasses the record-size
    # check and continues to certificate validation, emitting UnknownCA.
    # No session keys are involved; connection ultimately fails.
    # RFC 5246 §6.2.1 / RFC 8446 §5.1: length MUST NOT exceed 2^14 bytes;
    # receipt of oversized record MUST trigger record_overflow alert.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. 
    # Spec Audit: RFC 8446 §5.1 mandates a fatal RecordOverflow alert for records 
    # exceeding 2^14. LibreSSL's bypass is a clear protocol violation.
    # Logic Audit: Different(RecordOverflow, UnknownCA) precisely identifies 
    # the transport-layer bypass.
    # Bug report: BUGS/libressl_record_overflow_bypass.md
    "libre_record_overflow_bypass/": AllC(
        InnerKnowledgeC("Different(RecordOverflow, UnknownCA)", "AlertMessagePayload"),
        # Use a regex that is insensitive to whitespace/newlines
        TermContainsReC(OSSL, r"fn_append_certificate(.|\n)*fn_append_certificate"),
    ),

    # -------------------------------------------------------------------------
    # [RFC] libre_v12_sh_v13_cipher_zero_keys
    #
    # Behavior: LibreSSL client (tls_version=Both) accepts a TLS 1.2 ServerHello
    # selecting a TLS 1.3-only cipher (TLS_AES_128_GCM_SHA256=4865). Root cause:
    # ssl_clnt.c lines 999-1011 checks SSL_TLSV1_2 flag but not SSL_TLSV1_3.
    # Connection does NOT complete — TLS 1.3-only ciphers have no TLS 1.2 key
    # exchange; LibreSSL fails at CONNECT_CR_CERT. Zero early/handshake_secret
    # are TLS 1.3 fields never populated on the TLS 1.2 code path — not a key
    # leak. Fix: add `SSL_TLSV1_3` guard in ssl_clnt.c after line 1004.
    # RFC 8446 §4.1.3: client MUST abort with illegal_parameter for unoffered
    # cipher. LibreSSL violates this MUST. Not a CVE; upstream bug report
    # recommended.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED.
    # Spec Audit: RFC 8446 §4.1.3 mandates immediate abort for illegal cipher 
    # suite selection. LibreSSL's progression with null keys is a protocol 
    # and state-machine failure.
    # Logic Audit: Captures the contradiction of V1.2 version with V1.3 ciphers 
    # and resulting zeroed secrets.
    # Bug report: BUGS/libressl_wrong_cipher_acceptance.md
    "libre_v12_sh_v13_cipher_zero_keys/": AllC(
        # Confirms the claim contradiction observed in traces
        ClaimContainsC(LIBRE, r"tls_version: CLAIM_TLS_VERSION_V1_2"),
        ClaimContainsC(LIBRE, r"chosen_cipher: (4865|4866)"),
        # Confirms null key derivation (64 zeros)
        ClaimContainsC(LIBRE, r"handshake_secret: \[0(, 0){63}\]"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] libre_finished_claim_silent_ossl
    #
    # Behavior: LibreSSL emits a Finished claim; OpenSSL sends an alert and emits
    # none. Investigated in depth by P2 (Opus agent, 2026-04-30): root cause is
    # tls13_handshake_recv_action in tls13_handshake.c — the msg_callback fires
    # at line 531 before the message-type guard at line 540. Connection aborts
    # with unexpected_message; no session keys installed; no data exchanged;
    # no memory-safety issue. CVSS 2.7 (Low). Upstream bug report recommended.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED.
    # Spec Audit: Captures a state machine lookahead in callback emission, 
    # not a protocol-level secure bypass.
    # Logic Audit: DifferentClaimC identifies the premature claim.
    "libre_finished_claim_silent_ossl/": AllC(
        DifferentClaimC(in_first_type="()", in_second_type="Finished"),
        KnowledgeContainsC(OSSL, "AlertMessagePayload"),
    ),

    # =========================================================================
    # ossl_alert_libre_silent_injection — SPLIT into 9 sub-buckets
    #
    # Common pattern: OpenSSL detects a TLS protocol violation and sends a
    # fatal alert; LibreSSL produces no network output for the same input.
    # RFC 8446 §6: "A TLS implementation that encounters a fatal error condition
    # MUST send a fatal Alert before closing the connection."
    # LibreSSL's silence is an RFC §6 violation in all sub-buckets below.
    #
    # All sub-buckets use StatusC(OSSL, ..., first_to_fail=False) because the
    # differential is captured as a knowledge difference (AlertMessagePayload vs ()),
    # not a status difference; first_to_fail=False checks the per-PUT display-execute
    # error string directly.
    # =========================================================================

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_server_unexpected_msg
    #
    # OpenSSL server pre-flight state machine guard (ossl_statem_server_read_
    # transition, statem_srvr.c:336) rejects out-of-order messages with a fatal
    # UnexpectedMessage alert. LibreSSL's TLS 1.2 server path lacks an equivalent
    # guard; it fails internally (ssl_pkt.c decryption failure / ssl_srvr.c state
    # error) without sending any alert. The TLS 1.3 server path (tls13_handshake.c
    # :543) correctly sends the alert and is NOT affected.
    # Investigated (2026-05-03): 0/146 traces show LibreSSL emitting a Finished
    # claim — no authentication bypass, no key derivation from attacker material.
    # CVSS 0.0. See BUGS/libressl_server_unexpected_msg_silent.md.
    # RFC 5246 §7.4.1 + §7.2.2 / RFC 8446 §6.2: fatal conditions MUST alert.
    # -------------------------------------------------------------------------
    # AUDITED (2026-05-03): Confirmed RFC only. 0/146 traces show Finished claim
    # or auth state advancement. TLS 1.3 path unaffected (has guard at :543).
    # AUDITED BY GEMINI: APPROVED. RFC 5246 §7.2.2 mandates fatal alert for unexpected messages. LibreSSL silently drops the connection, which is a violation.
    # Bug report: BUGS/libressl_server_unexpected_msg_silent.md
    "ossl_alert_silent_server_unexpected_msg/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        StatusC(OSSL, "ossl_statem_server_read_transition", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_no_key_share
    #
    # OpenSSL server aborts because no key share group in the ClientHello
    # matches the server's supported groups (final_key_share: no suitable key
    # share). LibreSSL produces no alert — RFC 8446 §4.2.8 + §6 violation.
    # Trigger: fn_key_share_extension_make with empty or incompatible groups.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §6 violation (Silent Abort).
    # Bug report: BUGS/libressl_silent_abort_negotiation_failure.md
    "ossl_alert_silent_no_key_share/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        StatusC(OSSL, "final_key_share", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_hrr_key_share_length_mismatch  (40 traces)
    #
    # Attacker sends a ServerHello whose Random = HRR magic value (fn_hello_retry_
    # request_random = SHA-256("HelloRetryRequest")) but whose key_share extension
    # contains a full KeyShareEntry (group_id + 65-byte uncompressed EC point)
    # instead of the HRR-only KeyShareHelloRetryRequest (group_id only, 2 bytes).
    #
    # OpenSSL detects the trailing bytes in HRR context and sends DecodeError
    # (extensions_clnt.c:1856, SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST branch).
    # LibreSSL's tlsext_keyshare_client_process (ssl_tlsext.c) does not check
    # remaining bytes in the HRR context; it silently falls through and later
    # fails internally without sending an alert.
    #
    # CVSS 0.0 (None): connection always aborts; no data exchanged; no key
    # derivation from attacker-controlled material (Finished claim in traces is
    # from agent.1 server's legitimate handshake, not from the client processing
    # the malformed message). See BUGS/libressl_bad_key_share_stoc.md.
    # RFC 8446 §4.2.8: HRR key_share MUST contain only selected_group (2 bytes).
    # RFC 8446 §6.2: "decode_error" MUST be sent for malformed extensions.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED.
    # Spec Audit: RFC 8446 §4.2.8 and §6.2 violation (Silent Abort).
    # Logic Audit: Validates OpenSSL triggers "length mismatch" and "tls_parse_stoc_key_share"
    # Bug report: BUGS/ossl_alert_silent_hrr_key_share_length_mismatch.md
    "ossl_alert_silent_hrr_key_share_length_mismatch/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        StatusC(OSSL, "length mismatch", first_to_fail=False),
        StatusC(OSSL, "tls_parse_stoc_key_share", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_hrr_key_share_bad_group  (23 traces)
    #
    # Attacker sends a well-formed HRR whose key_share selects a group (e.g.
    # x25519 = 0x001d) that the client never offered in supported_groups or
    # key_share. OpenSSL sends illegal_parameter (extensions_clnt.c:1879).
    # LibreSSL validates the group at tls13_client.c:443-446 but the failure
    # path is `return 0; /* XXX alert */` — an explicit TODO comment, no alert
    # sent. The missing alert path is confirmed in LibreSSL source.
    #
    # CVSS 0.0 (None): same as above — connection aborts, no data exchanged.
    # RFC 8446 §4.2.8: server MUST NOT select a group not in client's
    # supported_groups; client MUST abort with illegal_parameter.
    # RFC 8446 §6.2: fatal conditions MUST produce an alert.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED.
    # Spec Audit: RFC 8446 §4.2.8 and §6.2 violation (Silent Abort).
    # Logic Audit: Validates OpenSSL triggers "bad key share" and "tls_parse_stoc_key_share"
    # Bug report: BUGS/ossl_alert_silent_hrr_key_share_bad_group.md
    "ossl_alert_silent_hrr_key_share_bad_group/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        StatusC(OSSL, "bad key share", first_to_fail=False),
        StatusC(OSSL, "tls_parse_stoc_key_share", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_client_unexpected_msg
    #
    # OpenSSL client's state machine rejects an out-of-order handshake message
    # (ossl_statem_client_read_transition: unexpected message).
    # LibreSSL client produces no alert — RFC 8446 §4.1 + §6 violation.
    # Trigger: attacker injects a message type unexpected at the client's
    # current state (e.g., EncryptedExtensions before ServerHello).
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §6 violation (Silent Abort).
    # Bug report: BUGS/libressl_invalid_curve_attack.md
    "ossl_alert_silent_client_unexpected_msg/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        StatusC(OSSL, "ossl_statem_client_read_transition", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_ecdh_error
    #
    # OpenSSL fails during TLS 1.2 ECDH key exchange processing: either
    # tls_process_cke_ecdhe (invalid client key exchange) or low-level EC field
    # arithmetic failures (ossl_ec_GF*: point at infinity, invalid point, etc.).
    # LibreSSL produces no alert — RFC 5246 §7.4.7 + RFC 8446 §6 violation.
    # Trigger: attacker injects a ClientKeyExchange with an invalid EC point.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §6 violation (Silent Abort).
    # Bug report: BUGS/libressl_invalid_curve_attack.md
    "ossl_alert_silent_ecdh_error/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        AnyC(
            StatusC(OSSL, "tls_process_cke_ecdhe", first_to_fail=False),
            StatusC(OSSL, "ossl_ec_GF", first_to_fail=False),
            StatusC(OSSL, "ossl_ec_key_public_check", first_to_fail=False),
        ),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_version_mismatch
    #
    # OpenSSL rejects due to a TLS version negotiation failure:
    # ssl_choose_client_version (wrong SSL version), tls_process_server_hello
    # (bad ServerHello), or tls_parse_stoc_supported_versions (bad version in
    # supported_versions extension). LibreSSL produces no alert.
    # RFC 8446 §4.2.1 / RFC 5246 §7.4.1 + §6 violation.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §6 violation (Silent Abort).
    # Bug report: BUGS/libressl_invalid_curve_attack.md
    "ossl_alert_silent_version_mismatch/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        AnyC(
            StatusC(OSSL, "ssl_choose_client_version", first_to_fail=False),
            StatusC(OSSL, "tls_process_server_hello", first_to_fail=False),
            StatusC(OSSL, "tls_parse_stoc_supported_versions", first_to_fail=False),
        ),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_hrr_no_change
    #
    # OpenSSL rejects a second ClientHello after a HelloRetryRequest where the
    # key share was not updated (tls_process_as_hello_retry_request: no change
    # following hrr). LibreSSL produces no alert.
    # RFC 8446 §4.1.4: the client MUST update its key share in the retry.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §6 violation (Silent Abort).
    # Bug report: BUGS/ossl_alert_silent_hrr_no_change.md
    "ossl_alert_silent_hrr_no_change/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        StatusC(OSSL, "no change following hrr", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_unsupported_protocol
    #
    # OpenSSL rejects a ClientHello with an unsupported protocol version early
    # in processing (tls_early_post_process_client_hello: unsupported protocol).
    # LibreSSL produces no alert — RFC 8446 §4.2.1 + §6 violation.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §6 violation (Silent Abort).
    # Bug report: BUGS/libressl_silent_abort_negotiation_failure.md
    "ossl_alert_silent_unsupported_protocol/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        StatusC(OSSL, "unsupported protocol", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_alert_silent_extension_error
    #
    # OpenSSL rejects due to a malformed or unsolicited extension in a handshake
    # message (tls_collect_extensions: unsolicited extension / bad extension).
    # LibreSSL produces no alert — RFC 8446 §4.2 + §6 violation.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §6 violation (Silent Abort).
    # Bug report: BUGS/libressl_silent_abort_negotiation_failure.md
    "ossl_alert_silent_extension_error/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="()",
        ),
        NotC(DifferentClaimC(in_first_type="()", in_second_type="Finished")),
        AnyC(
            StatusC(OSSL, "unsolicited extension", first_to_fail=False),
            StatusC(OSSL, "bad extension", first_to_fail=False),
        ),
    ),

    # =========================================================================
    # BATCH 1 — original implementation pass
    # =========================================================================

    # -------------------------------------------------------------------------
    # [RFC] ossl_missing_ext_libre_illegal_param
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. RFC 8446 §9.2 violation.
    # Bug report: BUGS/libressl_missing_ext_wrong_alert.md
    "ossl_missing_ext_libre_illegal_param/": AllC(
        InnerKnowledgeC(
            "Different(MissingExtension, IllegalParameter)",
            "AlertMessagePayload",
        ),
        TermContainsC(OSSL, "fn_supported_versions13_extension"),
    ),

    # -------------------------------------------------------------------------
    # [RFC] libre_accepts_wrong_cipher_suite
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. RFC 8446 §4.1.3 violation.
    # Bug report: BUGS/libressl_wrong_cipher_acceptance.md
    "libre_accepts_wrong_cipher_suite/": AllC(
        StatusC(OSSL, "wrong cipher returned", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
        # Exclude the zero-key VULN case which is more specific
        NotC(ClaimContainsC(LIBRE, r"chosen_cipher: (4865|4866)")),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_record_failure_libre_accepts
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. RFC 8446 §5.2 violation.
    # Bug report: BUGS/libressl_record_accepts_fn_no_key_share.md
    "ossl_record_failure_libre_accepts/": AllC(
        StatusC(OSSL, "record layer failure", first_to_fail=True),
        TermContainsC(OSSL, "fn_no_key_share"),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_unsafe_legacy_renegotiation
    #
    # LibreSSL 4.2.1 client silently accepts ServerHellos that omit the
    # `renegotiation_info` extension on both initial connect AND mid-session
    # renegotiation (RFC 5746 §4.1 violation).
    #
    # Defaults-level root cause (NOT a missing check):
    #   - ssl_clnt.c:1062-1067   correct enforcement is here
    #   - ssl_lib.c:2187         SSL_CTX_new unconditionally sets
    #                            SSL_OP_LEGACY_SERVER_CONNECT
    #   - include/openssl/ssl.h:414-415   SSL_OP_ALL macro == legacy bit only
    #
    # CVSS multi-framing (see BUGS/libressl_unsafe_renegotiation.md §6.2):
    #   Framing A (defect alone):      0.0 (None)
    #   Framing B (SSL_OP_ALL trap):   0.0 (None) — actively misleading API
    #   Framing C (Path α compound):   ~4.8 (Medium) with non-RI server
    #
    # Variants empirically verified:
    #   A initial connect default                — V1 of reproduce_*_full.py
    #   B SSL_OP_ALL developer trap              — V5 of reproduce_*_full.py
    #   C SSL_OP_NO_RENEGOTIATION false-safety   — V9 of reproduce_*_full.py
    #   D mid-session renegotiation              — poc_mid_session_renegotiation.py
    #   F server-side (control)                  — not affected
    #   Path α full handshake completion         — poc_path_alpha.py
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. RFC 5746 violation.
    # Bug report: BUGS/libressl_unsafe_renegotiation.md
    "ossl_unsafe_legacy_renegotiation/": AllC(
        StatusC(OSSL, "unsafe legacy renegotiation disabled", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),

    # =========================================================================
    # BATCH 2 — Alert Divergences
    # =========================================================================

    # -------------------------------------------------------------------------
    # [BENIGN] alert_illegal_param_vs_decode_err
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "alert_illegal_param_vs_decode_err/": AllC(
        InnerKnowledgeC(
            "Different(IllegalParameter, DecodeError)",
            "AlertMessagePayload",
        ),
        AnyC(
            TermContainsC(OSSL, "fn_fill_binder"),
            TermContainsC(OSSL, "fn_client_hello"),
        ),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_hf_vs_ip_no_shared_cipher
    #
    # OpenSSL server fails cipher selection (tls_post_process_client_hello or
    # tls_early_post_process_client_hello: no shared cipher) → HandshakeFailure.
    # LibreSSL finds a different fault in the same ClientHello → IllegalParameter.
    # Both reject; root cause: cipher-list mismatch triggers different code paths.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §4.1.1 mandates handshake_failure or insufficient_security for negotiation failure. LibreSSL's illegal_parameter is technically non-compliant but functionally benign.
    "alert_hf_vs_ip_no_shared_cipher/": AllC(
        InnerKnowledgeC("Different(HandshakeFailure, IllegalParameter)", "AlertMessagePayload"),
        AnyC(
            StatusC(OSSL, "no shared cipher", first_to_fail=False),
            StatusC(OSSL, "tls_post_process_client_hello", first_to_fail=False),
            StatusC(OSSL, "tls_early_post_process_client_hello", first_to_fail=False),
        ),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_hf_vs_ip_sigalg
    #
    # OpenSSL server fails signature-algorithm selection → HandshakeFailure.
    # LibreSSL reaches a different error first → IllegalParameter.
    # Root cause: incompatible signature algorithm list in ClientHello.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §4.1.1 mandates handshake_failure or insufficient_security for negotiation failure. LibreSSL's illegal_parameter is technically non-compliant but functionally benign.
    "alert_hf_vs_ip_sigalg/": AllC(
        InnerKnowledgeC("Different(HandshakeFailure, IllegalParameter)", "AlertMessagePayload"),
        AnyC(
            StatusC(OSSL, "no shared signature algorithms", first_to_fail=False),
            StatusC(OSSL, "no suitable signature algorithm", first_to_fail=False),
            StatusC(OSSL, "tls1_set_server_sigalgs", first_to_fail=False),
            StatusC(OSSL, "tls_choose_sigalg", first_to_fail=False),
        ),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_hf_vs_ip_no_key_share
    #
    # OpenSSL server fails key-share selection (final_key_share: no suitable
    # key share) → HandshakeFailure. LibreSSL → IllegalParameter.
    # Root cause: key_share group mismatch triggers different rejection paths.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. RFC 8446 §4.1.1 mandates handshake_failure or insufficient_security for negotiation failure.
    "alert_hf_vs_ip_no_key_share/": AllC(
        InnerKnowledgeC("Different(HandshakeFailure, IllegalParameter)", "AlertMessagePayload"),
        StatusC(OSSL, "final_key_share", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_handshake_failure_vs_illegal_param  (residual)
    #
    # Remaining HandshakeFailure↔IllegalParameter pairs not captured above
    # (renegotiation mismatch, missing PSK kex modes, etc.).
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference for malformed/un-negotiable ClientHello.
    "alert_handshake_failure_vs_illegal_param/": AllC(
        InnerKnowledgeC(
            "Different(HandshakeFailure, IllegalParameter)",
            "AlertMessagePayload",
        ),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_illegal_param_vs_protocol_version
    #
    # Both PUTs reject the same input but with different RFC-permitted alert codes:
    # OpenSSL → IllegalParameter; LibreSSL → ProtocolVersion.
    # This specific alert-pair divergence occurs across multiple attacker scenarios
    # (fn_server_hello, fn_client_hello, extension contexts) — the pair identifies
    # the BENIGN class regardless of which parsing code path triggers it.
    # Removing the prior TermContainsC(OSSL, "fn_server_hello") second condition
    # because it was artificially incomplete (C3 fail: 754 traces with the same root
    # cause leaked into alert_misc_pairs). The specific alert pair IS the complete
    # root-cause encoding for a BENIGN divergence.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. Revised to complete coverage (v3 self-audit).
    # Self-audit v3: C1 ✓ (specific pair); C2 ✓ (pair encodes BENIGN class);
    # C3 ✓ (now complete — absorbs all IP vs PV traces, 1435 total);
    # C4 ✓ (BENIGN-class level: multiple error functions, same divergence pattern)
    "alert_illegal_param_vs_protocol_version/": AllC(
        InnerKnowledgeC(
            "Different(IllegalParameter, ProtocolVersion)",
            "AlertMessagePayload",
        ),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_handshake_failure_ossl_decode_err_libre
    #
    # OpenSSL sends HandshakeFailure; LibreSSL sends DecodeError.
    # Both reject the same malformed input, differing only in diagnostic code.
    # Root cause: OpenSSL detects cipher/parameter failure (HandshakeFailure)
    # while LibreSSL reaches a parse error first (DecodeError).
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference (parsing vs semantic validation).
    "alert_handshake_failure_ossl_decode_err_libre/": AllC(
        InnerKnowledgeC("Different(HandshakeFailure, DecodeError)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_decode_err_ossl_handshake_failure_libre
    #
    # OpenSSL sends DecodeError; LibreSSL sends HandshakeFailure.
    # Symmetric reverse: LibreSSL reaches cipher/parameter failure while
    # OpenSSL hits a parse/decode error at the same malformed input.
    # Root cause: ssl_srvr.c:1124 (LibreSSL) vs tls_collect_extensions (OpenSSL).
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference (parsing vs semantic validation).
    "alert_decode_err_ossl_handshake_failure_libre/": AllC(
        InnerKnowledgeC("Different(DecodeError, HandshakeFailure)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [RFC] alert_missing_ext_vs_illegal_param_reverse
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. RFC 8446 §9.2 violation.
    # Bug report: BUGS/openssl_missing_ext_wrong_alert.md
    "alert_missing_ext_vs_illegal_param_reverse/": AllC(
        InnerKnowledgeC("Different(IllegalParameter, MissingExtension)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_illegal_param_vs_internal_err
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "alert_illegal_param_vs_internal_err/": AllC(
        InnerKnowledgeC("Different(IllegalParameter, InternalError)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_unsupported_ext_vs_decode_err
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "alert_unsupported_ext_vs_decode_err/": AllC(
        InnerKnowledgeC("Different(UnsupportedExtension, DecodeError)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_unexpected_msg_vs_handshake_failure
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "alert_unexpected_msg_vs_handshake_failure/": AllC(
        InnerKnowledgeC("Different(UnexpectedMessage, HandshakeFailure)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_unsupported_ext_vs_unrecognised_name
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "alert_unsupported_ext_vs_unrecognised_name/": AllC(
        InnerKnowledgeC("Different(UnsupportedExtension, UnrecognisedName)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_protocol_version_vs_illegal_param
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "alert_protocol_version_vs_illegal_param/": AllC(
        InnerKnowledgeC("Different(ProtocolVersion, IllegalParameter)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [RFC] alert_handshake_failure_vs_missing_ext_reverse
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. RFC 8446 §9.2 violation.
    # Bug report: BUGS/openssl_missing_ext_wrong_alert.md
    "alert_handshake_failure_vs_missing_ext_reverse/": AllC(
        InnerKnowledgeC("Different(HandshakeFailure, MissingExtension)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [RFC] alert_missing_ext_vs_protocol_version
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. RFC 8446 §9.2 violation.
    # Bug report: BUGS/openssl_missing_ext_wrong_alert.md
    "alert_missing_ext_vs_protocol_version/": AllC(
        InnerKnowledgeC("Different(MissingExtension, ProtocolVersion)", "AlertMessagePayload"),
    ),

    # =========================================================================
    # BATCH 3 — Status & Timing Differences
    # =========================================================================

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_lenient_empty_cipher_list
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "ossl_lenient_empty_cipher_list/": AllC(
        StatusC(LIBRE, in_error="tls13_lib.c", first_to_fail=True),
        TermContainsC(OSSL, "fn_new_cipher_suites", last_input_executed=True),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_truly_succeeds_libre_fails_tls13
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved. RFC 8446 §4.1.2 violation by OpenSSL.
    # Bug report: BUGS/openssl_accepts_wrong_legacy_version.md
    "ossl_truly_succeeds_libre_fails_tls13/": AllC(
        StatusC(LIBRE, "tls13_lib.c", first_to_fail=True),
        StepC(lambda f, s, total: f == total),
        NotC(TermContainsReC(OSSL, r"fn_key_share_extension_make\(.*fn_key_share_extension_make\(", last_input_executed=True)),
        NotC(TermContainsC(OSSL, "fn_new_cipher_suites", last_input_executed=True)),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] libre_tls13_rejects_unexpected_msg_ossl_proceeds
    #
    # LibreSSL TLS 1.3 sends unexpected_message before OpenSSL does.
    # Attacker injects an out-of-order message that LibreSSL's stricter state
    # machine rejects earlier; OpenSSL is more lenient and proceeds further
    # before failing. ~75% of the original ossl_fails_later bucket.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Both eventual rejections are benign; LibreSSL enforces stricter state machine ordering.
    "libre_tls13_rejects_unexpected_msg_ossl_proceeds/": AllC(
        StatusC(LIBRE, "tls13_lib.c", first_to_fail=True),
        StepC(lambda f, s, total: f > s and f < total),
        StatusC(LIBRE, "unexpected message", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] libre_tls13_rejects_protocol_version_ossl_proceeds
    #
    # LibreSSL TLS 1.3 sends protocol_version before OpenSSL.
    # LibreSSL's version negotiation guard triggers earlier than OpenSSL's.
    # ~14% of the original ossl_fails_later bucket.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign timing difference in version negotiation checks.
    "libre_tls13_rejects_protocol_version_ossl_proceeds/": AllC(
        StatusC(LIBRE, "tls13_lib.c", first_to_fail=True),
        StepC(lambda f, s, total: f > s and f < total),
        StatusC(LIBRE, "protocol version", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] libre_tls13_rejects_illegal_param_ossl_proceeds
    #
    # LibreSSL TLS 1.3 sends illegal_parameter before OpenSSL.
    # ~10% of the original ossl_fails_later bucket.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign timing difference in parameter validation.
    "libre_tls13_rejects_illegal_param_ossl_proceeds/": AllC(
        StatusC(LIBRE, "tls13_lib.c", first_to_fail=True),
        StepC(lambda f, s, total: f > s and f < total),
        StatusC(LIBRE, "illegal parameter", first_to_fail=False),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_fails_later_libre_fails_earlier_tls13  (residual)
    #
    # Remaining cases not matched by the three sub-buckets above.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Catch-all for benign state machine timing differences.
    "ossl_fails_later_libre_fails_earlier_tls13/": AllC(
        StatusC(LIBRE, "tls13_lib.c", first_to_fail=True),
        StepC(lambda f, s, total: f > s and f < total),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_unexpected_msg_clnt_libre_proceeds
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "ossl_unexpected_msg_clnt_libre_proceeds/": AllC(
        StatusC(OSSL, "ossl_statem_client_read_transition", first_to_fail=True),
        StepC(lambda f, s, total: f < s),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_unexpected_msg_rec_layer_libre_proceeds
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "ossl_unexpected_msg_rec_layer_libre_proceeds/": AllC(
        StatusC(OSSL, "ssl3_read_bytes", first_to_fail=True),
        AnyC(
            StepC(lambda f, s, total: f < s),
            StepC(lambda f, s, total: f > s),
        ),
    ),

    # =========================================================================
    # alert_misc_pairs — SPLIT into per-pair sub-buckets
    #
    # The original catch-all captured all remaining alert pair divergences not
    # covered by the more specific earlier buckets. Sampling confirmed 10+
    # distinct pairs. Each is split here by the specific alert pair.
    # All are BENIGN: both PUTs reject; they differ only in diagnostic code.
    # =========================================================================

    # -------------------------------------------------------------------------
    # [BENIGN] alert_illegal_param_vs_handshake_failure
    # OpenSSL → IllegalParameter; LibreSSL → HandshakeFailure.
    # Reverse of the existing alert_handshake_failure_vs_illegal_param bucket.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Reverse of alert_handshake_failure_vs_illegal_param. Benign diagnostic difference.
    "alert_illegal_param_vs_handshake_failure/": AllC(
        InnerKnowledgeC("Different(IllegalParameter, HandshakeFailure)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_unexpected_msg_vs_illegal_param
    # OpenSSL → UnexpectedMessage; LibreSSL → IllegalParameter.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference.
    "alert_unexpected_msg_vs_illegal_param/": AllC(
        InnerKnowledgeC("Different(UnexpectedMessage, IllegalParameter)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_unsupported_ext_vs_illegal_param
    # OpenSSL → UnsupportedExtension; LibreSSL → IllegalParameter.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference.
    "alert_unsupported_ext_vs_illegal_param/": AllC(
        InnerKnowledgeC("Different(UnsupportedExtension, IllegalParameter)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_unsupported_ext_vs_protocol_version
    # OpenSSL → UnsupportedExtension; LibreSSL → ProtocolVersion.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference.
    "alert_unsupported_ext_vs_protocol_version/": AllC(
        InnerKnowledgeC("Different(UnsupportedExtension, ProtocolVersion)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_handshake_failure_vs_unsupported_ext
    # OpenSSL → HandshakeFailure; LibreSSL → UnsupportedExtension.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference.
    "alert_handshake_failure_vs_unsupported_ext/": AllC(
        InnerKnowledgeC("Different(HandshakeFailure, UnsupportedExtension)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_decode_err_vs_illegal_param
    # OpenSSL → DecodeError; LibreSSL → IllegalParameter.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference.
    "alert_decode_err_vs_illegal_param/": AllC(
        InnerKnowledgeC("Different(DecodeError, IllegalParameter)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_decode_err_vs_protocol_version
    # OpenSSL → DecodeError; LibreSSL → ProtocolVersion.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference.
    "alert_decode_err_vs_protocol_version/": AllC(
        InnerKnowledgeC("Different(DecodeError, ProtocolVersion)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_illegal_param_vs_unsupported_ext
    # OpenSSL → IllegalParameter; LibreSSL → UnsupportedExtension.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference.
    "alert_illegal_param_vs_unsupported_ext/": AllC(
        InnerKnowledgeC("Different(IllegalParameter, UnsupportedExtension)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_decode_err_vs_missing_ext
    # OpenSSL → DecodeError; LibreSSL → MissingExtension.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Benign diagnostic difference.
    "alert_decode_err_vs_missing_ext/": AllC(
        InnerKnowledgeC("Different(DecodeError, MissingExtension)", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] alert_misc_pairs  (residual catch-all)
    #
    # Remaining alert pair divergences not covered by any specific bucket.
    # Should be empty or near-empty after the per-pair buckets above.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: APPROVED. Catch-all for remaining benign diagnostic differences.
    "alert_misc_pairs/": AllC(
        InnerKnowledgeC("Different(", "AlertMessagePayload"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_records_not_released_libre_proceeds  (346 traces)
    #
    # OpenSSL rejects a read attempt because a previous record was not yet consumed
    # by the application (tls_read_record:records not released, tls_common.c:1129).
    # LibreSSL has no equivalent release guard and continues the handshake.
    # Root cause: OpenSSL internal buffer-management consistency check; not mandated
    # by RFC. LibreSSL's different buffering strategy avoids the condition entirely.
    #
    # C1: "records not released" — specific error string, not generic "record layer failure"
    # C2: StepC(f < s) — OpenSSL trips the check first; LibreSSL proceeds further
    # C3: 346/356 traces in the former ossl_record_failure_libre_proceeds; 0 overlap
    #     with ossl_record_too_long or ossl_invalid_aad on 30-trace sample
    # C4: 30-trace sample: sole OpenSSL error function is tls_common.c:1129 in every trace
    # AUDITED BY GEMINI: APPROVED. C1-C4 all pass. v3 upgrade pass.
    "ossl_records_not_released_libre_proceeds/": AllC(
        StatusC(OSSL, "records not released", first_to_fail=True),
        StepC(lambda f, s, total: f < s),
    ),

    # -------------------------------------------------------------------------
    # [RFC] ossl_record_too_long_libre_proceeds  (5 traces)
    #
    # OpenSSL rejects a TLSCiphertext record whose length field exceeds the RFC
    # maximum (tls_validate_record_header:data length too long, tlsany_meth.c:124).
    # RFC 8446 §5.2 MUST: TLSCiphertext.length MUST NOT exceed 2^14 + 256 bytes.
    # RFC 5246 §6.2.3 MUST: fragment length MUST NOT exceed 2^14 + 2048.
    # LibreSSL accepts the oversized record and continues — a direct RFC violation.
    #
    # C1: "data length too long" — specific RFC-enforcement function, not generic
    # C2: StepC(f < s) — OpenSSL enforces the RFC bound first; LibreSSL proceeds
    # C3: 5/356 traces; disjoint from records_not_released and invalid_aad on full set
    # C4: 5 traces; all show tls_validate_record_header as the sole OpenSSL error function
    # AUDITED BY GEMINI: APPROVED. C1-C4 all pass. v3 upgrade pass.
    # Bug report: BUGS/libressl_record_too_long_acceptance.md
    "ossl_record_too_long_libre_proceeds/": AllC(
        StatusC(OSSL, "data length too long", first_to_fail=True),
        StepC(lambda f, s, total: f < s),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_invalid_aad_libre_proceeds  (5 traces)
    #
    # OpenSSL fails during AEAD-GCM decryption because the GCM provider rejects
    # the Additional Authentication Data (ossl_gcm_set_ctx_params:invalid aad,
    # ciphercommon_gcm.c:301), surfacing as tls1_cipher:internal error.
    # LibreSSL either fails at its own MAC check (bad record mac) or succeeds.
    # Root cause: OpenSSL provider AEAD API strictness on AAD construction by
    # the fuzzer; LibreSSL's distinct AEAD implementation handles the same input.
    #
    # C1: "invalid aad" — specific GCM provider error, not generic "record layer failure"
    # C2: StepC(f < s) — OpenSSL fails first on this internal AEAD check
    # C3: 5/356 traces; disjoint from the other two record-failure sub-buckets
    # C4: 5 traces; all show ossl_gcm_set_ctx_params as the triggering function
    # AUDITED BY GEMINI: APPROVED. C1-C4 all pass. v3 upgrade pass.
    "ossl_invalid_aad_libre_proceeds/": AllC(
        StatusC(OSSL, "invalid aad", first_to_fail=True),
        StepC(lambda f, s, total: f < s),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_no_sigalg_libre_proceeds
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "ossl_no_sigalg_libre_proceeds/": AllC(
        AnyC(
            StatusC(OSSL, "no suitable signature algorithm", first_to_fail=True),
            StatusC(OSSL, "no shared signature algorithms", first_to_fail=True),
        ),
        StepC(lambda f, s, total: f < s),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] libre_finished_claim_mid_handshake
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "libre_finished_claim_mid_handshake/": AllC(
        DifferentClaimC(in_first_type="()", in_second_type="Finished"),
        TermContainsC(OSSL, "fn_finished"),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_bad_extension_libre_proceeds  (76 traces)
    #
    # OpenSSL rejects a bad or unsolicited TLS extension (tls_collect_extensions,
    # tls_parse_ctos_sig_algs, tls_parse_stoc_sct) while LibreSSL proceeds.
    # Root cause: OpenSSL's extension-collection layer enforces stricter extension
    # validation before LibreSSL's equivalent check fires. Both PUTs eventually
    # fail, but OpenSSL fails first.
    # C1: "bad extension"/"unsolicited extension" — specific OpenSSL error string
    # C2: StepC(f < s) — OpenSSL's extension check fires first
    # C3: 76/184 traces in former status_ossl_earlier_libre_later; disjoint from
    #     wrong_cipher, server_hello, and renegotiation sub-buckets
    # C4: 122-trace audit — 5 error functions, all OpenSSL extension-validation
    #     code paths; same BENIGN root cause (OpenSSL strict, LibreSSL lenient)
    # AUDITED: C1-C4 pass (C4 at BENIGN-class level). v3 self-audit.
    "ossl_bad_extension_libre_proceeds/": AllC(
        AnyC(
            StatusC(OSSL, "bad extension", first_to_fail=True),
            StatusC(OSSL, "unsolicited extension", first_to_fail=True),
        ),
        StepC(lambda f, s, total: f < s),
        NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
        NotC(DifferentClaimC()),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_wrong_cipher_libre_proceeds  (36 traces)
    #
    # OpenSSL rejects a ServerHello offering an unrecognised or wrong cipher
    # suite (set_client_ciphersuite:wrong cipher returned) while LibreSSL
    # accepts it and proceeds further. Root cause: OpenSSL's cipher-selection
    # validation rejects ciphers LibreSSL's parser also eventually rejects but
    # at a later step.
    # C1: "wrong cipher returned" — specific OpenSSL cipher-selection error string
    # C2: StepC(f < s) — OpenSSL's cipher check fires first
    # C3: 36/184 traces; disjoint from bad_extension and server_hello sub-buckets
    # C4: All 36 traces show set_client_ciphersuite as the sole OpenSSL error function
    # AUDITED: C1-C4 all pass. v3 self-audit.
    "ossl_wrong_cipher_libre_proceeds/": AllC(
        AnyC(
            StatusC(OSSL, "wrong cipher returned", first_to_fail=True),
            StatusC(OSSL, "unknown cipher returned", first_to_fail=True),
        ),
        StepC(lambda f, s, total: f < s),
        NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
        NotC(DifferentClaimC()),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_server_hello_error_libre_proceeds  (12 traces)
    #
    # OpenSSL rejects a malformed or unexpected ServerHello (tls_process_server_hello:
    # bad length / bad extension / invalid session id) while LibreSSL proceeds.
    # Root cause: OpenSSL's ServerHello parser enforces stricter length and field
    # checks at the receive point; LibreSSL is more lenient in this path.
    # C1: "tls_process_server_hello" — specific OpenSSL ServerHello-parsing function
    # C2: StepC(f < s) — OpenSSL's ServerHello check fires first
    # C3: 12/184 traces; disjoint from extension and cipher sub-buckets
    # C4: All 8 traces show tls_process_server_hello as the sole OpenSSL error function
    # AUDITED: C1-C4 all pass. v3 self-audit.
    "ossl_server_hello_error_libre_proceeds/": AllC(
        StatusC(OSSL, "tls_process_server_hello", first_to_fail=True),
        StepC(lambda f, s, total: f < s),
        NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
        NotC(DifferentClaimC()),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] status_ossl_earlier_libre_later  (residual ~60 traces)
    #
    # Residual after splitting out:
    #   ossl_bad_extension_libre_proceeds (76)
    #   ossl_wrong_cipher_libre_proceeds (36)
    #   ossl_server_hello_error_libre_proceeds (12)
    # Remaining ~60 traces:
    #   16 × unsafe legacy renegotiation (final_renegotiate, lacks fn_server_hello
    #       as last input → not captured by ossl_unsafe_legacy_renegotiation)
    #   14 × tls_parse_stoc_sct:bad extension (SCT extension specific)
    #   18 × final_key_share:no suitable key share (in alert context, different from
    #       the dedicated key-share bucket which requires alert pair)
    #   ~12 × misc (bad ecpoint, unexpected message, etc.)
    # Too sparse/heterogeneous for further splitting; documented as residual.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved (original 184-trace form). Revised to residual.
    "status_ossl_earlier_libre_later/": AllC(
        StepC(lambda f, s, total: f < s),
        NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
        NotC(DifferentClaimC()),
    ),

    # -------------------------------------------------------------------------
    # [RFC] libre_bad_length_ossl_proceeds  (33 traces)
    #
    # LibreSSL rejects TLS 1.2 handshake messages whose encoded byte length fails
    # its strict bounds check at ssl_pkt.c:438. Affected states include
    # ACCEPT_SR_KEY_EXCH (28), CONNECT_CR_CERT (3), ACCEPT_SR_CERT_VRFY (1),
    # CONNECT_CR_KEY_EXCH (1). All trigger the same enforcement point; OpenSSL
    # proceeds with the same messages without error.
    # RFC 5246 §7.4 requires length validation, but the precise bound may differ;
    # the LibreSSL rejection may be stricter than RFC mandates. Tag [RFC] pending
    # Auditor verification of whether LibreSSL's bound reflects a MUST requirement.
    #
    # C1: "bad length" — specific LibreSSL error string at ssl_pkt.c:438
    # C2: StepC(s < f) — LibreSSL fails first; OpenSSL proceeds
    # C3: 33/62 traces in former status_libre_earlier_ossl_later; 0 overlap with
    #     libre_parse_tlsext on full set
    # C4: All 33 traces show ssl_pkt.c:438 as the sole LibreSSL error site
    # AUDITED BY GEMINI: APPROVED. C1-C4 all pass. v3 upgrade pass.
    # Bug report: BUGS/libressl_bad_length_rejection.md
    "libre_bad_length_ossl_proceeds/": AllC(
        StatusC(LIBRE, "bad length", first_to_fail=True),
        StepC(lambda f, s, total: s < f),
        NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
        NotC(DifferentClaimC()),
    ),

    # -------------------------------------------------------------------------
    # [RFC] libre_parse_tlsext_ossl_proceeds  (20 traces)
    #
    # LibreSSL fails to parse TLS extensions in a ClientHello during the server
    # path (ACCEPT_SR_CLNT_HELLO:parse tlsext, ssl_srvr.c:1013). OpenSSL parses
    # the same extensions without error and continues the handshake.
    # RFC 8446 §4.2 / RFC 5246 §7.4.1.4: extension parsing failures MUST result
    # in a fatal alert (decode_error or illegal_parameter); LibreSSL does not send
    # the required alert — a possible RFC violation on top of the parsing divergence.
    #
    # C1: "parse tlsext" — specific LibreSSL extension-parsing error function
    # C2: StepC(s < f) — LibreSSL fails first at this specific extension-parse point
    # C3: 20/62 traces; disjoint from libre_bad_length on full set
    # C4: All 20 traces show ssl_srvr.c:1013 as the sole LibreSSL error site
    # AUDITED BY GEMINI: APPROVED. C1-C4 all pass. v3 upgrade pass.
    # Bug report: BUGS/libressl_parse_tlsext_failure.md
    "libre_parse_tlsext_ossl_proceeds/": AllC(
        StatusC(LIBRE, "parse tlsext", first_to_fail=True),
        StepC(lambda f, s, total: s < f),
        NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
        NotC(DifferentClaimC()),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] status_libre_earlier_ossl_later  (residual ~9 traces)
    #
    # Residual catch-all for traces where LibreSSL fails first but the specific
    # LibreSSL error does not match any named sub-bucket above. After splitting
    # out libre_bad_length_ossl_proceeds (33) and libre_parse_tlsext_ossl_proceeds
    # (20), approximately 9 traces remain:
    #   2 × wrong ssl version (ssl_clnt.c:859)
    #   2 × bad decrypt (e_aes.c:1496, AEAD MAC failure)
    #   2 × UNKNOWN SSL internal error
    #   2 × tlspuffin evaluation error (unable to find ApplicationData variable)
    #   1 × Codec error (Failed to parse client ecdh public key)
    # These are too sparse and heterogeneous to form independent buckets.
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved (original 62-trace form). Revised to residual.
    "status_libre_earlier_ossl_later/": AllC(
        StepC(lambda f, s, total: s < f),
        NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
        NotC(DifferentClaimC()),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] status_same_step_different_error
    # -------------------------------------------------------------------------
    # AUDITED BY GEMINI: Approved.
    "status_same_step_different_error/": AllC(
        StepC(lambda f, s, total: f == s and f < total),
        NotC(InnerKnowledgeC("Different(", "AlertMessagePayload")),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_alert_vs_libre_handshake  (217 traces)
    #
    # OpenSSL sends an alert where LibreSSL sends a handshake message instead.
    # Root cause: OpenSSL's signature-algorithm negotiation layer rejects the
    # input with a fatal alert before LibreSSL's equivalent check fires.
    # LibreSSL proceeds and sends a subsequent handshake message into the same
    # round-trip.
    # Distribution (full 217-trace audit):
    #   80 × tls1_set_server_sigalgs:no shared signature algorithms
    #   78 × tls_choose_sigalg:no suitable signature algorithm
    #   58 × tls_parse_ctos_sig_algs:bad extension
    #    1 × tls_parse_ctos_key_share:bad ecpoint
    # All 217 traces share the same BENIGN class: OpenSSL's sig-alg / param
    # validation fires earlier, producing an alert; LibreSSL continues.
    #
    # C1: KnowledgeDiffC(Alert, Handshake) — type-level difference is the specific
    #     observable (OpenSSL sends Alert type; LibreSSL sends Handshake type)
    # C2: StatusC group grounded in OpenSSL's sig-alg validation code paths
    # C3: 217/217 traces covered; no overlap with alert-pair buckets (type differs,
    #     not alert code within the same type)
    # C4: Full 217-trace audit — 4 distinct error functions, all sig-alg or ext
    #     validation in OpenSSL
    # AUDITED: C1 ✓ (KnowledgeDiffC names both types); C2 ✓ (sig-alg error functions
    #     are root-cause-grounded); C3 ✓ (217/217 covered); C4 ✓ (3 functions, all
    #     sig-alg validation in OpenSSL; same BENIGN class). v3 self-audit.
    "ossl_alert_vs_libre_handshake/": AllC(
        KnowledgeDiffC(
            first_type_name="tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload",
            second_type_name="tlspuffin::tls::rustls::msgs::handshake::HandshakeMessagePayload",
        ),
        AnyC(
            StatusC(OSSL, "no shared signature algorithms", first_to_fail=False),
            StatusC(OSSL, "no suitable signature algorithm", first_to_fail=False),
            StatusC(OSSL, "tls_parse_ctos_sig_algs", first_to_fail=False),
            StatusC(OSSL, "tls_parse_ctos_key_share", first_to_fail=False),
        ),
    ),

    # -------------------------------------------------------------------------
    # [BENIGN] ossl_finished_libre_absent  (4 traces)
    #
    # OpenSSL emits a Finished claim; LibreSSL does not. All 4 traces share the
    # same protocol-path divergence: the first knowledge entry is a
    # HandshakeMessagePayload where OpenSSL parses the message as ServerHello
    # (group secp384r1) while LibreSSL parses the same message as a
    # HelloRetryRequest (requesting secp256r1). Because OpenSSL believes the
    # handshake completed normally (it processed a "ServerHello"), it proceeds
    # to emit Finished; LibreSSL, seeing an HRR, takes the retry path and never
    # reaches the Finished state in the trace length.
    # Root cause: OpenSSL / LibreSSL differ in how they distinguish a ServerHello
    # from a HelloRetryRequest based on the magic session_id in the message.
    # This is a BENIGN harness-driven scenario, not a real-world exploitable path.
    #
    # C1: DifferentClaimC(Finished, ()) + InnerKnowledgeC(ServerHello vs HRR) —
    #     two independent specific constraints identifying claim type and protocol path
    # C2: InnerKnowledgeC("Different(ServerHello, HelloRetryRequest)") reflects the
    #     actual root cause (ServerHello vs HRR ambiguity) confirmed in all 4 traces
    # C3: 4/4 traces; InnerKnowledgeC excludes alert-diff and plain claim-diff traces
    # C4: 4 traces; all show the identical ServerHello/HRR knowledge divergence
    # AUDITED BY GEMINI: APPROVED. C1-C4 all pass. v3 upgrade pass.
    "ossl_finished_libre_absent/": AllC(
        DifferentClaimC(in_first_type="Finished", in_second_type="()"),
        InnerKnowledgeC("Different(ServerHello, HelloRetryRequest)", "HandshakeMessagePayload"),
    ),

}

if __name__ == "__main__":
    objective_folder = sys.argv[1] if len(sys.argv) > 1 else "objective"
    run_triaging(
        buckets,
        FIRST_PUT,
        SECOND_PUT,
        source_folder=objective_folder,
        target_folder=objective_folder,
        parallelism=PARALLELISM,
    )
