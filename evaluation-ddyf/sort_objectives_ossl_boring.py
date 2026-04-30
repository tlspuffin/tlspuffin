import sys

from .diff_analyzer import (
    AllC,
    AnyC,
    BucketCondition,
    CheckAgentC,
    InnerKnowledgeC,
    KnowledgeDiffC,
    NoDiffC,
    NotC,
    StatusC,
    StepC,
    TermContainsC,
    run_triaging,
)

OSSL = 1
BORING = 2
FIRST_PUT = "openssl340"
SECOND_PUT = "boringssl202403"
PARALLELISM = 10

buckets: dict[str, BucketCondition] = {
    # ──────────────────────────────────────────────────────────────────────────
    # FLAKINESS
    # ──────────────────────────────────────────────────────────────────────────
    # No differences reported → execution is non-deterministic / flaky.
    "no_errors/": NoDiffC(),
    # ──────────────────────────────────────────────────────────────────────────
    # RFC VIOLATIONS
    # ──────────────────────────────────────────────────────────────────────────
    # RFC: OpenSSL accepts HelloRequest (handshake type 0, RESERVED in TLS 1.3)
    # in a TLS 1.3 connection without aborting, while BoringSSL correctly sends
    # an "unexpected_message" alert.
    #
    # RFC 8446 §4: "Protocol messages MUST be sent in the order defined in
    # Section 4.4.1 … A peer which receives a handshake message in an
    # unexpected order MUST abort the handshake with an 'unexpected_message'
    # alert." The TLS 1.3 HandshakeType enum does not include HelloRequest
    # (hello_request_RESERVED(0), see RFC 8446 Appendix B.3); receiving it is
    # therefore an unexpected message.
    #
    # Tag: RFC
    # TODO: test tcp
    "tls13_hello_request/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        TermContainsC(BORING, "fn_hello_request"),
        StatusC(BORING, in_error="UNEXPECTED_MESSAGE"),
        # BoringSSL fails before OpenSSL finishes: OSSL tolerates the message
        # and executes more steps, while BORING aborts immediately.
        StepC(lambda f, s, _: f > s),
    ),
    # RFC: OpenSSL does NOT abort the handshake when it cannot verify a client
    # CertificateVerify signature (the client certificate sent in the same
    # trace is malformed / contains no valid public key).  BoringSSL correctly
    # rejects the message with [BAD_SIGNATURE].
    #
    # RFC 8446 §4.4.3: "If the verification fails, the receiver MUST terminate
    # the handshake with a 'decrypt_error' alert."
    #
    # Tag: RFC (OpenSSL fails to enforce §4.4.3; potential VULN if client auth
    # is bypassed as a result)
    #
    # TODO: fix boring
    "bad_signature_boring/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(BORING, in_error="BAD_SIGNATURE"),
        # The client sends a Certificate built from fn_certificate13 with a
        # payload derived from the server's CertificateRequest context
        # (fn_find_server_certificate_request), yielding a cert with no valid
        # public key, then a CertificateVerify signed via fn_rsa_sign_client.
        TermContainsC(BORING, "fn_find_server_certificate_request"),
        TermContainsC(BORING, "fn_certificate_verify"),
        TermContainsC(BORING, "fn_rsa_sign_client"),
    ),
    # RFC: OpenSSL sends "illegal_parameter" instead of "missing_extension"
    # when a ServerHello is missing the mandatory "key_share" extension.
    # BoringSSL correctly sends "missing_extension".
    #
    # RFC 8446 §9.2: "A peer that receives a ClientHello or ServerHello message
    # that does not contain a mandatory extension MUST abort the handshake with
    # a 'missing_extension' alert." The "key_share" extension is mandatory in
    # ServerHello when (EC)DHE key exchange is used (RFC 8446 §9.2).
    #
    # Tag: RFC (OpenSSL uses wrong alert code; BoringSSL is correct)
    #
    # https://github.com/openssl/openssl/issues/30818
    "alert_illegal_param_ossl_vs_missing_ext_key_share/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, MissingExtension))]"),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
        NotC(TermContainsC(OSSL, "fn_key_share", last_input_executed=True)),
    ),
    # RFC: OpenSSL sends "illegal_parameter" instead of "missing_extension"
    # when a ClientHello is missing the mandatory "supported_groups" extension.
    # BoringSSL correctly sends "missing_extension".
    #
    # RFC 8446 §9.2: Same requirement as above.
    #
    # Tag: RFC (OpenSSL uses wrong alert code; BoringSSL is correct)
    #
    # Race condition
    "alert_illegal_param_ossl_vs_missing_ext_supported_groups/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, MissingExtension))]"),
        TermContainsC(OSSL, "fn_client_hello", last_input_executed=True),
        NotC(TermContainsC(OSSL, "fn_support_group_extension", last_input_executed=True)),
    ),
    # RFC: BoringSSL sends "handshake_failure" instead of "missing_extension"
    # when a ClientHello is missing a mandatory extension (e.g. "supported_groups"
    # when key_share is present).  OpenSSL correctly sends "missing_extension".
    #
    # RFC 8446 §9.2: "Servers receiving a ClientHello which does not conform to
    # these requirements MUST abort the handshake with a 'missing_extension'
    # alert."
    #
    # Tag: RFC (BoringSSL uses wrong alert code; OpenSSL is correct)
    #
    # TODO: CONFIRMED
    "alert_missing_ext_ossl_vs_handshake_failure_boring/": InnerKnowledgeC(
        "[Description(Different(MissingExtension, HandshakeFailure))]"
    ),
    # RFC: BoringSSL sends "illegal_parameter" instead of "unsupported_extension"
    # when it receives a ServerHello or other message that contains an extension
    # not first offered in the ClientHello.  OpenSSL correctly sends
    # "unsupported_extension".
    #
    # RFC 8446 §4.2: "Implementations MUST NOT send extension responses if the
    # remote endpoint did not send the corresponding extension requests … Upon
    # receiving such an extension, an endpoint MUST abort the handshake with an
    # 'unsupported_extension' alert."
    #
    # Tag: RFC (BoringSSL uses wrong alert code; OpenSSL is correct)
    #
    # Race condition
    "alert_unsupported_ext_ossl_vs_illegal_param_boring/": InnerKnowledgeC(
        "[Description(Different(UnsupportedExtension, IllegalParameter))]"
    ),
    # RFC: OpenSSL sends "illegal_parameter" instead of "unsupported_extension"
    # when it receives an extension not offered in the ClientHello.
    # BoringSSL correctly sends "unsupported_extension".
    #
    # RFC 8446 §4.2 (same requirement as above).
    #
    # Tag: RFC (OpenSSL uses wrong alert code; BoringSSL is correct)
    "alert_illegal_param_ossl_vs_unsupported_ext_boring/": InnerKnowledgeC(
        "[Description(Different(IllegalParameter, UnsupportedExtension))]"
    ),
    # RFC: BoringSSL accepts a TLS 1.2 ServerHello that lacks the
    # "renegotiation_info" extension (required by RFC 5746), completing the
    # handshake successfully.  OpenSSL correctly aborts.
    #
    # RFC 5746 §3.4: "Both the SSLv3/TLS renegotiation and the initial
    # handshake for a connection on which renegotiation will be requested MUST
    # use this extension."  The initial TLS 1.2 handshake MUST include either
    # the renegotiation_info extension or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    # cipher suite value.
    #
    # Tag: RFC (BoringSSL violates RFC 5746 §3.4 by not requiring
    # renegotiation_info on the initial TLS 1.2 handshake)
    "tls12_renegotiation_info_boring_ok/": AllC(
        StatusC(
            OSSL, in_error="final_renegotiate:unsafe legacy renegotiation disabled"
        ),
        # BoringSSL completes all steps (second_executed_steps == total_step),
        # meaning it accepted the TLS 1.2 ServerHello without renegotiation_info
        # and finished the handshake successfully.  Traces where BoringSSL also
        # fails are caught by final_renegotiate_both_fail below.
        StepC(lambda f, s, t: s == t),
    ),
    # ──────────────────────────────────────────────────────────────────────────
    # BENIGN – Different alert codes for the same class of malformed input
    # ──────────────────────────────────────────────────────────────────────────
    # ──────────────────────────────────────────────────────────────────────────
    # BENIGN: Both implementations reject a malformed or protocol-violating
    # message but send different alert codes.  OpenSSL sends "illegal_parameter"
    # while BoringSSL sends "decode_error".  Split by root cause.
    # ──────────────────────────────────────────────────────────────────────────
    # BENIGN: ClientHello with HRR magic random value causes OpenSSL to report
    # "illegal_parameter" (bad length) while BoringSSL reports "decode_error".
    #
    # RFC 8446 §4.1.3: The Random field in ClientHello contains a specific
    # 32-byte value for HelloRetryRequest. Using it in a normal ClientHello is
    # a protocol violation.
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_decode_error_hrr_random/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_hello_retry_request_random", last_input_executed=True),
    ),
    # BENIGN: ClientHello with empty cipher_suites list. OpenSSL reports
    # "illegal_parameter" (no ciphers specified), BoringSSL reports "decode_error".
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_decode_error_empty_ciphers/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_new_cipher_suites", last_input_executed=True),
        NotC(TermContainsC(OSSL, "fn_append_cipher_suite", last_input_executed=True)),
    ),
    # BENIGN: ServerHello with TLS 1.3 legacy_version (0x0304) combined with
    # TLS 1.2 cipher suite. OpenSSL reports "illegal_parameter", BoringSSL
    # reports "decode_error".
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_decode_error_version_mismatch/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_protocol_version13", last_input_executed=True),
        TermContainsC(OSSL, "fn_cipher_suite12", last_input_executed=True),
    ),
    # BENIGN: ServerHello with weak/export cipher suite. OpenSSL reports
    # "illegal_parameter" (bad extension), BoringSSL reports "decode_error".
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_decode_error_weak_cipher/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_weak_export_cipher_suite", last_input_executed=True),
    ),
    # BENIGN: ServerHello with duplicate extensions. OpenSSL reports
    # "illegal_parameter" (bad extension), BoringSSL reports "decode_error".
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_decode_error_duplicate_ext/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_server_extensions_append", last_input_executed=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # BENIGN: Other malformed messages causing IllegalParameter vs DecodeError.
    # Catch-all for remaining cases not matched above.
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_decode_error_other/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        NotC(TermContainsC(OSSL, "fn_hello_retry_request_random", last_input_executed=True)),
        NotC(TermContainsC(OSSL, "fn_new_cipher_suites", last_input_executed=True)),
        NotC(AllC(
            TermContainsC(OSSL, "fn_protocol_version13", last_input_executed=True),
            TermContainsC(OSSL, "fn_cipher_suite12", last_input_executed=True),
        )),
        NotC(TermContainsC(OSSL, "fn_weak_export_cipher_suite", last_input_executed=True)),
        NotC(AllC(
            TermContainsC(OSSL, "fn_server_extensions_append", last_input_executed=True),
            TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
        )),
    ),
    # BENIGN: Same as above but reversed – OpenSSL sends "decode_error" and
    # BoringSSL sends "illegal_parameter".
    #
    # Typical cause: ServerHello with hello_retry_request_random together with
    # a TLS 1.2 cipher suite — OpenSSL fails with "bad length" (decode_error),
    # BoringSSL fails with "wrong cipher returned" (illegal_parameter).
    #
    # Tag: BENIGN
    "alert_decode_error_ossl_vs_illegal_param_boring/": InnerKnowledgeC(
        "[Description(Different(DecodeError, IllegalParameter))]"
    ),
    # BENIGN: Both reject the message with alert codes from different semantic
    # categories: OpenSSL sends "unexpected_message", BoringSSL sends
    # "illegal_parameter".
    #
    # Typical cause: messages sent out of the expected handshake order, or
    # encrypted messages using incorrect keys / sequence numbers.  Both
    # implementations correctly identify a protocol violation; the choice of
    # alert code is implementation-defined.
    #
    # Tag: BENIGN
    "alert_unexpected_msg_ossl_vs_illegal_param_boring/": InnerKnowledgeC(
        "[Description(Different(UnexpectedMessage, IllegalParameter))]"
    ),
    # BENIGN: OpenSSL sends "unexpected_message", BoringSSL sends "decode_error".
    # Similar to the bucket above; both implementations detect a protocol
    # anomaly but categorise it differently.
    #
    # Tag: BENIGN
    "alert_unexpected_msg_ossl_vs_decode_error_boring/": InnerKnowledgeC(
        "[Description(Different(UnexpectedMessage, DecodeError))]"
    ),
    # BENIGN: OpenSSL sends "handshake_failure", BoringSSL sends
    # "illegal_parameter".  Both correctly abort the handshake; the alert code
    # selection is implementation-defined for these inputs.
    #
    # Tag: BENIGN
    "alert_handshake_failure_ossl_vs_illegal_param_boring/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, IllegalParameter))]"
    ),
    # BENIGN: OpenSSL sends "illegal_parameter", BoringSSL sends
    # "handshake_failure".  Symmetric of the bucket above.
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_handshake_failure_boring/": InnerKnowledgeC(
        "[Description(Different(IllegalParameter, HandshakeFailure))]"
    ),
    # ──────────────────────────────────────────────────────────────────────────
    # BENIGN – Different status/error at the record or state-machine layer
    # ──────────────────────────────────────────────────────────────────────────
    # BENIGN: OpenSSL reports "records not released" (a record was received
    # before the previous one was fully consumed) and aborts the execution,
    # while BoringSSL completes the handshake successfully.
    #
    # The typical trace sends a close_notify alert very early in the handshake
    # (before completion) and then continues with further handshake messages.
    # RFC 8446 §6.1 allows both interpretations: the peer MAY respond with
    # close_notify and stop, or MAY treat close_notify during a handshake as
    # an edge case.  BoringSSL completes the handshake; OpenSSL refuses to
    # read more records after receiving close_notify.  Neither behaviour is
    # explicitly forbidden by the RFC.
    #
    # Tag: BENIGN
    # The trace sends fn_alert_close_notify early (before the handshake
    # completes) and then continues with further messages.  OpenSSL refuses to
    # read more records after receiving close_notify; BoringSSL ignores the
    # early alert and finishes the handshake.  first_to_fail=False is needed
    # because BoringSSL may execute more steps than OpenSSL.
    "records_not_released_ossl/": AllC(
        StatusC(
            OSSL, in_error="tls_read_record:records not released", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_alert_close_notify"),
    ),
    # BENIGN: OpenSSL fails with "bad record type" (tls13_validate_record_header)
    # while BoringSSL fails with [DECODE_ERROR].  Both implementations detect
    # that the record content type is invalid for a TLS 1.3 record, but at
    # slightly different points in their processing pipelines.
    #
    # RFC 8446 §5.1: TLS 1.3 record content types are strictly defined; an
    # invalid type is a protocol error.  Both alerts ("decode_error" and the
    # record-layer failure) are valid responses.
    #
    # Tag: BENIGN
    # first_to_fail=False: BoringSSL may fail at an earlier step with
    # [DECODE_ERROR] while OpenSSL fails later with the record-type error.
    "bad_record_type_ossl/": StatusC(
        OSSL,
        in_error="tls13_validate_record_header:bad record type",
        first_to_fail=False,
    ),
    # BENIGN: OpenSSL fails with "decryption failed or bad record MAC" at a
    # later step, while BoringSSL detects a MAC / authentication tag failure
    # earlier (DIGEST_CHECK_FAILED or DECODE_ERROR).  Both implementations
    # ultimately detect the same AEAD authentication failure; the difference
    # is in when each implementation checks the authentication tag.
    #
    # Tag: BENIGN
    # first_to_fail=False: BoringSSL often detects the MAC failure earlier
    # (DIGEST_CHECK_FAILED / DECODE_ERROR) than OpenSSL.
    "decryption_failed_ossl_vs_digest_check_boring/": StatusC(
        OSSL,
        in_error="tls_get_more_records:decryption failed or bad record mac",
        first_to_fail=False,
    ),
    # BENIGN: OpenSSL (acting as client) aborts with "unsafe legacy renegotiation
    # disabled" on receipt of a TLS 1.2 ServerHello without a renegotiation_info
    # extension, while BoringSSL also fails but at a later step with
    # [UNEXPECTED_MESSAGE].  Both implementations reject the malformed TLS 1.2
    # downgrade attempt; the difference is only in which validation fires first.
    #
    # Tag: BENIGN
    "final_renegotiate_both_fail/": StatusC(
        OSSL, in_error="final_renegotiate:unsafe legacy renegotiation disabled"
    ),
    # BENIGN: OpenSSL (acting as server) fails with "no shared cipher" when it
    # receives a ClientHello whose cipher suites do not include any cipher the
    # server supports.  BoringSSL fails with [UNEXPECTED_MESSAGE] at a
    # different step, indicating it reached a different state before detecting
    # the incompatibility.  Both abort correctly; the order/choice of error
    # is implementation-defined.
    #
    # Tag: BENIGN
    "no_shared_cipher_ossl/": StatusC(
        OSSL, in_error="tls_post_process_client_hello:no shared cipher"
    ),
    # BENIGN: Both implementations receive a message that violates handshake
    # state-machine ordering and send "unexpected_message", but they detect
    # the violation at different steps.  OpenSSL triggers on a client-state
    # transition check, BoringSSL on a different internal check.
    #
    # RFC 8446 §4: "A peer which receives a handshake message in an unexpected
    # order MUST abort the handshake with an 'unexpected_message' alert."
    # Both are compliant; the difference is purely which step triggers first.
    #
    # Tag: BENIGN
    # first_to_fail=False for OSSL: BoringSSL may execute fewer steps and fail
    # first, even though both ultimately send unexpected_message.
    "both_unexpected_message/": AllC(
        StatusC(
            OSSL,
            in_error="ossl_statem_client_read_transition:unexpected message",
            first_to_fail=False,
        ),
        StatusC(BORING, in_error="UNEXPECTED_MESSAGE", first_to_fail=False),
    ),
    # --------------------------------------------------------------------------
    # BENIGN – Additional alert-code differences
    # --------------------------------------------------------------------------
    # BENIGN: OpenSSL sends "handshake_failure", BoringSSL sends "decode_error".
    # Both abort on a malformed or incompatible handshake message; the specific
    # alert code is implementation-defined for these inputs.
    #
    # Tag: BENIGN
    "alert_handshake_failure_ossl_vs_decode_error_boring/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, DecodeError))]"
    ),
    # BENIGN: OpenSSL sends "handshake_failure", BoringSSL sends
    # "unsupported_extension".  Both abort; the code choice is
    # implementation-defined.
    #
    # Tag: BENIGN
    "alert_handshake_failure_ossl_vs_unsupported_ext_boring/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, UnsupportedExtension))]"
    ),
    # BENIGN: OpenSSL sends "decode_error", BoringSSL sends "handshake_failure".
    # Symmetric of the bucket above.
    #
    # Tag: BENIGN
    "alert_decode_error_ossl_vs_handshake_failure_boring/": InnerKnowledgeC(
        "[Description(Different(DecodeError, HandshakeFailure))]"
    ),
    # RFC: OpenSSL sends "missing_extension", BoringSSL sends
    # "unsupported_extension".  These are semantically opposite alerts:
    # missing_extension(109) is for absent mandatory extensions while
    # unsupported_extension(110) is for unexpected present extensions.
    # OpenSSL's choice is more likely correct; BoringSSL may be mis-classifying
    # the violation.
    #
    # RFC 8446 Section 9.2: "A peer that receives a ... message that does not
    # contain a mandatory extension MUST abort the handshake with a
    # 'missing_extension' alert."
    #
    # Tag: RFC (BoringSSL uses wrong alert code; OpenSSL is correct)
    "alert_missing_ext_ossl_vs_unsupported_ext_boring/": InnerKnowledgeC(
        "[Description(Different(MissingExtension, UnsupportedExtension))]"
    ),
    # RFC: OpenSSL sends "missing_extension", BoringSSL sends
    # "illegal_parameter".  OpenSSL is correct per RFC 8446 Section 9.2.
    #
    # Tag: RFC (BoringSSL uses wrong alert code; OpenSSL is correct)
    "alert_missing_ext_ossl_vs_illegal_param_boring/": InnerKnowledgeC(
        "[Description(Different(MissingExtension, IllegalParameter))]"
    ),
    # BENIGN: OpenSSL sends "unsupported_extension", BoringSSL sends
    # "decode_error".  Both detect an unexpected or malformed extension; the
    # specific alert is implementation-defined.
    #
    # Tag: BENIGN
    "alert_unsupported_ext_ossl_vs_decode_error_boring/": InnerKnowledgeC(
        "[Description(Different(UnsupportedExtension, DecodeError))]"
    ),
    # --------------------------------------------------------------------------
    # BENIGN – Additional status/error differences
    # --------------------------------------------------------------------------
    # BENIGN: OpenSSL (client) fails with "tls_process_server_hello:bad length"
    # when it receives a ServerHello whose Random field contains the
    # HelloRetryRequest magic value (fn_hello_retry_request_random) combined
    # with a TLS 1.2 cipher suite — a malformed pseudo-HRR.  BoringSSL fails
    # with [UNEXPECTED_MESSAGE] at a different step.  Both correctly reject the
    # input; the choice of error path is implementation-defined.
    #
    # Tag: BENIGN
    "tls_process_server_hello_bad_length/": AllC(
        StatusC(
            OSSL, in_error="tls_process_server_hello:bad length", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_hello_retry_request_random"),
    ),
    # BENIGN: OpenSSL (server) fails with "tls_process_cert_verify:bad
    # signature" when it receives a CertificateVerify whose signature does not
    # verify against the certificate.  BoringSSL fails earlier with [DECODE_ERROR].
    # Both detect the same underlying authentication failure via different code
    # paths.
    #
    # Tag: BENIGN
    "tls_process_cert_verify_bad_signature_ossl/": StatusC(
        OSSL,
        in_error="tls_process_cert_verify:bad signature",
        first_to_fail=False,
    ),
    # RFC: OpenSSL (client) successfully completes a TLS 1.3 handshake after
    # receiving a ServerHello that is missing the mandatory "key_share"
    # extension.  BoringSSL correctly rejects it with [DECODE_ERROR].
    #
    # RFC 8446 Section 9.2: "A peer that receives a ... ServerHello message
    # that does not contain a mandatory extension MUST abort the handshake with
    # a 'missing_extension' alert."  The "key_share" extension is mandatory in
    # ServerHello when (EC)DHE key exchange is in use.
    #
    # Tag: RFC (OpenSSL violates Section 9.2 by accepting a ServerHello missing
    # key_share; potential VULN — the derived keys may be compromised)
    "ossl_ok_boring_decode_error_no_key_share/": AllC(
        StatusC(BORING, in_error="DECODE_ERROR"),
        # OSSL completed all steps (succeeded); BORING failed before the end.
        StepC(lambda f, s, t: f == t and s < t),
        TermContainsC(BORING, "fn_server_hello", last_input_executed=True),
    ),
    # BENIGN: OpenSSL (server) fails with "ssl3_read_bytes:unexpected message"
    # when it receives fn_alert_close_notify as the very first message (before
    # any handshake), while BoringSSL ignores the pre-handshake close_notify
    # and completes the handshake successfully.  RFC 8446 does not explicitly
    # define the behaviour on receiving an alert before handshake establishment,
    # so both responses are permissible.
    #
    # Tag: BENIGN
    "ssl3_unexpected_boring_ok/": AllC(
        StatusC(
            OSSL, in_error="ssl3_read_bytes:unexpected message", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_alert_close_notify"),
        # BoringSSL completed all steps (succeeded).
        StepC(lambda f, s, t: s == t),
    ),
    # BENIGN: OpenSSL (server) fails with "ssl3_read_bytes:unexpected message"
    # and BoringSSL also fails (with an evaluation error or a different alert).
    # Catch-all for the remaining ssl3_read_bytes:unexpected traces not matched
    # by ssl3_unexpected_boring_ok above.
    #
    # Tag: BENIGN
    "ssl3_unexpected_both_fail/": StatusC(
        OSSL,
        in_error="ssl3_read_bytes:unexpected message",
        first_to_fail=False,
    ),
    # BENIGN: The trace itself contains a function symbol whose evaluation
    # fails (e.g. a Malformed or Crypto error from rustls internals).  The
    # resulting differential is an artefact of the fuzzer being unable to
    # compute the term, not a meaningful protocol difference.
    #
    # Tag: BENIGN
    "function_eval_error/": AnyC(
        StatusC(
            OSSL, in_error="error executing a function symbol", first_to_fail=False
        ),
        StatusC(
            BORING, in_error="error executing a function symbol", first_to_fail=False
        ),
    ),
    # --------------------------------------------------------------------------
    # BENIGN – Additional alert-code pair differences
    # --------------------------------------------------------------------------
    # BENIGN: OpenSSL sends "decode_error", BoringSSL sends "unsupported_extension".
    # Both implementations detect a protocol anomaly but categorise it differently.
    #
    # Tag: BENIGN
    "alert_decode_error_ossl_vs_unsupported_ext_boring/": InnerKnowledgeC(
        "[Description(Different(DecodeError, UnsupportedExtension))]"
    ),
    # BENIGN: OpenSSL sends "illegal_parameter", BoringSSL sends
    # "unexpected_message".  Both abort; the specific code is
    # implementation-defined.
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_unexpected_msg_boring/": InnerKnowledgeC(
        "[Description(Different(IllegalParameter, UnexpectedMessage))]"
    ),
    # BENIGN: OpenSSL sends "decode_error", BoringSSL sends "missing_extension".
    # Both detect a malformed or incomplete message; the choice of alert code is
    # implementation-defined.
    #
    # Tag: BENIGN
    "alert_decode_error_ossl_vs_missing_ext_boring/": InnerKnowledgeC(
        "[Description(Different(DecodeError, MissingExtension))]"
    ),
    # BENIGN: OpenSSL sends "illegal_parameter", BoringSSL sends "internal_error".
    # An "internal_error" alert from BoringSSL indicates an unexpected internal
    # condition; both implementations abort correctly.
    #
    # Tag: BENIGN
    "alert_illegal_param_ossl_vs_internal_error_boring/": InnerKnowledgeC(
        "[Description(Different(IllegalParameter, InternalError))]"
    ),
    # BENIGN: One PUT produces an AlertMessagePayload knowledge entry while the
    # other produces nothing (unit type).  The implementations diverge on whether
    # to emit an alert for this input.
    #
    # Tag: BENIGN
    "knowledge_alert_vs_none/": KnowledgeDiffC(
        "tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload", "()"
    ),
    # --------------------------------------------------------------------------
    # BENIGN – Additional status/error differences
    # --------------------------------------------------------------------------
    # BENIGN: OpenSSL (server) fails with "tls_parse_ctos_key_share:bad key share"
    # when it receives a ClientHello whose key_share entry is malformed or
    # incompatible (e.g. the ClientHello Random contains the HelloRetryRequest
    # magic value, causing OpenSSL to treat it as a second CH with a mismatched
    # key share).  BoringSSL behaviour varies: it may succeed, fail with
    # [WRONG_CURVE], [BAD_DECRYPT], or have an evaluation error.  All variants
    # are grouped here as the root cause — a malformed ClientHello key_share — is
    # the same.
    #
    # Tag: BENIGN
    "tls_parse_ctos_key_share_bad/": AllC(
        StatusC(
            OSSL, in_error="tls_parse_ctos_key_share:bad key share", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_hello_retry_request_random"),
    ),
    # BENIGN: OpenSSL (client) fails while processing the server Certificate
    # message: either an ASN.1 parsing error or a length error.  BoringSSL
    # fails with [DECODE_ERROR] or another error at a different step.  Both
    # detect invalid certificate data via different code paths.
    #
    # Tag: BENIGN
    "tls_process_server_certificate_ossl/": StatusC(
        OSSL, in_error="tls_process_server_certificate", first_to_fail=False
    ),
    # BENIGN: OpenSSL (client) fails with "ossl_statem_client_read_transition:
    # unexpected message" when it receives a message that violates its client
    # state machine.  BoringSSL behaviour varies (DECODE_ERROR, BAD_DECRYPT,
    # Success, or evaluation error).  OpenSSL is detecting a handshake ordering
    # or message-type violation; the difference in BORING's reaction is
    # implementation-defined.
    #
    # Tag: BENIGN
    "ossl_statem_client_unexpected/": StatusC(
        OSSL,
        in_error="ossl_statem_client_read_transition:unexpected message",
        first_to_fail=False,
    ),
    # BENIGN: OpenSSL fails at the post-processing stage of a TLS 1.3 record
    # ("tls13_common_post_process_record:bad") while BoringSSL fails with
    # [BAD_DECRYPT] / [DECRYPTION_FAILED_OR_BAD_RECORD_MAC].  Both detect an
    # authentication failure on the same record; the difference is in which
    # internal check fires first.
    #
    # Tag: BENIGN
    "tls13_post_process_record_bad_ossl/": StatusC(
        OSSL, in_error="tls13_common_post_process_record:bad", first_to_fail=False
    ),
    # BENIGN: OpenSSL (server) fails with "tls_collect_extensions:bad extension"
    # or "tls_collect_extensions:unsolicited extension" when it receives a
    # handshake message containing a malformed or unexpected extension.
    # BoringSSL fails with [DECODE_ERROR] or [UNEXPECTED_MESSAGE] at a different
    # step.  Both implementations correctly reject the invalid input.
    #
    # Tag: BENIGN
    "tls_collect_extensions_bad_ossl/": StatusC(
        OSSL, in_error="tls_collect_extensions", first_to_fail=False
    ),
    # BENIGN: OpenSSL (client) fails while processing the server Finished message
    # ("tls_process_finished:digest failure").  BoringSSL fails earlier with
    # [DECODE_ERROR].  Both detect a MAC/integrity failure; the difference is
    # purely in which step each implementation verifies it.
    #
    # Tag: BENIGN
    "tls_process_finished_digest_ossl/": StatusC(
        OSSL, in_error="tls_process_finished:digest", first_to_fail=False
    ),
    # BENIGN: OpenSSL (server) fails while post-processing a client certificate
    # ("tls_post_process_server_certificate:certificate verify failed" or similar).
    # BoringSSL fails with [BAD_DECRYPT] at a different step.
    #
    # Tag: BENIGN
    "tls_post_process_certificate_ossl/": StatusC(
        OSSL, in_error="tls_post_process_server_certificate", first_to_fail=False
    ),
    # RFC: OpenSSL (client) successfully completes a TLS 1.3 handshake after
    # receiving a message with an unexpected extension (one not offered in the
    # ClientHello), while BoringSSL correctly rejects it with
    # [UNEXPECTED_EXTENSION].
    #
    # RFC 8446 Section 4.2: "Upon receiving such an extension, an endpoint MUST
    # abort the handshake with an 'unsupported_extension' alert."  OpenSSL
    # accepting the connection is an RFC violation.
    #
    # Tag: RFC (OpenSSL violates Section 4.2; BoringSSL is correct)
    "ossl_ok_boring_unexpected_extension/": AllC(
        StatusC(BORING, in_error="UNEXPECTED_EXTENSION"),
        StepC(lambda f, s, t: f == t and s < t),
    ),
    # BENIGN: OpenSSL successfully completes the handshake while BoringSSL fails
    # with [BAD_DECRYPT] / [DECRYPTION_FAILED_OR_BAD_RECORD_MAC].  BoringSSL
    # detects an AEAD authentication failure that OpenSSL either does not check
    # at this point or handles differently.
    #
    # Tag: BENIGN
    "ossl_ok_boring_bad_decrypt/": AllC(
        StatusC(BORING, in_error="DECRYPTION_FAILED_OR_BAD_RECORD_MAC"),
        StepC(lambda f, s, t: f == t and s < t),
    ),
    # BENIGN: OpenSSL (server) fails with "tls_process_certificate_request:bad
    # extension" or similar when receiving a CertificateRequest with unexpected
    # content.  BoringSSL fails with [DECODE_ERROR] at a different step.
    #
    # Tag: BENIGN
    "tls_process_certificate_request_ossl/": StatusC(
        OSSL, in_error="tls_process_certificate_request", first_to_fail=False
    ),
    # BENIGN: OpenSSL fails while parsing a signed_certificate_timestamp (SCT)
    # extension ("tls_parse_stoc_sct:bad extension").  BoringSSL fails with
    # [DECODE_ERROR].  Both detect a malformed extension; the difference is
    # which parser catches it.
    #
    # Tag: BENIGN
    "tls_parse_stoc_sct_bad_ossl/": StatusC(
        OSSL, in_error="tls_parse_stoc_sct:bad", first_to_fail=False
    ),
    # BENIGN: OpenSSL (server) fails while validating a ServerHello field
    # ("tls_process_server_hello:invalid value" or similar).  BoringSSL fails
    # with [UNEXPECTED_MESSAGE].  Both reject the malformed ServerHello; the
    # specific validation point differs.
    #
    # Tag: BENIGN
    "tls_process_server_hello_invalid_ossl/": StatusC(
        OSSL, in_error="tls_process_server_hello:invalid", first_to_fail=False
    ),
    # BENIGN: OpenSSL (server) fails with "tls_parse_ctos_key_share:bad key
    # share" when the ClientHello offers fn_key_share_deterministic_extension
    # for a group (e.g. x25519) that is NOT listed in the supported_groups
    # extension (e.g. only secp384r1).  OpenSSL immediately rejects the mismatch
    # while BoringSSL is more permissive: it may send HelloRetryRequest,
    # succeed, or fail with [WRONG_CURVE] / [CLIENTHELLO_PARSE_FAILED] /
    # [MISSING_KEY_SHARE] / [BAD_DECRYPT] / evaluation error.
    # Root cause: fn_key_share_deterministic_extension uses a group absent from
    # fn_support_group_extension_make, creating an incompatible key share.
    #
    # Tag: BENIGN
    "tls_parse_ctos_key_share_bad_other/": AllC(
        StatusC(
            OSSL, in_error="tls_parse_ctos_key_share:bad key share", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_key_share_deterministic_extension"),
        NotC(TermContainsC(OSSL, "fn_hello_retry_request_random")),
    ),
    # --------------------------------------------------------------------------
    # BENIGN – Remaining alert-code pair differences
    # --------------------------------------------------------------------------
    # BENIGN: OpenSSL sends "missing_extension", BoringSSL sends "decode_error".
    # Both detect an absent mandatory extension; the specific alert code choice
    # is implementation-defined.
    #
    # Tag: BENIGN
    "alert_missing_ext_ossl_vs_decode_error_boring/": InnerKnowledgeC(
        "[Description(Different(MissingExtension, DecodeError))]"
    ),
    # BENIGN: OpenSSL sends "handshake_failure", BoringSSL sends
    # "unexpected_message".  Both abort the handshake; the code is
    # implementation-defined.
    #
    # Tag: BENIGN
    "alert_handshake_failure_ossl_vs_unexpected_msg_boring/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, UnexpectedMessage))]"
    ),
    # BENIGN: OpenSSL sends "protocol_version", BoringSSL sends
    # "illegal_parameter".  Both detect a version negotiation failure; the
    # specific alert is implementation-defined for this input.
    #
    # Tag: BENIGN
    "alert_protocol_version_ossl_vs_illegal_param_boring/": InnerKnowledgeC(
        "[Description(Different(ProtocolVersion, IllegalParameter))]"
    ),
    # RFC: One PUT interprets a server message as a ServerHello while the other
    # interprets it as a HelloRetryRequest.  RFC 8446 Section 4.1.3 mandates:
    # "Upon receiving a message with type server_hello, implementations MUST
    # first examine the Random value and, if it matches [the HRR magic value],
    # process it as described in Section 4.1.4."  If OpenSSL fails to detect
    # the HRR magic random and treats the message as a ServerHello, it violates
    # this requirement.
    #
    # Tag: RFC (OpenSSL may fail to distinguish ServerHello from
    # HelloRetryRequest via the magic Random value; BoringSSL is correct)
    "server_hello_vs_hrr_divergence/": InnerKnowledgeC(
        "Different(ServerHello, HelloRetryRequest)"
    ),
    # --------------------------------------------------------------------------
    # BENIGN – Remaining rare status differences
    # --------------------------------------------------------------------------
    # BENIGN: OpenSSL fails with "tls_get_more_records:packet length too long"
    # because the coalesced server flight includes fn_certificate_status with a
    # large random payload (fn_payload_u24(fn_random_...)), causing the total
    # TLS record to exceed the 2^14-byte limit (RFC 8446 Section 5.1).
    # BoringSSL fails with [DECODE_ERROR].  Both detect the oversized record;
    # the difference is purely which check triggers first.
    #
    # Tag: BENIGN
    "tls_get_more_records_packet_too_long_ossl/": AllC(
        StatusC(
            OSSL,
            in_error="tls_get_more_records:packet length too long",
            first_to_fail=False,
        ),
        TermContainsC(OSSL, "fn_certificate_status"),
    ),
    # BENIGN: OpenSSL (client) fails at "tls_process_finished:not equal"
    # because the server's Finished MAC is wrong.  The trace builds a fake
    # server flight using fn_encrypt_handshake_opaque with a manually
    # constructed transcript (fn_append_transcript chains) rather than the real
    # session state, so the derived Finished verify_data does not match the
    # expected value.  BoringSSL fails earlier with [DECODE_ERROR].
    #
    # Tag: BENIGN
    "tls_process_finished_wrong_mac_ossl/": AllC(
        StatusC(OSSL, in_error="tls_process_finished:not", first_to_fail=False),
        TermContainsC(OSSL, "fn_append_transcript"),
        TermContainsC(OSSL, "fn_rsa_sign_server"),
    ),
    # BENIGN: OpenSSL (client) fails at "tls12_check_peer_sigalg:wrong
    # signature type" because the server CertificateVerify uses
    # fn_invalid_signature_algorithm — a deliberately invalid/unsupported
    # SignatureScheme value.  BoringSSL fails earlier with [DECODE_ERROR].
    # Both correctly reject the invalid signature algorithm; the difference is
    # in which check fires first.
    #
    # Tag: BENIGN
    "tls12_check_peer_sigalg_invalid_ossl/": AllC(
        StatusC(OSSL, in_error="tls12_check_peer_sigalg", first_to_fail=False),
        TermContainsC(OSSL, "fn_invalid_signature_algorithm"),
    ),
    # BENIGN: OpenSSL fails with "tls1_set_server_sigalgs:no shared signature
    # algorithms".  BoringSSL fails with [UNEXPECTED_MESSAGE] at a different
    # step.  Both reject the handshake due to algorithm incompatibility.
    #
    # Tag: BENIGN
    "tls1_set_server_sigalgs_ossl/": StatusC(
        OSSL, in_error="tls1_set_server_sigalgs:no shared", first_to_fail=False
    ),
    # BENIGN: OpenSSL (server) rejects a ClientHello extension that is present
    # but has invalid content.  Each sub-case is identified by the specific
    # extension function symbol in the last executed input step:
    #   - tls_early_post_process_client_hello: fn_early_data_indication (0-RTT
    #     early data extension with invalid content)
    #   - tls_parse_ctos_status_request: fn_status_request_extension (OCSP
    #     status request with malformed data)
    #   - tls_parse_ctos_alpn: fn_al_protocol_negotiation (ALPN list with
    #     invalid/empty protocol names)
    #   - tls_parse_ctos_supported_groups: fn_support_group_extension_make with
    #     empty or malformed group list
    # BoringSSL ignores or silently rejects these extensions, leading to
    # different failure modes.
    #
    # Tag: BENIGN
    "tls_parse_ctos_early_data_bad_ossl/": AllC(
        StatusC(
            OSSL, in_error="tls_early_post_process_client_hello", first_to_fail=False
        ),
        AnyC(
            TermContainsC(OSSL, "fn_early_data_indication"),
            TermContainsC(OSSL, "fn_early_data_extension"),
        ),
    ),
    "tls_parse_ctos_status_request_bad_ossl/": AllC(
        StatusC(
            OSSL, in_error="tls_parse_ctos_status_request:bad", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_status_request_extension"),
    ),
    "tls_parse_ctos_alpn_bad_ossl/": AllC(
        StatusC(OSSL, in_error="tls_parse_ctos_alpn:bad", first_to_fail=False),
        TermContainsC(OSSL, "fn_al_protocol_negotiation"),
    ),
    "tls_parse_ctos_supported_groups_bad_ossl/": AllC(
        StatusC(
            OSSL, in_error="tls_parse_ctos_supported_groups:bad", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_support_group_extension_make"),
    ),
    # BENIGN: OpenSSL fails while reading CA names from a CertificateRequest
    # ("parse_ca_names:ASN1 lib").  BoringSSL fails with [DECODE_ERROR].
    # Both detect a malformed CA name list.
    #
    # Tag: BENIGN
    "parse_ca_names_bad_ossl/": StatusC(
        OSSL, in_error="parse_ca_names", first_to_fail=False
    ),
    # BENIGN: OpenSSL fails with "read_state_machine:excessive message size".
    # BoringSSL fails with [DECODE_ERROR].  Both detect a record that exceeds
    # the allowed size limit.
    #
    # Tag: BENIGN
    "read_state_machine_excessive_ossl/": StatusC(
        OSSL, in_error="read_state_machine:excessive", first_to_fail=False
    ),
    # RFC: OpenSSL successfully completes a TLS 1.3 handshake while BoringSSL
    # fails with [BAD_SIGNATURE] for a CertificateVerify that uses a signing
    # function other than fn_rsa_sign_client (e.g. fn_rsa_sign_server used in a
    # client context, or a different key).  OpenSSL accepting an unverifiable
    # CertificateVerify violates RFC 8446 Section 4.4.3.
    #
    # RFC 8446 Section 4.4.3: "If the verification fails, the receiver MUST
    # terminate the handshake with a 'decrypt_error' alert."
    #
    # Tag: RFC (OpenSSL fails to enforce Section 4.4.3)
    "bad_signature_boring_other/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(BORING, in_error="BAD_SIGNATURE"),
        TermContainsC(BORING, "fn_certificate_verify"),
    ),
    # BENIGN: OpenSSL (server) receives a TLS 1.2-style encrypted message
    # (fn_encrypt12) during what should be a TLS 1.3 handshake and fails at the
    # record layer with "ssl3_read_bytes:unexpected message".  BoringSSL fails
    # with [DECODE_ERROR] because it cannot decrypt the TLS 1.2-style record.
    # Root cause: fn_encrypt12 injects a TLS 1.2-encrypted record into a
    # TLS 1.3 session.
    #
    # Tag: BENIGN
    "ssl3_unexpected_boring_decode_error/": AllC(
        StatusC(
            OSSL, in_error="ssl3_read_bytes:unexpected message", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_encrypt12"),
        StatusC(BORING, in_error="DECODE_ERROR", first_to_fail=False),
    ),
    # BENIGN: OpenSSL (client) fails with "tls13_post_process_record:data
    # remaining after message" when a TLS 1.3 record contains trailing bytes
    # after the handshake message.  The root cause is a coalesced flight
    # (fn_coalesced_flight) that appends padding or extra data.  BoringSSL
    # fails with [DECODE_ERROR] at the same record.
    #
    # Tag: BENIGN
    "tls13_post_process_record_data_ossl/": AllC(
        StatusC(OSSL, in_error="tls13_post_process_record", first_to_fail=False),
        TermContainsC(OSSL, "fn_coalesced_flight"),
    ),
    # RFC: OpenSSL (server) correctly rejects a ClientHello that is missing the
    # mandatory "signature_algorithms" extension (fn_signature_algorithm_extension
    # absent) while containing a key_share (fn_key_share_deterministic_extension).
    # BoringSSL accepts the connection and completes the handshake successfully.
    #
    # RFC 8446 Section 9.2: "If not containing a 'pre_shared_key' extension,
    # it MUST contain both a 'signature_algorithms' extension and a
    # 'supported_groups' extension.  Servers receiving a ClientHello which does
    # not conform to these requirements MUST abort the handshake with a
    # 'missing_extension' alert."
    #
    # Tag: RFC (BoringSSL violates Section 9.2 by accepting a ClientHello
    # missing the mandatory signature_algorithms extension; OpenSSL is correct)
    "final_sig_algs_missing_boring_ok/": AllC(
        StatusC(OSSL, in_error="final_sig_algs:missing", first_to_fail=False),
        # Check only the last executed input step: it must have a key_share but
        # no signature_algorithms extension — the precise missing-extension cause.
        TermContainsC(
            OSSL, "fn_key_share_deterministic_extension", last_input_executed=True
        ),
        NotC(
            TermContainsC(
                OSSL, "fn_signature_algorithm_extension", last_input_executed=True
            )
        ),
        StepC(lambda f, s, t: s == t),  # BoringSSL completed all steps (succeeded)
    ),
    # BENIGN: OpenSSL (server) fails with "final_sig_algs:missing" and
    # BoringSSL also fails (with [BAD_DECRYPT], [DECODE_ERROR], etc.).  Both
    # reject the ClientHello missing the signature_algorithms extension; the
    # difference is only in which step triggers first.
    #
    # Tag: BENIGN
    "final_sig_algs_missing_both_fail/": AllC(
        StatusC(OSSL, in_error="final_sig_algs:missing", first_to_fail=False),
        TermContainsC(
            OSSL, "fn_key_share_deterministic_extension", last_input_executed=True
        ),
        NotC(
            TermContainsC(
                OSSL, "fn_signature_algorithm_extension", last_input_executed=True
            )
        ),
    ),
    # RFC: Same root cause as final_sig_algs_missing_* above, but OpenSSL
    # reports a different internal error ("tls_early_post_process_client_hello:
    # unsupported/bad/no ...") instead of "final_sig_algs:missing".  Both
    # error paths stem from a ClientHello that contains fn_key_share_deterministic_extension
    # but lacks fn_signature_algorithm_extension in the last executed step.
    # When BoringSSL completes the handshake successfully, it is violating
    # RFC 8446 Section 9.2 (same rationale as final_sig_algs_missing_boring_ok).
    #
    # Tag: RFC (BoringSSL violates Section 9.2; OpenSSL is correct)
    "tls_early_post_process_missing_sig_alg_boring_ok/": AllC(
        StatusC(
            OSSL, in_error="tls_early_post_process_client_hello", first_to_fail=False
        ),
        TermContainsC(
            OSSL, "fn_key_share_deterministic_extension", last_input_executed=True
        ),
        NotC(
            TermContainsC(
                OSSL, "fn_signature_algorithm_extension", last_input_executed=True
            )
        ),
        StepC(lambda f, s, t: s == t),  # BoringSSL completed all steps (succeeded)
    ),
    # BENIGN: Same as above but BoringSSL also fails (does not complete all steps).
    #
    # Tag: BENIGN
    "tls_early_post_process_missing_sig_alg_both_fail/": AllC(
        StatusC(
            OSSL, in_error="tls_early_post_process_client_hello", first_to_fail=False
        ),
        TermContainsC(
            OSSL, "fn_key_share_deterministic_extension", last_input_executed=True
        ),
        NotC(
            TermContainsC(
                OSSL, "fn_signature_algorithm_extension", last_input_executed=True
            )
        ),
    ),
    # BENIGN: OpenSSL fails with "tls_get_more_records:invalid record type"
    # when it receives a TLS 1.2-style encrypted Change Cipher Spec record
    # (fn_encrypt12 wrapping fn_change_cipher_spec) during a TLS 1.3 session.
    # In TLS 1.3, CCS records sent encrypted are invalid; only unencrypted CCS
    # compatibility messages are allowed (RFC 8446 Section 5).  BoringSSL fails
    # with [DECODE_ERROR] for the same reason.
    #
    # Tag: BENIGN
    "tls_get_more_records_invalid_record_type_ossl/": AllC(
        StatusC(
            OSSL,
            in_error="tls_get_more_records:invalid record type",
            first_to_fail=False,
        ),
        # fn_encrypt12 sends a TLS 1.2-style encrypted record (invalid in TLS 1.3);
        # fn_change_cipher_spec may or may not be present depending on the flight.
        TermContainsC(OSSL, "fn_encrypt12"),
    ),
    # BENIGN: OpenSSL fails with "tls_get_more_records:packet length too long"
    # for coalesced flights that do NOT include fn_certificate_status (covered
    # by tls_get_more_records_packet_too_long_ossl above).  The oversized record
    # is caused by a large fn_encrypt_handshake_opaque flight.  BoringSSL fails
    # with [DECODE_ERROR] or [UNEXPECTED_EXTENSION].
    #
    # Tag: BENIGN
    "tls_get_more_records_packet_too_long_other_ossl/": AllC(
        StatusC(
            OSSL,
            in_error="tls_get_more_records:packet length too long",
            first_to_fail=False,
        ),
        TermContainsC(OSSL, "fn_encrypt_handshake_opaque"),
    ),
    # BENIGN: OpenSSL (server or client) fails at the record layer with
    # "ssl3_read_bytes:invalid record type" when it receives a message that
    # uses an unexpected record content type.  The trace sends an encrypted
    # TLS 1.2-style record (fn_encrypt12) or other invalid-type record during
    # a TLS 1.3 session.  BoringSSL fails with [DECODE_ERROR].
    #
    # Tag: BENIGN
    "ssl3_read_bytes_invalid_record_type_ossl/": AllC(
        StatusC(OSSL, in_error="ssl3_read_bytes:invalid", first_to_fail=False),
        AnyC(
            TermContainsC(OSSL, "fn_encrypt12"),
            TermContainsC(OSSL, "fn_alert_close_notify"),
            TermContainsC(OSSL, "fn_certificate_verify"),
            TermContainsC(OSSL, "fn_append_transcript"),
        ),
    ),
    # BENIGN: OpenSSL fails with "ssl3_read_bytes:unexpected message" and
    # BoringSSL fails with [DECODE_ERROR].  Unlike ssl3_unexpected_boring_ok
    # (where BoringSSL succeeds), here both implementations fail.  The root
    # cause is typically fn_alert_close_notify or fn_encrypt12 injected into
    # an unexpected protocol state.
    #
    # Tag: BENIGN
    "ssl3_unexpected_boring_decode_error_any/": AllC(
        StatusC(
            OSSL, in_error="ssl3_read_bytes:unexpected message", first_to_fail=False
        ),
        StatusC(BORING, in_error="DECODE_ERROR", first_to_fail=False),
    ),
    # BENIGN: OpenSSL fails with "tls12_check_peer_sigalg:wrong signature type"
    # for a CertificateVerify whose transcript is manually constructed with
    # fn_append_transcript (not using the real session state) and whose key may
    # not correspond to the certificate (e.g. fn_bob_key with fn_alice_cert).
    # BoringSSL fails with [DECODE_ERROR].  Both detect an invalid signature;
    # the difference is which layer catches it first.
    #
    # Tag: BENIGN
    "tls12_check_peer_sigalg_wrong_key_ossl/": AllC(
        StatusC(OSSL, in_error="tls12_check_peer_sigalg", first_to_fail=False),
        TermContainsC(OSSL, "fn_certificate_verify"),
        TermContainsC(OSSL, "fn_append_transcript"),
    ),
    # BENIGN: OpenSSL (client) fails with "tls_process_finished:bad" (bad
    # Finished MAC) in the same fn_append_transcript + fn_rsa_sign_server
    # pattern as tls_process_finished_wrong_mac_ossl, but a slightly different
    # transcript chain produces a "bad" rather than "not equal" error.
    #
    # Tag: BENIGN
    "tls_process_finished_bad_mac_ossl/": AllC(
        StatusC(OSSL, in_error="tls_process_finished:bad", first_to_fail=False),
        TermContainsC(OSSL, "fn_append_transcript"),
    ),
    # BENIGN: OpenSSL (server) fails while processing a TLS 1.3 encrypted
    # record header ("tls13_validate_record_header:encrypted record type in
    # wrong direction" or similar).  BoringSSL fails with [DECODE_ERROR].
    # Root cause: fn_encrypt_handshake or fn_encrypt12 sends a record whose
    # content type is not valid in the current direction.
    #
    # Tag: BENIGN
    "tls13_validate_record_header_encrypted_ossl/": AllC(
        StatusC(
            OSSL, in_error="tls13_validate_record_header:encrypted", first_to_fail=False
        ),
        AnyC(
            TermContainsC(OSSL, "fn_encrypt_handshake"),
            TermContainsC(OSSL, "fn_encrypt12"),
        ),
    ),
    # RFC: OpenSSL (client) completes the handshake while BoringSSL fails with
    # [SERVER_ECHOED_INVALID_SESSION_ID].  BoringSSL correctly detects that the
    # server echoed a session ID that does not match what the client sent.
    # OpenSSL's acceptance may indicate that it does not verify the echoed
    # legacy_session_id_echo field.
    #
    # RFC 8446 Section 4.1.3: "legacy_session_id_echo: The contents of the
    # client's legacy_session_id field.  Note that this field is echoed even
    # if the client's value corresponded to a cached pre-TLS 1.3 session which
    # the server is not attempting to resume."  A mismatch should be flagged.
    #
    # Tag: RFC (OpenSSL does not validate legacy_session_id_echo; BoringSSL
    # is correct)
    "ossl_ok_boring_invalid_session_id/": AllC(
        StatusC(BORING, in_error="SERVER_ECHOED_INVALID_SESSION_ID"),
        StepC(lambda f, s, t: f == t and s < t),
    ),
    # RFC: OpenSSL (client) completes the handshake while BoringSSL fails with
    # [ERROR_PARSING_EXTENSION] [PARSE_TLSEXT].  BoringSSL detects a malformed
    # or prohibited extension in the server's flight.  OpenSSL accepting it
    # may indicate a lax extension parser.
    #
    # Tag: RFC (BoringSSL is stricter; OpenSSL may be accepting invalid extensions)
    "ossl_ok_boring_parse_tlsext_error/": AllC(
        StatusC(BORING, in_error="PARSE_TLSEXT"),
        StepC(lambda f, s, t: f == t and s < t),
    ),
    # RFC: OpenSSL (client) completes the handshake while BoringSSL fails with
    # [DIGEST_CHECK_FAILED].  BoringSSL detects an AEAD authentication failure
    # that OpenSSL does not check or ignores.
    #
    # Tag: RFC (OpenSSL accepts data whose authentication tag fails to verify)
    "ossl_ok_boring_digest_check_failed/": AllC(
        StatusC(BORING, in_error="DIGEST_CHECK_FAILED"),
        StepC(lambda f, s, t: f == t and s < t),
    ),
    # --------------------------------------------------------------------------
    # BENIGN – Final alert-code pair differences
    # --------------------------------------------------------------------------
    # BENIGN: OpenSSL sends "protocol_version", BoringSSL sends
    # "missing_extension".  Both detect a version/extension incompatibility;
    # the specific alert code is implementation-defined.
    #
    # Tag: BENIGN
    "alert_protocol_version_ossl_vs_missing_ext_boring/": InnerKnowledgeC(
        "[Description(Different(ProtocolVersion, MissingExtension))]"
    ),
    # BENIGN: OpenSSL sends "protocol_version", BoringSSL sends "decode_error".
    # Both detect a version negotiation failure; the specific code differs.
    #
    # Tag: BENIGN
    "alert_protocol_version_ossl_vs_decode_error_boring/": InnerKnowledgeC(
        "[Description(Different(ProtocolVersion, DecodeError))]"
    ),
    # BENIGN: OpenSSL sends "unexpected_message", BoringSSL sends
    # "missing_extension".  Both abort on a protocol ordering violation; the
    # specific alert is implementation-defined.
    #
    # Tag: BENIGN
    "alert_unexpected_msg_ossl_vs_missing_ext_boring/": InnerKnowledgeC(
        "[Description(Different(UnexpectedMessage, MissingExtension))]"
    ),
    # BENIGN: OpenSSL sends "handshake_failure", BoringSSL sends
    # "missing_extension".  Both abort due to incompatible parameters; the
    # specific alert is implementation-defined.
    #
    # Tag: BENIGN
    "alert_handshake_failure_ossl_vs_missing_ext_boring/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, MissingExtension))]"
    ),
    # BENIGN: OpenSSL (server) rejects a ClientHello or extension with "missing
    # psk kex modes" and BoringSSL fails with [UNEXPECTED_MESSAGE].  Both abort
    # because the PSK exchange mode is absent; the error path differs.
    #
    # Tag: BENIGN
    "final_psk_missing_ossl/": StatusC(
        OSSL, in_error="final_psk:missing", first_to_fail=False
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
