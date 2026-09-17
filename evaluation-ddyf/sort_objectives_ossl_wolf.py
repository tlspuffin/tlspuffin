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
WOLF = 2
FIRST_PUT = "openssl340"
SECOND_PUT = "wolfssl580"
PARALLELISM = 10

buckets: dict[str, BucketCondition] = {
    # No differences reported --> flakyness
    "no_errors/": NoDiffC(),
    "tls12_no_sigalgs/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(
            OSSL,
            in_error="tls1_set_server_sigalgs:no shared signature algorithms",
        ),
    ),
    # tls 1.2 alerts are encrypted but are in unencrypted records
    "tls12_encrypted_alerts/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StepC(
            lambda a, b, _: a >= 2
        ),  # we need at least to have some encrypted messages
        InnerKnowledgeC(
            "BothAlert"
        ),
    ),
    # TLS 1.2 traces discared for now
    "tls12/": CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
    # If the first message is a handshake message with empty payload, wolf returns an error and ossl ignores it
    "empty_msg_first_step/": AllC(
        StatusC(WOLF, in_error="record layer length error"),
        TermContainsC(
            WOLF, "fn_empty_handshake_message -> OpaqueMessage", check_first_input=True
        ),
    ),
    # When receiving close notify wolfssl closes instantly while ossl returns an error after
    "close_notify/": AllC(
        StatusC(
            WOLF,
            in_error="peer sent close notify alert",
        ),
        TermContainsC(WOLF, "fn_alert_close_notify", last_input_executed=True),
    ),
    # AUDITED BY GEMINI
    "no_change_hrr/":
        # Verdict: APPROVED
        # Spec Audit: The bucket identifies a server-side error that occurs when a client violates RFC 8446, Section 4.1.4.
        # The RFC states: "Clients MUST abort the handshake with an 'illegal_parameter' alert if the HelloRetryRequest would not result in any change in the ClientHello."
        # If a client proceeds with an unmodified ClientHello, the server correctly detects this protocol violation.
        # Logic Audit: The `StatusC` condition accurately captures the OpenSSL error `tls_process_as_hello_retry_request:no change following hrr`, which is the expected server behavior when confronted with a non-compliant client. The logic is sound.
        # Tag: RFC
        StatusC(
            OSSL,
            in_error="tls_process_as_hello_retry_request:no change following hrr",
            first_executed_steps=lambda steps: steps > 0,
        ),
    # HRR as a first step : wolfssl sends its client hello anyway
    "no_change_hrr_first_step/": StatusC(
        OSSL,
        in_error="tls_process_as_hello_retry_request:no change following hrr",
        first_executed_steps=lambda steps: steps == 0,
    ),
    "no_cipher_specified/": StatusC(
        OSSL,
        in_error="ssl_cache_cipherlist:no ciphers specified",
    ),
    # when preshared_key extension contains an incorrect ticket OpenSSL rejects the CH, while WolfSSL doesn't
    # check this extension but fails at the next step using encryption because the computed keys are not the same
    "ctos_psk_bad_ext/": AllC(
        StatusC(
            OSSL,
            in_error="tls_parse_ctos_psk:bad extension",
        ),
        TermContainsC(OSSL, "fn_fill_binder", last_input_executed=True),
        AnyC(
            TermContainsC(OSSL, "fn_derive_binder", last_input_executed=True),
            TermContainsC(OSSL, "fn_derive_psk", last_input_executed=True),
        ),
    ),
    # supported group extension with no supported groups is accepted by wolf but rejected by openssl
    "ctos_supported_groups_bad_ext/": AllC(
        StatusC(
            OSSL,
            in_error="tls_parse_ctos_supported_groups:bad extension",
        ),
        TermContainsReC(
            OSSL,
            r"fn_support_group_extension_make\(\s*fn_support_group_extension_new",
            last_input_executed=True,
        ),
    ),
    # an incorrect certificate_status_request in a CH triggers OSSL server to tls_parse_ctos_status_request:bad extension
    # this extensions is ignored by wolfssl
    "ctos_status_request_bad_ext/": AllC(
        StatusC(
            OSSL,
            in_error="tls_parse_ctos_status_request:bad extension",
        ),
        TermContainsC(OSSL, "fn_status_request_extension", last_input_executed=True),
    ),
    # No psk_key_exchange_modes extensions in client hello with binder: OSSL rejects and Wolfssl replies with a ServerHello
    "missing_psk_kex_mode/": StatusC(
        OSSL,
        in_error="final_psk:missing psk kex modes extension",
    ),
    # Two consecutives change cipher spec makes wolfssl return unknown_type_in_record_hdr
    "unknown_type_in_record_hdr/": StatusC(
        WOLF,
        in_error="unknown type in record hdr",
    ),
    # WolfSSL returns an error when binder value is too big or too small eg. fn_large_bytes_vec, bob_cert, eve_signature
    "buffer_error/": AllC(
        StatusC(
            WOLF,
            in_error="Buffer error, output too small or input too big",
        ),
        TermContainsC(WOLF, "fn_fill_binder", last_input_executed=True),
    ),
    # Wolfssl seems to check certificate upon reception whereas OpenSSL check them at a later step
    "certificate_verify_failed/": StatusC(
        WOLF,
        in_error="certificate verify failed",
    ),
    # if legacy version is TLS 1.3 instead of TLS 1.2, WolfSSL returns a record layer version error while openssl do the handshake
    "record_layer_version_error/": StatusC(
        WOLF,
        in_error="record layer version error",
    ),
    "malformed_buffer/": StatusC(
        WOLF,
        in_error="malformed buffer input error",
    ),
    # putting the same valid certificate in a handshake message many times
    # (tested with 19 certs) and sending it as a encrypted extension to the server
    # when client auth is activated causes wolf to return message too long error
    "handshake_msg_too_large/": AllC(
        StatusC(
            WOLF,
            in_error="Handshake message too large Error",
        ),
        TermContainsC(WOLF, "fn_certificate13", last_input_executed=True),
    ),
    # an incorrect CCS message tiggers a client read transition error in OpenSSL
    "client_state_transition_CCS/": AllC(
        StatusC(
            OSSL,
            in_error="ossl_statem_client_read_transition",
        ),
        TermContainsC(OSSL, "fn_change_cipher_spec", last_input_executed=True),
    ),
    # use of fn_derive_binder or other functions producing vec<u8> in messages containing certificates
    "asn1_error/": AllC(
        StatusC(OSSL, in_error="asn1 encoding routines"),
        AnyC(
            TermContainsC(
                OSSL, "fn_al_protocol_server_negotiation", last_input_executed=True
            ),
            TermContainsC(OSSL, "fn_derive_binder", last_input_executed=True),
        ),
    ),
    # an incorrect CCS message tiggers a server read transition error on openssl
    "server_state_transition_CCS/": AllC(
        StatusC(
            OSSL,
            in_error="ossl_statem_server_read_transition",
        ),
        TermContainsC(OSSL, "fn_change_cipher_spec", last_input_executed=True),
    ),
    # When OSSL returns a state transition error, WolfSSL returns it at the next step
    "server_state_transition/": AllC(
        StatusC(OSSL, in_error="ossl_statem_server_read_transition"),
        StepC(lambda first, second, _: second == first + 1),
    ),
    # unclear
    "header_error/": AllC(
        StatusC(WOLF, in_error="parse error on header"),
        TermContainsC(WOLF, "fn_alert_close_notify", last_input_executed=True),
    ),
    # "unexpected_byte/": StatusC(OSSL, in_error="ssl3_read_bytes:unexpected"),
    # a CH containing (fn_al_protocol_negotiation((fn_make_payload_u8_vec_u16(fn_empty_payload_u8_vec)))) will trigger a bad_extension error on OpenSSL
    # and be ignored by wolfssl
    # likely due to the activated extension in wolfssl
    "ctos_alpn_bad_ext/": AllC(
        StatusC(OSSL, in_error="tls_parse_ctos_alpn:bad extension"),
        TermContainsC(OSSL, "fn_al_protocol_negotiation", last_input_executed=True),
    ),
    # AUDITED BY GEMINI
    "unsolicited_ext/":
        # Verdict: APPROVED
        # Spec Audit: This bucket captures a server sending an extension that the client did not request. This violates RFC 8446, Section 4.2,
        # which states: "Implementations MUST NOT send extension responses if the remote endpoint did not send the corresponding extension requests...
        # Upon receiving such an extension, an endpoint MUST abort the handshake with an 'unsupported_extension' alert."
        # Logic Audit: The logic correctly links the OpenSSL `unsolicited extension` error to specific server-sent extensions that are only valid as responses.
        # Tag: RFC
        AllC(
            StatusC(OSSL, in_error="tls_collect_extensions:unsolicited extension"),
            AnyC(
                TermContainsC(
                    OSSL, "fn_al_protocol_server_negotiation", last_input_executed=True
                ),
                TermContainsC(
                    OSSL, "fn_early_data_server_extension", last_input_executed=True
                ),
            ),
        ),
    # AUDITED BY GEMINI
    "server_hello_bad_ext/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a server sending legacy TLS 1.2 extensions in a TLS 1.3 handshake. The extensions listed
        # (e.g., `ec_point_formats`, `extended_master_secret`) are not valid in TLS 1.3 as per the table in RFC 8446, Section 4.2.
        # Sending these obsolete extensions is a protocol violation. OpenSSL correctly rejects the `ServerHello`.
        # Logic Audit: The logic correctly identifies the OpenSSL errors and correlates them with the presence of illegal legacy extensions in the ServerHello.
        # Tag: RFC
        AllC(
            AnyC(
                StatusC(OSSL, in_error="tls_process_server_hello:bad extension"),
                StatusC(OSSL, in_error="tls_collect_extensions:bad extension"),
            ),
            AnyC(
                TermContainsC(
                    OSSL, "fn_ec_point_formats_server_extension", last_input_executed=True
                ),
                TermContainsC(
                    OSSL,
                    "fn_extended_master_secret_server_extension",
                    last_input_executed=True,
                ),
                TermContainsC(
                    OSSL, "fn_renegotiation_info_server_extension", last_input_executed=True
                ),
                TermContainsC(
                    OSSL,
                    "fn_signed_certificate_timestamp_server_extension",
                    last_input_executed=True,
                ),
                TermContainsC(
                    OSSL, "fn_early_data_server_extension", last_input_executed=True
                ),
            ),
        ),
    "ossl_finished/": DifferentClaimC(
        in_first_type="tlspuffin::claims::Finished", in_second_type="()"
    ),
    "wolf_finished/": DifferentClaimC(
        in_first_type="()", in_second_type="tlspuffin::claims::Finished"
    ),
    # a fn_hello_request message triggers Sanity Check on message order
    "message_order_error_wolf/": AllC(
        StatusC(WOLF, in_error="Sanity Check on message order"),
        TermContainsC(WOLF, "fn_hello_request", last_input_executed=True),
    ),
    # handshake message with empty payloads cause length error with wolf
    "length_wolf/": AllC(
        StatusC(WOLF, in_error="length error"),
        TermContainsC(WOLF, "fn_empty_handshake_message", last_input_executed=True),
    ),
    # AUDITED BY GEMINI
    "ch_changing_cipher_after_hrr/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a client changing its offered `cipher_suites` in the second `ClientHello` after a `HelloRetryRequest`.
        # This violates RFC 8446, Section 4.1.2, which strictly defines the limited set of modifications a client is allowed to make.
        # Changing the cipher suites is not a permitted modification. OpenSSL correctly rejects this non-compliant ClientHello.
        # Logic Audit: The logic correctly identifies the OpenSSL error and confirms the scenario involves a second ClientHello,
        # while WolfSSL proceeds, thus capturing the divergent and non-compliant behavior.
        # Tag: RFC
        AllC(
            StatusC(
                OSSL, "tls_early_post_process_client_hello:bad cipher", first_to_fail=False
            ),
            KnowledgeContainsC(WOLF, "ServerHelloPayload"),
            TermContainsReC(
                OSSL,
                r"fn_client_hello\(\s*",
                last_input_executed=True,
            ),
        ),
    # AUDITED BY GEMINI
    "hrr_changing_cipher/":
        # Verdict: APPROVED
        # Spec Audit: This scenario violates RFC 8446, Section 4.1.4. The RFC states that a client
        # "MUST check that the cipher suite supplied in the ServerHello is the same as that in the HelloRetryRequest and otherwise abort the handshake with an 'illegal_parameter' alert."
        # This bucket identifies a case where the server changes the cipher suite after an HRR.
        # Logic Audit: The logic correctly combines the expected client error from OpenSSL (`wrong cipher returned`)
        # with the downstream crypto failure from WolfSSL (`AES-GCM Authentication check fail`) to precisely identify this invalid handshake.
        # Tag: RFC
        AllC(
            StatusC(
                WOLF, in_error="AES-GCM Authentication check fail", first_to_fail=False
            ),
            StatusC(
                OSSL, "set_client_ciphersuite:wrong cipher returned", first_to_fail=False
            ),
            TermContainsC(OSSL, "fn_hello_retry_request_random"),
            TermContainsReC(
                OSSL,
                r"fn_server_hello\(\s*",
                last_input_executed=True,
            ),
        ),
    # AUDITED BY GEMINI
    "keyshare_not_requested_hrr/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a client violation of RFC 8446, Section 4.1.2.
        # The RFC states that after a HelloRetryRequest, the client's new `key_share` extension MUST contain a `KeyShareEntry` from the group indicated by the server.
        # Sending a key share for a different, unrequested group is a protocol violation.
        # Logic Audit: The logic correctly identifies the scenario by checking for the specific OpenSSL error (`bad key share`),
        # ensuring it happens after at least one handshake round, and confirming it's in response to a ClientHello.
        # Tag: RFC
        AllC(
            StatusC(OSSL, "tls_parse_ctos_key_share:bad key share"),
            StepC(lambda put1, put2, _: put2 >= put1 + 2),
            TermContainsReC(
                OSSL,
                r"fn_client_hello\(\s*",
                last_input_executed=True,
            ),
        ),
    # Group in KeyShare is not used in SupportedGroup extension : OpenSSL returns an error and WolfSSL sends a HRR
    "bad_key_share/": StatusC(
        OSSL,
        in_error="tls_parse_ctos_key_share:bad key share",
    ),
    # seems to be related to encryption with bad fn_seq number
    "aes_auth_fail/": StatusC(WOLF, in_error="AES-GCM Authentication check fail"),
    # traces with a cert or key in the ticket in CH, wolfssl returns an error while openssl sends a serverhello
    "session_ticket_size_err/": StatusC(
        WOLF, in_error="Bad session ticket message Size Error"
    ),
    # AUDITED BY GEMINI
    "no_supported_groups_in_ch/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a client sending a `key_share` extension without the corresponding `supported_groups` extension.
        # RFC 8446, Section 4.1.1, describes cryptographic negotiation as the client offering a `"supported_groups" ... extension which indicates
        # the (EC)DHE groups which the client supports and a "key_share" ... extension which contains (EC)DHE shares for some or all of these groups.`
        # A `key_share` without `supported_groups` is invalid. OpenSSL correctly rejects this. WolfSSL incorrectly proceeds.
        # Logic Audit: The logic correctly pairs the OpenSSL error with the fact that WolfSSL proceeds to a `ServerHelloPayload`, precisely identifying the divergent behavior.
        # Tag: RFC
        AllC(
            StatusC(OSSL, in_error="missing supported groups"),
            KnowledgeContainsC(WOLF, "ServerHelloPayload"),
        ),
    # AUDITED BY GEMINI
    "no_sigalgs_in_cert_request/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a `CertificateRequest` message sent without the mandatory `signature_algorithms` extension.
        # RFC 8446, Section 4.3.2, states: "The 'signature_algorithms' extension MUST be specified".
        # OpenSSL correctly rejects this malformed message. The bucket implies WolfSSL accepts it, which is an RFC violation.
        # Logic Audit: The logic precisely captures the OpenSSL error in the context of a `CertificateRequest` message. The logic is sound.
        # Tag: RFC
        AllC(
            StatusC(OSSL, in_error="missing sigalgs"),
            TermContainsC(OSSL, "fn_certificate_request13", last_input_executed=True),
        ),
    # Different ways for the server to choose ciphers (client vs server prefs)
    "different_ciphers/": InnerKnowledgeC(
        "BothHandshake([Payload(BothServerHello([CipherSuite(Different(TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384))]))])"
    ),
    # here binder is computed using derive binder (but its value is incorrect)
    # or there is a fn_preshared_keys_extension_empty_binder extension
    # so the binder format is right but not its value
    "wolf_binder/": AllC(
        StatusC(WOLF, in_error="binder does not verify"),
        AnyC(
            TermContainsC(WOLF, "fn_derive_binder", last_input_executed=True),
            TermContainsC(
                WOLF,
                "fn_preshared_keys_extension_empty_binder",
                last_input_executed=True,
            ),
        ),
    ),
    # here binder value is computed using fn_derive_psk function
    "ossl_binder/": AllC(
        StatusC(OSSL, in_error="binder does not verify"),
        TermContainsC(OSSL, "fn_derive_psk", last_input_executed=True),
    ),
    # AUDITED BY GEMINI
    "no_suitable_keyshare/":
        # Verdict: APPROVED
        # Spec Audit: This bucket captures a negotiation failure where the server can find no common (EC)DHE group with the client.
        # Per RFC 8446, Section 4.1.1, if there is no overlap in supported groups, the server "MUST abort the handshake".
        # The observed "no suitable key share" error is the internal state leading to this correct, compliant abort.
        # Logic Audit: The `StatusC` condition correctly identifies the OpenSSL error for this negotiation failure.
        # Tag: BENIGN
        StatusC(
            OSSL, in_error="final_key_share:no suitable key share"
        ),
    # AUDITED BY GEMINI
    "no_shared_cipher/":
        # Verdict: APPROVED
        # Spec Audit: This bucket captures a negotiation failure where the server can find no common cipher suite with the client. Per RFC 8446, Section 4.1.1,
        # if there is no overlap in parameters, the server "MUST abort the handshake". This error is the internal state leading to this correct, compliant abort.
        # Logic Audit: The `StatusC` condition correctly identifies the OpenSSL error for this negotiation failure.
        # Tag: BENIGN
        StatusC(
            OSSL, in_error="tls_post_process_client_hello:no shared cipher"
        ),
    # a HRR with a Cipher A followed by a ServerHello with a Cipher B causes OSSL to return a wrong cipher error
    # while Wolf ignores this change
    "wrong_cipher/": StatusC(
        OSSL, in_error="set_client_ciphersuite:wrong cipher returned"
    ),
    # AUDITED BY GEMINI
    "encrypted_out_of_order/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies an implementation failing to send a required alert. When a fatal error like an out-of-order handshake message
        # is detected, RFC 8446 requires the implementation to send an `unexpected_message` alert (Section 6). The bucket logic implies one implementation
        # logs a fatal error internally but fails to send the alert to the peer.
        # Logic Audit: The logic correctly combines the internal error status from both implementations with a `KnowledgeDiffC` check to confirm
        # one peer did not generate a `MessagePayload` (the alert). This accurately pinpoints the silent-failure bug.
        # Tag: RFC
        AllC(
            KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
            StatusC(WOLF, in_error="Out of order message, fatal", first_to_fail=False),
            StatusC(
                OSSL,
                "ossl_statem_client_read_transition:unexpected message",
                first_to_fail=False,
            ),
            TermContainsReC(
                OSSL,
                r"fn_encrypt_handshake\(\s*",
                last_input_executed=True,
            ),
        ),
    # AUDITED BY GEMINI
    "duplicate_ext_sh/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a ServerHello with a duplicate extension, violating RFC 8446, Section 4.2, which states
        # "There MUST NOT be more than one extension of the same type in a given extension block." It also captures the subsequent failure
        # of the receiving implementation (WolfSSL) to send a required fatal alert (e.g., `illegal_parameter`) before closing the connection.
        # Logic Audit: The logic soundly combines status errors from both PUTs with a `KnowledgeDiffC` to confirm that one of them failed to generate an alert.
        # Tag: RFC
        AllC(
            KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
            StatusC(WOLF, in_error="error in PUT : Duplicate TLS extension in message."),
            StatusC(OSSL, "tls_collect_extensions:bad extension"),
            TermContainsReC(
                OSSL,
                r"fn_server_hello\(\s*",
                last_input_executed=True,
            ),
        ),
    # race condition
    "alert_illegal_param_vs_proto_version/": InnerKnowledgeC(
        "BothAlert([Description(Different(IllegalParameter, ProtocolVersion))])"
    ),
    # race condition
    "alert_handshake_failure_missing_ext/": InnerKnowledgeC(
        "BothAlert([Description(Different(HandshakeFailure, MissingExtension))])"
    ),
    # race condition
    "alert_illegal_param_unexpected_msg/": InnerKnowledgeC(
        "BothAlert([Description(Different(IllegalParameter, UnexpectedMessage))])"
    ),
    # race condition
    "alert_illegal_param_decode_err/": InnerKnowledgeC(
        "BothAlert([Description(Different(IllegalParameter, DecodeError))])"
    ),
    # race condition
    "alert_decrypt_handshake_failure/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecryptError, HandshakeFailure))])"
    ),
    # AUDITED BY GEMINI
    "alert_unsupported_ext_illegal_param_server_psk/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a client's response to an unsolicited `pre_shared_key` extension from a server. Per RFC 8446, Section 4.2,
        # a server MUST NOT send an extension that was not requested. The required client response is an `unsupported_extension` alert.
        # The implementation that sends `illegal_parameter` is non-compliant.
        # Logic Audit: The logic correctly combines the alert divergence with the `preshared_keys_server_extension` context.
        # Tag: RFC
        AllC(
            InnerKnowledgeC(
                "BothAlert([Description(Different(UnsupportedExtension, IllegalParameter))])"
            ),
            TermContainsC(
                WOLF,
                "fn_preshared_keys_server_extension",
                last_input_executed=True,
            ),
        ),
    # AUDITED BY GEMINI
    "alert_unsupported_ext_illegal_param_sh_status_request/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a response to a `status_request` extension in a ServerHello. Per RFC 8446, Section 4.2, this extension
        # is not valid in a ServerHello. The RFC requires that a recognized but misplaced extension MUST be rejected with an `illegal_parameter` alert.
        # The implementation that sends `unsupported_extension` is non-compliant.
        # Logic Audit: The logic correctly combines the alert divergence with the `status_request_server_extension` context.
        # Tag: RFC
        AllC(
            InnerKnowledgeC(
                "BothAlert([Description(Different(UnsupportedExtension, IllegalParameter))])"
            ),
            TermContainsC(
                OSSL,
                "fn_status_request_server_extension",
                last_input_executed=True,
            ),
        ),
    # race condition
    "alert_unsupported_ext_illegal_param/": InnerKnowledgeC(
        "BothAlert([Description(Different(UnsupportedExtension, IllegalParameter))])"
    ),
    # AUDITED BY GEMINI
    "alert_missing_ext_handshake_failure/":
        # Verdict: APPROVED
        # Spec Audit: This bucket describes a `ClientHello` with `key_share` but no `supported_groups`. The `supported_groups` extension is contextually
        # mandatory to validate the `key_share`. Per RFC 8446, Section 9.2, `missing_extension` is the appropriate alert for a missing mandatory
        # extension. The generic `handshake_failure` is less specific and therefore less compliant.
        # Logic Audit: The `InnerKnowledgeC` precisely captures the alert divergence for this protocol violation.
        # Tag: RFC
        InnerKnowledgeC(
            "BothAlert([Description(Different(MissingExtension, HandshakeFailure))])"
        ),
    # AUDITED BY GEMINI
    "alert_missing_ext_illegal_param_no_supported_groups/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a race condition in error checking. The client sends a ClientHello with two distinct errors: a missing `supported_groups`
        # extension and a `key_share` for an unsupported group. One implementation flags the missing extension (`MissingExtension`), while the other flags the
        # bad key share (`IllegalParameter`). Both are valid, fatal errors. The RFC does not mandate a specific order for these checks, making this a benign divergence.
        # Logic Audit: The logic correctly identifies the alert divergence in the context of this dual-error scenario.
        # Tag: BENIGN
        AllC(
            InnerKnowledgeC(
                "BothAlert([Description(Different(MissingExtension, IllegalParameter))])"
            ),
            TermContainsC(
                WOLF,
                "fn_named_group_x25519",
                last_input_executed=True,
            ),
        ),
    # AUDITED BY GEMINI
    "alert_missing_ext_illegal_param_binder/":
        # Verdict: APPROVED
        # Spec Audit: This bucket describes a `ClientHello` offering a `pre_shared_key` extension but omitting the mandatory `psk_key_exchange_modes` extension.
        # RFC 8446, Section 4.2.9, requires servers to abort the handshake. The most appropriate alert is `missing_extension`. The use of the more
        # generic `illegal_parameter` is less compliant.
        # Logic Audit: The logic correctly identifies the alert divergence in a PSK context (`fn_fill_binder`).
        # Tag: RFC
        AllC(
            InnerKnowledgeC(
                "BothAlert([Description(Different(MissingExtension, IllegalParameter))])"
            ),
            TermContainsC(
                WOLF,
                "fn_fill_binder",
                last_input_executed=True,
            ),
        ),
    "alert_missing_ext_illegal_param/": InnerKnowledgeC(
        "BothAlert([Description(Different(MissingExtension, IllegalParameter))])"
    ),
    # AUDITED BY GEMINI
    "alert_illegal_param_missing_ext_no_cipher/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a race condition in error checking. The client sends a `ClientHello` with two distinct errors: a missing mandatory
        # extension and an empty cipher suite list. One implementation flags the missing extension (`MissingExtension`), while the other flags the invalid
        # cipher suite list (`IllegalParameter`). Both are valid, fatal errors. The RFC does not mandate a specific order for these checks. This is a benign divergence.
        # Logic Audit: The logic correctly identifies the alert divergence and links it to the creation of an empty cipher suite list.
        # Tag: BENIGN
        AllC(
            InnerKnowledgeC(
                "BothAlert([Description(Different(IllegalParameter, MissingExtension))])"
            ),
            TermContainsReC(
                OSSL,
                r"fn_cipher_suites_make\(\s*fn_new_cipher_suites",
                last_input_executed=True,
            ),
        ),
    # race condition: Missing signature algorithm extension and using a keyshare not advertised in the supported group extension
    # AUDITED BY GEMINI
    "alert_illegal_param_missing_ext/":
        # Verdict: APPROVED
        # Spec Audit: Benign race condition. The ClientHello has multiple distinct errors (e.g., missing a mandatory extension, providing an invalid field).
        # One implementation flags the missing extension (`MissingExtension`), while another flags the invalid field (`IllegalParameter`).
        # Both are valid, fatal errors, and the RFC does not mandate a specific order for these checks. This is a permissible divergence.
        # Logic Audit: The logic correctly captures the alert divergence.
        # Tag: BENIGN
        InnerKnowledgeC(
            "BothAlert([Description(Different(IllegalParameter, MissingExtension))])"
        ),
    # AUDITED BY GEMINI
    "alert_illegalparameter_handshakefailure/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a scenario where OpenSSL sends an `illegal_parameter` alert while WolfSSL sends `handshake_failure`.
        # The scenario, as described in the original comment, involves a server (fuzzer) offering an invalid cipher suite. Per RFC 8446, Section 6,
        # `illegal_parameter` is for fields that are "incorrect or inconsistent", while `handshake_failure` is for a failure "to negotiate an acceptable set of security parameters".
        # Sending an invalid suite is a protocol field error, making `illegal_parameter` the more accurate alert. WolfSSL's choice is therefore less compliant.
        # Logic Audit: The `InnerKnowledgeC` perfectly captures the divergent alert behavior, making the bucket's logic sound and precise.
        # Tag: RFC
        InnerKnowledgeC(
            "BothAlert([Description(Different(IllegalParameter, HandshakeFailure))])"
        ),
    # race condition: empty supported group extension (catched by ossl) + other error catched by wolf
    "alert_decodeerror_handshakefailure/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecodeError, HandshakeFailure))])"
    ),
    # race condition: missing sigalgs (catched by wolf) and empty supported_group (catched by ossl)
    "alert_decodeerror_missingextension/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecodeError, MissingExtension))])"
    ),
    # race condition: tls1.3 as legacy version (catched by ossl) + other protocol error (catched by wolf)
    "alert_handshakefailure_protocolversion/": InnerKnowledgeC(
        "BothAlert([Description(Different(HandshakeFailure, ProtocolVersion))])"
    ),
    # race condition: seems that message too long to be processed by wolf
    "alert_missingextension_decodeerror/": InnerKnowledgeC(
        "BothAlert([Description(Different(MissingExtension, DecodeError))])"
    ),
    # AUDITED BY GEMINI
    "alert_unexpectedmessage_badrecordmac/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a race condition when a plaintext record is received where an encrypted one is expected.
        # An implementation may fail at the record layer (unable to deprotect, sending `BadRecordMac`) or at the message layer (plaintext is
        # inappropriate, sending `UnexpectedMessage`). Both are valid responses. This is a benign divergence.
        # Logic Audit: The `InnerKnowledgeC` correctly captures the alert divergence.
        # Tag: BENIGN
        InnerKnowledgeC(
            "BothAlert([Description(Different(UnexpectedMessage, BadRecordMac))])"
        ),
    # AUDITED BY GEMINI
    "alert_protocolversion_decodeerror/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a race condition when a client sends an ambiguous `ClientHello` (e.g., missing `supported_versions`). A server may fail
        # immediately on version negotiation (`protocol_version`), or it may attempt to parse the message as TLS 1.2 and fail on an invalid extension format (`decode_error`).
        # Both are compliant failure paths depending on implementation strategy.
        # Logic Audit: The `InnerKnowledgeC` correctly captures the alert divergence.
        # Tag: BENIGN
        InnerKnowledgeC(
            "BothAlert([Description(Different(ProtocolVersion, DecodeError))])"
        ),
    # AUDITED BY GEMINI
    "alert_decodeerror_protocolversion/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a race condition in error checking. The `ClientHello` contains two distinct errors (e.g., missing `supported_versions`
        # and another malformed extension). One implementation fails on the malformed extension (`decode_error`), while the other fails on the versioning
        # issue (`protocol_version`). Both are compliant failure paths.
        # Logic Audit: The logic correctly captures the alert divergence.
        # Tag: BENIGN
        InnerKnowledgeC(
            "BothAlert([Description(Different(DecodeError, ProtocolVersion))])"
        ),
    # AUDITED BY GEMINI
    "alert_handshakefailure_decodeerror/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a race condition in error checking. The `ServerHello` contains two distinct errors (a malformed extension and an
        # unsupported cipher suite selection). One implementation fails on the malformed extension (`decode_error`), while the other fails on the negotiation
        # failure (`handshake_failure`). Both are compliant failure paths.
        # Logic Audit: The logic correctly captures the alert divergence.
        # Tag: BENIGN
        InnerKnowledgeC(
            "BothAlert([Description(Different(HandshakeFailure, DecodeError))])"
        ),
    # AUDITED BY GEMINI
    "alert_decodeerror_illegalparameter/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a divergence in alerts for a malformed KeyShare extension. Per RFC 8446, Section 6, `decode_error`
        # is for messages that "do not conform to the formal protocol syntax". `illegal_parameter` is for messages that are syntactically correct but
        # semantically invalid. A malformed extension is a syntax error. OpenSSL correctly sends `decode_error`; WolfSSL's use of `illegal_parameter` is an RFC violation.
        # Logic Audit: The `InnerKnowledgeC` precisely captures this alert divergence. The logic is sound.
        # Tag: RFC
        InnerKnowledgeC(
            "BothAlert([Description(Different(DecodeError, IllegalParameter))])"
        ),
    # AUDITED BY GEMINI
    "alert_unexpectedmessage_illegalparameter/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a divergence in alerts for an out-of-place ChangeCipherSpec (CCS) message. Per RFC 8446, Section 6,
        # `unexpected_message` is for "An inappropriate message". A second, redundant CCS message fits this definition.
        # `illegal_parameter` is for invalid fields within a message, not a misplaced message. The implementation sending `illegal_parameter` is non-compliant.
        # Logic Audit: The `InnerKnowledgeC` precisely captures this alert divergence. The logic is sound.
        # Tag: RFC
        InnerKnowledgeC(
            "BothAlert([Description(Different(UnexpectedMessage, IllegalParameter))])"
        ),
    # race concition : bad cipher (catched by ossl) other error (catched by wolf)
    "alert_handshakefailure_illegalparameter/": InnerKnowledgeC(
        "BothAlert([Description(Different(HandshakeFailure, IllegalParameter))])"
    ),
    # AUDITED BY GEMINI
    "alert_decrypterror_illegalparameter/":
        # Verdict: APPROVED
        # Spec Audit: This bucket describes a PSK binder verification failure. Per RFC 8446, Section 6, the `decrypt_error` alert is explicitly
        # for handshake cryptographic failures, including failing to "validate a ... PSK binder". The use of `illegal_parameter` is incorrect.
        # Logic Audit: The logic correctly captures the alert divergence in what the original comment identifies as a binder-related scenario.
        # Tag: RFC
        InnerKnowledgeC(
            "BothAlert([Description(Different(DecryptError, IllegalParameter))])"
        ),
    # AUDITED BY GEMINI
    "alert_missingextension_protocolversion/":
        # Verdict: APPROVED
        # Spec Audit: This bucket describes a `HelloRetryRequest` missing the mandatory `supported_versions` extension (a violation of RFC 8446, Section 4.1.4).
        # The correct response is to identify this specific error, making `missing_extension` the most accurate alert. The `protocol_version` alert arises from
        # a less precise interpretation of the malformed message. The implementation sending `missing_extension` is more compliant.
        # Logic Audit: The logic correctly captures the alert divergence in this scenario.
        # Tag: RFC
        InnerKnowledgeC(
            "BothAlert([Description(Different(MissingExtension, ProtocolVersion))])"
        ),
    # AUDITED BY GEMINI
    "alert_unsupportedextension_protocolversion/":
        # Verdict: APPROVED
        # Spec Audit: This bucket identifies a race condition in error checking. The client sends a `ClientHello` with two distinct errors: a missing `supported_versions`
        # extension and another unsupported extension. One implementation flags the unsupported extension (`UnsupportedExtension`), while the other flags the
        # version negotiation failure (`ProtocolVersion`). Both are valid, fatal errors. The RFC does not mandate a specific order for these checks. This is a benign divergence.
        # Logic Audit: The logic correctly captures the alert divergence for this dual-error scenario.
        # Tag: BENIGN
        InnerKnowledgeC(
            "BothAlert([Description(Different(UnsupportedExtension, ProtocolVersion))])"
        ),
    # race condition: big coalesced message and missing SH, openssl can't parse and wolf spot missing SH
    "alert_recordoverflow_unexpectedmessage/": InnerKnowledgeC(
        "BothAlert([Description(Different(RecordOverflow, UnexpectedMessage))])"
    ),
    # binder related
    "alert_decrypterror_protocolversion/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecryptError, ProtocolVersion))])"
    ),
    # race condition : unsupported extension + other error. wolf does not support the extension and ignores it but catch another error
    "alert_unsupportedextension_handshakefailure/": InnerKnowledgeC(
        "BothAlert([Description(Different(UnsupportedExtension, HandshakeFailure))])"
    ),
    # TODO
    "alert_unexpectedmessage_decodeerror/": InnerKnowledgeC(
        "BothAlert([Description(Different(UnexpectedMessage, DecodeError))])"
    ),
    # TODO
    "alert_recordoverflow_protocolversion/": InnerKnowledgeC(
        "BothAlert([Description(Different(RecordOverflow, ProtocolVersion))])"
    ),
    # TODO
    "alert_decrypterror_missingextension/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecryptError, MissingExtension))])"
    ),
    # TODO
    "alert_unsupportedextension_unexpectedmessage/": InnerKnowledgeC(
        "BothAlert([Description(Different(UnsupportedExtension, UnexpectedMessage))])"
    ),
    # TODO
    "alert_unexpectedmessage_protocolversion/": InnerKnowledgeC(
        "BothAlert([Description(Different(UnexpectedMessage, ProtocolVersion))])"
    ),
    # TODO
    "alert_decodeerror_unexpectedmessage/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecodeError, UnexpectedMessage))])"
    ),
    # TODO
    "alert_missingextension_unexpectedmessage/": InnerKnowledgeC(
        "BothAlert([Description(Different(MissingExtension, UnexpectedMessage))])"
    ),
    # catch potential vulnerability patterns
    "cve/": AllC(
        KnowledgeContainsC(WOLF, "Finished"),
        NotC(KnowledgeContainsC(OSSL, "Finished")),
        ClaimContainsC(WOLF, r".*master_secret: \[[1-9][0-9]*,.*"),
        NotC(ClaimContainsC(OSSL, r".*master_secret: \[[1-9][0-9]*,.*")),
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
