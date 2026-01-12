import sys
from DDYF.diff_analyzer import (
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
    # Hello Retry Request where wolf sends two identical ClientHello
    "no_change_hrr/": StatusC(
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
    # fn_al_protocol_server_negotiation extension in serverhello or fn_early_data_server_extension in encrypted extensions returns unsolicited extension with openssl
    "unsolicited_ext/": AllC(
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
    # any of fn_ec_point_formats_server_extension,
    # fn_extended_master_secret_server_extension,
    # fn_renegotiation_info_server_extension,
    # fn_signed_certificate_timestamp_server_extension in serverhello will trigger the
    # error on ossl side
    # likely due to the activated extension in wolfssl
    "server_hello_bad_ext/": AllC(
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
    # hrr with changing cipher
    "hrr_changing_cipher/": AllC(
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
    # use a keyshare not requested in HRR
    "keyshare_not_requested_hrr/": AllC(
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
    # wolf can respond to a client hello without a supported group list if the CH contains a keyshare
    "no_supported_groups_in_ch/": AllC(
        StatusC(OSSL, in_error="missing supported groups"),
        KnowledgeContainsC(WOLF, "ServerHelloPayload"),
    ),
    # missing sigalgs extension in certificate request make openssl return an error and not wolf
    "no_sigalgs_in_cert_request/": AllC(
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
    # TODO
    "no_suitable_keyshare/": StatusC(
        OSSL, in_error="final_key_share:no suitable key share"
    ),
    # TODO
    "no_shared_cipher/": StatusC(
        OSSL, in_error="tls_post_process_client_hello:no shared cipher"
    ),
    # a HRR with a Cipher A followed by a ServerHello with a Cipher B causes OSSL to return a wrong cipher error
    # while Wolf ignores this change
    "wrong_cipher/": StatusC(
        OSSL, in_error="set_client_ciphersuite:wrong cipher returned"
    ),
    # encrypted out of order message triggers no alert for wolfssl
    "encrypted_out_of_order/": AllC(
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
    # duplicate extension in SH cause wolf to abord without alert message
    "duplicate_ext_sh/": AllC(
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
    # RFC violation
    "alert_unsupported_ext_illegal_param_server_psk/": AllC(
        InnerKnowledgeC(
            "BothAlert([Description(Different(UnsupportedExtension, IllegalParameter))])"
        ),
        TermContainsC(
            WOLF,
            "fn_preshared_keys_server_extension",
            last_input_executed=True,
        ),
    ),
    # race condition
    "alert_unsupported_ext_illegal_param/": InnerKnowledgeC(
        "BothAlert([Description(Different(UnsupportedExtension, IllegalParameter))])"
    ),
    # ClientHello without SupportedGroup but with KeyShare --> RFC violation for wolfSSL
    "alert_missing_ext_handshake_failure/": InnerKnowledgeC(
        "BothAlert([Description(Different(MissingExtension, HandshakeFailure))])"
    ),
    # missing supported groups with unsupported group keyshare --> ossl rejects because missing supported group, wolf rejects because invalid keyshare
    # race condition
    "alert_missing_ext_illegal_param_no_supported_groups/": AllC(
        InnerKnowledgeC(
            "BothAlert([Description(Different(MissingExtension, IllegalParameter))])"
        ),
        TermContainsC(
            WOLF,
            "fn_named_group_x25519",
            last_input_executed=True,
        ),
    ),
    # binder stuff
    "alert_missing_ext_illegal_param_binder/": AllC(
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
    # missing extension + missing ciphersuite in clienthello leading to error race conditions
    "alert_illegal_param_missing_ext_no_cipher/": AllC(
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
    "alert_illegal_param_missing_ext/": InnerKnowledgeC(
        "BothAlert([Description(Different(IllegalParameter, MissingExtension))])"
    ),
    # server attacker responds to a client with an invalid ciphersuite, OSSL responds with IllegalParameter while wolf responds with Handshake failure
    # according to RFC 8446 section 6.2 :
    # illegal_parameter:  A field in the handshake was incorrect or inconsistent with other fields.  This alert is used for errors which conform to the formal protocol syntax but are otherwise incorrect.
    # and
    # handshake_failure:  Receipt of a "handshake_failure" alert message indicates that the sender was unable to negotiate an acceptable set of security parameters given the options available.
    # So wolfssl is wrong
    "alert_illegalparameter_handshakefailure/": InnerKnowledgeC(
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
    # TODO
    "alert_unexpectedmessage_badrecordmac/": InnerKnowledgeC(
        "BothAlert([Description(Different(UnexpectedMessage, BadRecordMac))])"
    ),
    # race condition: tls1.3 as legacy version (catched by ossl) + other protocol error (catched by wolf)
    "alert_protocolversion_decodeerror/": InnerKnowledgeC(
        "BothAlert([Description(Different(ProtocolVersion, DecodeError))])"
    ),
    # race condition: missing supported_version extension (catched by wolf) + malformed extension (catched by ossl)
    "alert_decodeerror_protocolversion/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecodeError, ProtocolVersion))])"
    ),
    # race condition: malformed extension in SH (catched by wolf) + use of an unsupported cipher (catched by ossl)
    "alert_handshakefailure_decodeerror/": InnerKnowledgeC(
        "BothAlert([Description(Different(HandshakeFailure, DecodeError))])"
    ),
    # Malformed KeyShare extension : ossl returns DecodeError while wolf send IllegalParameter
    # malformed messages should trigger Decode error -> RFC violation for wolf
    "alert_decodeerror_illegalparameter/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecodeError, IllegalParameter))])"
    ),
    # two CCS, wolf returns illegal_parameter which is invalid -> tested with wolf 5.8.4 got unexpectedmessage
    "alert_unexpectedmessage_illegalparameter/": InnerKnowledgeC(
        "BothAlert([Description(Different(UnexpectedMessage, IllegalParameter))])"
    ),
    # race concition : bad cipher (catched by ossl) other error (catched by wolf)
    "alert_handshakefailure_illegalparameter/": InnerKnowledgeC(
        "BothAlert([Description(Different(HandshakeFailure, IllegalParameter))])"
    ),
    # related to binder
    "alert_decrypterror_illegalparameter/": InnerKnowledgeC(
        "BothAlert([Description(Different(DecryptError, IllegalParameter))])"
    ),
    # missing supported_version in HRR, OSSL catches the missing extension while wolf tries to interpret the message as a TLS 1.2 SH
    # both alert seems valid. TODO investigate
    "alert_missingextension_protocolversion/": InnerKnowledgeC(
        "BothAlert([Description(Different(MissingExtension, ProtocolVersion))])"
    ),
    # race conditon: missing supported_version + unsupported extension
    "alert_unsupportedextension_protocolversion/": InnerKnowledgeC(
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
