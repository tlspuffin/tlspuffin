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
PARALLELISM = 10

buckets: dict[str, BucketCondition] = {
    # [UNCLASSIFIED] OpenSSL 3.4.0 rejects unexpected alert(close_notify) messages in TLS 1.3
    "tls13_alert_close_notify_unexpected_message_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(OSSL, in_error="unexpected message", first_executed_steps=None),
        TermContainsC(OSSL, "fn_alert_close_notify", last_input_executed=True),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 rejects ChangeCipherSpec messages out of order in TLS 1.3
    "tls13_change_cipher_spec_unexpected_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(OSSL, in_error="unexpected message", first_to_fail=True),
        TermContainsC(OSSL, "fn_change_cipher_spec", last_input_executed=True),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 fails on ChangeCipherSpec with unexpected state in TLS 1.2
    "tls12_change_cipher_spec_unexpected_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="unexpected message", first_to_fail=True),
        TermContainsC(OSSL, "fn_change_cipher_spec", last_input_executed=True),
    ),
    # [UNCLASSIFIED] LibreSSL 4.2.1 rejects HelloRequest messages in TLS 1.3
    "tls13_hello_request_unexpected_libressl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(LIBRE, in_error="unexpected message", first_to_fail=True),
        TermContainsC(LIBRE, "fn_hello_request", last_input_executed=True),
    ),
    # [UNCLASSIFIED] TLS 1.3 knowledge diff: IllegalParameter vs DecodeError in ClientHello
    "tls13_knowledge_diff_illegal_parameter_decode_error/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("Different(IllegalParameter, DecodeError)"),
    ),
    # [UNCLASSIFIED] TLS 1.3 claim diff: OpenSSL vs LibreSSL Finished message claims
    "tls13_finished_message_claim_diff/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        DifferentClaimC(in_first_type="()", in_second_type="tlspuffin::claims::Finished"),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 TLS 1.2 record layer failure with 'records not released'
    "tls12_record_layer_failure_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="records not released", first_to_fail=True),
        TermContainsC(OSSL, "fn_alert", last_input_executed=True),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 TLS 1.3 record layer failure with 'records not released'
    "tls13_record_layer_failure_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(OSSL, in_error="records not released", first_to_fail=True),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 rejects ServerHello with unsafe legacy renegotiation flag in TLS 1.2
    "tls12_server_hello_renegotiation_unsafe_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="unsafe legacy renegotiation", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [UNCLASSIFIED] TLS 1.3 knowledge diff: IllegalParameter vs ProtocolVersion
    "tls13_knowledge_diff_illegal_parameter_protocol_version/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("Different(IllegalParameter, ProtocolVersion)"),
    ),
    # [UNCLASSIFIED] TLS 1.3 knowledge diff: HandshakeFailure vs MissingExtension
    "tls13_knowledge_diff_handshake_failure_missing_extension/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("Different(HandshakeFailure, MissingExtension)"),
    ),
    # [UNCLASSIFIED] TLS 1.2 knowledge diff: DecodeError vs HandshakeFailure
    "tls12_knowledge_diff_decode_error_handshake_failure/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        InnerKnowledgeC("HandshakeFailure"),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 rejects TLS 1.2 ClientHello with unsupported signature algorithms at the extension level
    "tls12_signature_algorithm_mismatch_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="no shared signature algorithms", first_to_fail=True),
        TermContainsC(OSSL, "fn_fill_binder", last_input_executed=True),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 rejects ServerHello messages with unsafe legacy renegotiation flag in TLS 1.2
    "tls12_renegotiation_error_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="unsafe legacy renegotiation", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 fails when ServerHello selects a TLS 1.3 cipher suite in a TLS 1.2 context
    "tls12_cipher_mismatch_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="wrong cipher", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 fails when processing ClientHello with no ciphers enabled for the negotiated TLS version
    "tls13_cipher_list_error_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(OSSL, in_error="no ciphers", first_to_fail=True),
    ),
    # [UNCLASSIFIED] OpenSSL 3.4.0 fails with 'records not released' error during encrypted record processing in TLS 1.3
    "tls13_record_failure_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(OSSL, in_error="records not released", first_to_fail=True),
        TermContainsC(OSSL, "fn_change_cipher_spec", last_input_executed=True),
    ),
    # [UNCLASSIFIED] Knowledge differences in TLS 1.3 where OpenSSL reports IllegalParameter but LibreSSL reports DecodeError
    "tls13_illegal_parameter_decode_error_knowledge_diff/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("Different(IllegalParameter, DecodeError)"),
    ),
    # [UNCLASSIFIED] LibreSSL 4.2.1 rejects ClientHello messages missing required extensions in TLS 1.3
    "tls13_missing_extension_error_libressl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(LIBRE, in_error="illegal parameter", first_to_fail=True),
        TermContainsC(LIBRE, "fn_client_hello", last_input_executed=True),
    ),
    # [UNCLASSIFIED] LibreSSL 4.2.1 fails with 'tlsv1 alert protocol version' error when processing ClientHello or other messages
    "tls13_protocol_version_error_libressl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(LIBRE, in_error="protocol version", first_to_fail=True),
    ),
    # [UNCLASSIFIED] Knowledge differences in TLS 1.3 where OpenSSL reports DecodeError but LibreSSL reports ProtocolVersion error
    "tls13_knowledge_diff_decode_protocol_version/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("ProtocolVersion"),
    ),
    # [UNCLASSIFIED] Knowledge differences in TLS 1.2 where OpenSSL and LibreSSL report different alert descriptions
    "tls12_knowledge_diff_record_overflow_unknown_ca/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        InnerKnowledgeC("RecordOverflow"),
    ),
    # [UNCLASSIFIED] Claim differences in TLS 1.2 where OpenSSL produces no Finished claims but LibreSSL emits Finished claims
    "tls12_finished_claim_diff_empty_vs_nonempty/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        DifferentClaimC(in_first_type="()", in_second_type="tlspuffin::claims::Finished"),
    ),
    # [UNCLASSIFIED] Knowledge differences in TLS 1.3 where OpenSSL reports IllegalParameter but LibreSSL reports InternalError
    "tls13_knowledge_diff_illegal_parameter_internal_error/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("InternalError"),
    ),
    # [UNCLASSIFIED] Knowledge differences in TLS 1.3 where OpenSSL reports MissingExtension but LibreSSL reports IllegalParameter
    "tls13_knowledge_diff_missing_extension_illegal_parameter/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("MissingExtension"),
    ),
    # [UNCLASSIFIED] Knowledge differences in TLS 1.2 where OpenSSL reports UnexpectedMessage but LibreSSL reports IllegalParameter
    "tls12_knowledge_diff_unexpected_message_illegal_parameter/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        InnerKnowledgeC("UnexpectedMessage"),
    ),
    # [Round 3] TLS 1.3 knowledge differences: Inner knowledge of RustLS alert messages
    "tls3_knowledge_knowledges/": InnerKnowledgeC("Inner[tlspuffin::tls::rustls::msgs::aler"),
    # [Round 3] TLS 1.2 claim differences: Empty vs Finished claims
    "tls2_claim_finished/": DifferentClaimC(in_first_type="()", in_second_type="tlspuffin::claims::Finished"),
    # [Round 3] TLS 1.3 OpenSSL status: decrypt_handshake_flight failure
    "tls3_status_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(OSSL, in_error="error", first_to_fail=True),
        TermContainsC(OSSL, "fn_decrypt_handshake_flight", last_input_executed=True),
    ),
    # [Round 3] TLS 1.2 OpenSSL status: server_hello failure
    "tls2_status_ossl/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="error", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [Round 3] TLS 1.2 knowledge differences: Inner knowledge of RustLS alert messages
    "tls2_knowledge_knowledges/": InnerKnowledgeC("Inner[tlspuffin::tls::rustls::msgs::aler"),
    # [Round 3] TLS 1.2 LibreSSL status: empty_handshake_message failure
    "tls2_status_libre/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(LIBRE, in_error="error", first_to_fail=True),
        TermContainsC(LIBRE, "fn_empty_handshake_message -> OpaqueMessage", last_input_executed=True),
    ),
    # [Round 3] TLS 1.3 LibreSSL status: encrypt_handshake failure
    "tls3_status_libre/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(LIBRE, in_error="error", first_to_fail=True),
        TermContainsC(LIBRE, "fn_encrypt_handshake", last_input_executed=True),
    ),
    # [Round 4] TLS 1.2 knowledge diff: IllegalParameter vs DecodeError
    "tls12_knowledge_diff_illegal_parameter_decode_error_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        InnerKnowledgeC("Different(IllegalParameter, DecodeError)"),
    ),
    # [Round 4] TLS 1.3 knowledge diff: HandshakeFailure vs IllegalParameter
    "tls13_knowledge_diff_handshake_failure_illegal_parameter_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("Different(HandshakeFailure, IllegalParameter)"),
    ),
    # [Round 4] TLS 1.3 knowledge diff: HandshakeFailure vs DecodeError
    "tls13_knowledge_diff_handshake_failure_decode_error_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("Different(HandshakeFailure, DecodeError)"),
    ),
    # [Round 4] TLS 1.2 OpenSSL status: signature algorithm mismatch
    "tls12_status_signature_algorithm_mismatch_ossl_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="no suitable signature algorithm", first_to_fail=True),
    ),
    # [Round 4] TLS 1.3 knowledge diff: Alert vs Handshake payload
    "tls13_knowledge_diff_alert_vs_handshake_payload_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload", "tlspuffin::tls::rustls::msgs::handshake::HandshakeMessagePayload"),
    ),
    # [Round 4] TLS 1.3 LibreSSL status: unsupported protocol
    "tls13_status_unsupported_protocol_libressl_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(LIBRE, in_error="unexpected message", first_to_fail=True),
    ),
    # [Round 4] TLS 1.2 OpenSSL status: alert close notify
    "tls12_status_alert_close_notify_ossl_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="unexpected message", first_to_fail=True),
        TermContainsC(OSSL, "fn_alert_close_notify", last_input_executed=True),
    ),
    # [Round 4] TLS 1.2 OpenSSL status: records not released
    "tls12_status_records_not_released_ossl_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(OSSL, in_error="records not released", first_to_fail=True),
    ),
    # [Round 4] TLS 1.2 knowledge diff: UnsupportedExtension vs UnrecognisedName
    "tls12_both_knowledge_diff_unsupported_extension_unrecognised_name_round4/": AllC(
        InnerKnowledgeC("Different(UnsupportedExtension, UnrecognisedName)"),
    ),
    # [Round 4] TLS 1.2 LibreSSL status: hello request
    "tls12_status_hello_request_libressl_round4/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        StatusC(LIBRE, in_error="unexpected message", first_to_fail=True),
        TermContainsC(LIBRE, "fn_hello_request", last_input_executed=True),
    ),
    # [Round 5] TLS 1.3 knowledge
    "tls__knowledge_round5_B044/": CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
    # [Round 5] TLS 1.2 knowledge
    "tls__knowledge_round5_B045/": CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
    # [Round 5] TLS 1.2 knowledge
    "tls__knowledge_round5_B046/": CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
    # [Round 5] OpenSSL status: final_renegotiate error
    "tlst_status_ossl_0a000152:ssl_routine_round5_B047/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        StatusC(OSSL, in_error="0A000152:SSL routines:final_renegotiate:", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [Round 5] OpenSSL status: final_renegotiate error
    "tlst_status_ossl_0a000152:ssl_routine_round5_B048/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        StatusC(OSSL, in_error="0A000152:SSL routines:final_renegotiate:", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [Round 5] TLS 1.3 knowledge
    "tls__knowledge_round5_B049/": CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
    # [Round 5] OpenSSL status: tls_read_record error
    "tlst_status_ossl_0a000141:ssl_routine_round5_B050/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        StatusC(OSSL, in_error="0A000141:SSL routines:tls_read_record:re", first_to_fail=True),
    ),
    # [Round 5] TLS 1.2 knowledge diff: IllegalParameter vs ProtocolVersion
    "tls__knowledge_diff_illegalparameter_protocolversion_round5_B051/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        InnerKnowledgeC("IllegalParameter, ProtocolVersion"),
    ),
    # [Round 5] TLS 1.3 knowledge diff: UnsupportedExtension vs IllegalParameter
    "tls__knowledge_diff_unsupportedextension_illegalparameter_round5_B052/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("UnsupportedExtension, IllegalParameter"),
    ),
    # [Round 5] TLS 1.2 knowledge diff: UnsupportedExtension vs IllegalParameter
    "tls__knowledge_diff_unsupportedextension_illegalparameter_round5_B053/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        InnerKnowledgeC("UnsupportedExtension, IllegalParameter"),
    ),
    # [Round 5] TLS 1.2 knowledge diff: UnsupportedExtension vs DecodeError
    "tls__knowledge_diff_unsupportedextension_decodeerror_round5_B054/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        InnerKnowledgeC("UnsupportedExtension, DecodeError"),
    ),
    # [Round 5] Knowledge diff: IllegalParameter vs ProtocolVersion
    "tlst_knowledge_diff_illegalparameter_protocolversion_round5_B055/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        InnerKnowledgeC("IllegalParameter, ProtocolVersion"),
    ),
    # [Round 5] TLS 1.2 knowledge
    "tls__knowledge_round5_B056/": CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
    # [Round 5] TLS 1.3 knowledge diff: IllegalParameter vs HandshakeFailure
    "tls__knowledge_diff_illegalparameter_handshakefailure_round5_B057/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        InnerKnowledgeC("IllegalParameter, HandshakeFailure"),
    ),
    # [Round 5] TLS 1.3 knowledge
    "tls__knowledge_round5_B058/": CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
    # [Round 5] TLS 1.2 knowledge diff: UnsupportedExtension vs ProtocolVersion
    "tls__knowledge_diff_unsupportedextension_protocolversion_round5_B059/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_2"),
        InnerKnowledgeC("UnsupportedExtension, ProtocolVersion"),
    ),
    # [Round 5] LibreSSL status: tls_early_post_pro error
    "tls__status_libre_0a000102:ssl_routine_round5_B060/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(LIBRE, in_error="0A000102:SSL routines:tls_early_post_pro", first_to_fail=True),
        TermContainsC(LIBRE, "fn_fill_binder", last_input_executed=True),
    ),
    # [Round 6] OpenSSL status: unexpected message on change_cipher_spec
    "both_status_ossl_change_cipher_spec_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        StatusC(OSSL, in_error="unexpected message", first_to_fail=True),
        TermContainsC(OSSL, "fn_change_cipher_spec", last_input_executed=True),
    ),
    # [Round 6] OpenSSL status: wrong cipher returned
    "both_status_ossl_wrong_cipher_returned_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        StatusC(OSSL, in_error="wrong cipher", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [Round 6] OpenSSL status: bad length in server_hello
    "both_status_ossl_bad_length_server_hello_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        StatusC(OSSL, in_error="bad length", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [Round 6] OpenSSL status: bad extension in server_hello
    "both_status_ossl_bad_extension_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        StatusC(OSSL, in_error="bad extension", first_to_fail=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),
    # [Round 6] LibreSSL status: unexpected message
    "both_status_libressl_unexpected_message_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        StatusC(LIBRE, in_error="unexpected message", first_to_fail=True),
    ),
    # [Round 6] Knowledge diff: UnsupportedExtension vs IllegalParameter
    "both_knowledge_diff_unsupported_extension_illegal_parameter_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        InnerKnowledgeC("UnsupportedExtension, IllegalParameter"),
    ),
    # [Round 6] Knowledge diff: IllegalParameter vs DecodeError
    "both_knowledge_diff_illegal_parameter_decode_error_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        InnerKnowledgeC("IllegalParameter, DecodeError"),
    ),
    # [Round 6] Knowledge diff: UnsupportedExtension vs ProtocolVersion
    "both_knowledge_diff_unsupported_extension_protocol_version_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        InnerKnowledgeC("UnsupportedExtension, ProtocolVersion"),
    ),
    # [Round 6] Claim diff: LibreSSL TranscriptServerHello
    "both_knowledge_diff_claims_transcript_round6/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "Both"),
        ClaimContainsC(LIBRE, "TranscriptServerHello"),
    ),
    # No differences reported --> flakyness
    "no_errors/": NoDiffC(),
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
