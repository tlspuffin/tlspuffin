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
