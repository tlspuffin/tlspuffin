import os
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
# Overridable so that a campaign run against another wolfSSL version (the CVE
# campaigns of Claim 1 use wolfssl510) can be triaged with the same buckets.
FIRST_PUT = os.environ.get("DDYF_FIRST_PUT", "openssl340")
SECOND_PUT = os.environ.get("DDYF_SECOND_PUT", "wolfssl580")
PARALLELISM = int(os.environ.get("DDYF_PARALLELISM", "8"))

buckets: dict[str, BucketCondition] = {

    # BENIGN: No TLS differential observed — all claims and knowledge are identical
    # across both PUTs. Residual execution-status-only differentials (where both PUTs
    # fail with unrelated errors but produce identical TLS knowledge) may remain;
    # these are accepted as BENIGN noise.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — NoDiffC() is the correct zero-diff
    #   catch-all. Placed first; any trace with no observable difference lands here.
    #   Single condition with a well-defined semantics; no ambiguity in classification.
    "no_errors/": NoDiffC(),

    # --------------------------------------------------------------------------
    # RFC — Specific multi-condition buckets (adapted from ossl-boringssl campaign)
    # --------------------------------------------------------------------------
    # RFC: OpenSSL accepts HelloRequest in TLS 1.3 while wolfssl aborts with
    # "Sanity Check on message order Error" (wolfssl's unexpected_message
    # equivalent).  RFC 8446 Section 9.1: servers MUST NOT send HelloRequest.
    #
    # Tag: RFC (OpenSSL incorrectly accepts a HelloRequest in TLS 1.3)
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — StepC(f==t) requires OSSL to run to
    #   completion without failing (f==t semantics: OSSL never fails; cf. s==t for
    #   wolfssl-ok in tls12_renegotiation_info_wolf_ok). Combined with wolfssl
    #   fn_hello_request TermContainsC and the wolfssl Sanity-Check StatusC, this
    #   ensures only genuine RFC 8446 §9.1 acceptance traces survive (OSSL accepts
    #   the HelloRequest; wolfssl correctly rejects it). Prior StepC(f>s) was
    #   tightened from C4 fail to C4 pass.
    # AUDITED [Audit 1 Pass 4]: C1 ✓ / C2 ✓ / C3 ✓ / C4 unchecked (0 traces) —
    #   StepC(f==t) fix confirmed correct (OSSL-completion constraint); 4-condition AllC
    #   is root-cause-grounded; no overlap with tls12_renegotiation_info_wolf_ok.
    # Bug report: BUGS/RFC000_ossl_hello_request_tls13.md
    # NOTE (Audit 2 open action, resolved 2026-06-04): 0 traces in the 418,300-trace
    #   campaign snapshot (2026-06-01); removal condition was met at campaign close.
    #   Removal moot — live objective/ has since accumulated 48,741 traces; bucket
    #   condition is validated and kept for future campaigns.
    "tls13_hello_request/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        TermContainsC(WOLF, "fn_hello_request"),
        StatusC(WOLF, in_error="Sanity Check on message order Error"),
        StepC(lambda f, s, t: f == t),
    ),

    # RFC: TLS 1.2 renegotiation_info — wolfssl succeeds while OpenSSL aborts
    # because it has legacy renegotiation disabled.
    # RFC 5746 requires both peers to support the renegotiation_info extension
    # before renegotiating; wolfssl proceeding without it violates this.
    #
    # Tag: RFC (wolfssl violates RFC 5746 by completing renegotiation)
    # Bug report: BUGS/RFC001_wolfssl_renegotiation_info.md
    # AUDITED: Gate 3 FAIL — wolfssl server Finished present in only 16/4,945
    #          traces; master_secret=[0,0,...] in all wolfssl server Finished
    #          samples. No key material derived. [RFC] CVSS 0.0 confirmed.
    "tls12_renegotiation_info_wolf_ok/": AllC(
        StatusC(
            OSSL,
            in_error="final_renegotiate:unsafe legacy renegotiation disabled",
        ),
        StepC(lambda f, s, t: s == t),
    ),

    # BENIGN: OSSL detects a missing renegotiation_info extension and aborts.
    # wolfssl's behavior in this scenario varies — sampled traces show wolfssl
    # failing for unrelated reasons (Buffer error, unknown type in record hdr,
    # Out of order message, Malformed binder), not because wolfssl detects the
    # renegotiation_info absence. The bucket captures exactly what the OSSL
    # StatusC says: OSSL rejects unsafe legacy renegotiation; wolfssl behavior
    # is unconstrained and forms a heterogeneous mix irrelevant to the OSSL side.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ (specific OSSL renegotiation error function:reason); C2 ✓
    #   (single root-cause-grounded OSSL StatusC; wolfssl side intentionally
    #   unconstrained — the bucket describes OSSL's detection only, not a joint
    #   "both fail" pattern); C3 ✓ (no overlap with tls12_renegotiation_info_wolf_ok
    #   which requires StepC(s==t), i.e. wolfssl completes); C4 — deferred (wolfssl
    #   heterogeneity is by design; OSSL error string is single root cause).
    # AUDITED [Audit 1 Pass 4]: C1 ✓ / C2 ✓ / C3 ✓ / C4 unchecked (0 traces) —
    #   specific function:reason string; wolfssl side unconstrained by design;
    #   discriminated from tls12_renegotiation_info_wolf_ok by ordering.
    # NOTE (ADV-2, 2026-06-04): "0 traces" in Pass 4 comment is stale — live corpus
    #   has ~109K traces. Condition and classification remain correct.
    "final_renegotiate_ossl_detects/": StatusC(
        OSSL, in_error="final_renegotiate:unsafe legacy renegotiation disabled"
    ),

    # RFC: missing_extension in key_share context.
    # OpenSSL sends illegal_parameter; wolfssl sends missing_extension.
    #
    # Tag: RFC (OpenSSL uses wrong alert for missing key_share — RFC 8446 §9.2
    # requires missing_extension for absent mandatory extension)
    # Bug report: BUGS/RFC002_ossl_wrong_alert_missing_ext.md
    # AUDITED: Gate 1 FAIL — 0 Finished claims in 5 traces; both PUTs send alert
    #          and abort (alert-code differential only, no completed handshake).
    #          [RFC] CVSS 0.0 confirmed. No VULN potential.
    "alert_illegal_param_ossl_vs_missing_ext_key_share/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, MissingExtension))]"),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
        NotC(TermContainsC(OSSL, "fn_key_share", last_input_executed=True)),
    ),

    # RFC: missing_extension in supported_groups context.
    # OpenSSL sends illegal_parameter; wolfssl sends missing_extension.
    # RFC 8446 §9.2: missing mandatory extension should be missing_extension.
    #
    # Tag: RFC
    # Bug report: BUGS/RFC002_ossl_wrong_alert_missing_ext.md
    # AUDITED: Gate 1 FAIL — 0 Finished claims in 4,046 traces; both PUTs send
    #          alert and abort. Alert-code differential only.
    #          [RFC] CVSS 0.0 confirmed.
    "alert_illegal_param_ossl_vs_missing_ext_supported_groups/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, MissingExtension))]"),
        TermContainsC(OSSL, "fn_client_hello", last_input_executed=True),
        NotC(
            TermContainsC(
                OSSL, "fn_support_group_extension", last_input_executed=True
            )
        ),
    ),

    # BENIGN: catch-all for remaining IllegalParameter vs MissingExtension
    # alert-pair differences not captured by the specific key_share or
    # supported_groups sub-buckets above.
    #
    # Tag: BENIGN (implementation-defined alert code choice; both parties reject)
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair
    #   (IllegalParameter vs MissingExtension) in InnerKnowledgeC exact string match;
    #   single root cause (different alert code choice for same RFC §9.2 condition).
    # C8-CATCHALL investigated (2026-06-04): 20-trace sample confirmed BENIGN. Extension
    #   symbols (fn_support_group_extension, fn_key_share_extension) are present in trace
    #   terms — not absent. Alerts triggered by malformed content (bad ecpoint, no ciphers
    #   specified, bad key share), not by missing mandatory §9.2 extensions. 0 Finished
    #   claims in all 20 samples (Gate 1 FAIL). No new [RFC] sub-bucket warranted.
    "alert_illegal_param_ossl_vs_missing_ext_wolf/": InnerKnowledgeC(
        "[Description(Different(IllegalParameter, MissingExtension))]"
    ),

    # RFC: wolfssl sends handshake_failure for missing extension instead of
    # missing_extension as required by RFC 8446 §9.2.
    #
    # Tag: RFC (wolfssl uses wrong alert code)
    # Reported: wolfssl/wolfssl#9521 (closed) — RFC 8446 violation: wolfssl returns
    #   handshake_failure instead of missing_extension when ClientHello lacks SupportedGroups.
    # AUDITED: Gate 1 FAIL — 0 Finished claims in 4,171 traces; both PUTs abort.
    #          Alert-code differential only. [RFC] CVSS 0.0 confirmed.
    "alert_missing_ext_ossl_vs_handshake_failure_wolf/": InnerKnowledgeC(
        "[Description(Different(MissingExtension, HandshakeFailure))]"
    ),

    # RFC: wolfssl sends illegal_parameter instead of RFC-mandated unsupported_extension.
    # RFC 8446 §4.2: "If a client receives a ServerHello extension not first offered in
    # its ClientHello, it MUST abort the handshake with an unsupported_extension alert."
    # OpenSSL correctly sends unsupported_extension; wolfssl sends illegal_parameter.
    #
    # Tag: RFC (wolfssl violates RFC 8446 §4.2 — wrong alert for unsolicited extension)
    # Reported: wolfssl/wolfssl#9503 (closed) — no separate bug report; upstream covers this.
    # AUDITED: Gate 1 FAIL — 0 Finished claims; both PUTs abort. [RFC] CVSS 0.0 confirmed.
    # Reclassified 2026-06-04: BENIGN → [RFC] per benign_reclassification_report_2026-06-04.md
    # AUDIT 5 (2026-06-05): AUDITED — 40/40 sampled OSSL errors are
    #   "tls_collect_extensions:unsolicited extension" → unsupported_extension is RFC-correct
    #   (§4.2); wolfSSL illegal_parameter is wrong; matches upstream #9503. 364 Finished but
    #   0 with authenticate_peer:true AND non-zero master_secret — VULN check PASS.
    "alert_unsupported_ext_ossl_vs_illegal_param_wolf/": InnerKnowledgeC(
        "[Description(Different(UnsupportedExtension, IllegalParameter))]"
    ),

    # ===================================================================
    # SPLIT 2026-06-24 of the former monolithic bucket
    #   "alert_illegal_param_ossl_vs_unsupported_ext_wolf/"
    #   InnerKnowledgeC("[Description(Different(IllegalParameter, UnsupportedExtension))]")
    # (603 traces). The Audit-5 "direction holds" verdict (2026-06-05) was
    # built on a MISREAD of the OpenSSL error string and is CORRECTED here.
    #
    # Source-confirmed root cause (vendor/openssl340-asan/.../ssl/statem/extensions.c):
    #   * line 655  SSLfatal(SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_EXTENSION)
    #               fires when verify_extension() -> validate_context() FAILS, i.e.
    #               a *recognised* extension appears in a message where it is not
    #               allowed (wrong message). String: "tls_collect_extensions:bad extension".
    #   * line 687  SSLfatal(SSL_AD_UNSUPPORTED_EXTENSION, SSL_R_UNSOLICITED_EXTENSION)
    #               is a SEPARATE branch for a context-valid but un-offered extension.
    #               String: "tls_collect_extensions:unsolicited extension".
    # "bad extension" is therefore the WRONG-MESSAGE path, NOT the unsolicited path.
    # RFC 8446 §4.2: "If an implementation receives an extension which it recognizes
    # and which is not specified for the message in which it appears, it MUST abort
    # the handshake with an illegal_parameter alert." => OpenSSL's illegal_parameter
    # is RFC-CORRECT; wolfSSL's unsupported_extension is the VIOLATION. The old
    # "OpenSSL violates / RFC005" attribution was backwards and is withdrawn.
    #
    # Full-bucket OSSL error distribution (603/603 co-located metadata logs):
    #   468  tls_collect_extensions:bad extension       -> RFC (wolfSSL wrong alert)
    #   135  tls_process_server_hello:invalid session id-> BENIGN race (distinct root causes)
    # The 135 are a validation-ORDERING race: OSSL aborts on the §4.1.3 session-id
    # check (illegal_parameter, correct for ITS trigger) before reaching extension
    # collection, while wolfSSL aborts on the extension. Two different defects -> BENIGN.
    # -------------------------------------------------------------------

    # RFC: wolfSSL sends unsupported_extension where RFC 8446 §4.2 mandates
    # illegal_parameter for a recognised extension carried in the wrong message
    # (e.g. server_name placed in ServerHello). OpenSSL correctly sends
    # illegal_parameter (extensions.c:655, validate_context fail). wolfSSL is wrong.
    #
    # Tag: RFC (wolfSSL violates RFC 8446 §4.2 — wrong alert for wrong-message extension)
    # AUDIT: Gate 1 FAIL — 0 Finished claims; both PUTs (clients) abort. [RFC] CVSS 0.0.
    # C2: root-cause-grounded via StatusC on the OSSL wrong-message error site.
    # C4: single OSSL error function (tls_collect_extensions) across the subset.
    # PENDING REVIEW
    "alert_illegal_param_ossl_vs_unsupported_ext_wolf_bad_extension/": AllC(
        InnerKnowledgeC(
            "[Description(Different(IllegalParameter, UnsupportedExtension))]"
        ),
        StatusC(
            OSSL,
            in_error="tls_collect_extensions:bad extension",
            first_to_fail=False,
        ),
    ),

    # BENIGN: validation-ordering race. OpenSSL aborts on the legacy_session_id_echo
    # check (RFC 8446 §4.1.3, tls_process_server_hello:invalid session id,
    # illegal_parameter — correct for that trigger) before extension collection,
    # while wolfSSL aborts on the offending extension (unsupported_extension). The
    # alert pair is an artefact of which check each client runs first, not a single
    # joint root cause. Two distinct defects in one trace -> not an RFC finding.
    #
    # Tag: BENIGN (race condition; distinct root causes per PUT)
    # AUDIT: Gate 1 FAIL — 0 Finished claims; both clients abort. CVSS 0.0.
    # C2: root-cause-grounded via StatusC on the OSSL session-id error site.
    # PENDING REVIEW
    "alert_illegal_param_ossl_vs_unsupported_ext_wolf_invalid_session_id/": AllC(
        InnerKnowledgeC(
            "[Description(Different(IllegalParameter, UnsupportedExtension))]"
        ),
        StatusC(
            OSSL,
            in_error="tls_process_server_hello:invalid session id",
            first_to_fail=False,
        ),
    ),
    # NOTE: a residual "_other" catch-all (NotC bad_extension AND NotC invalid_session_id)
    # was created during the 2026-06-24 split but captured 0/603 traces — the two sites
    # above partition the bucket exactly — so it was removed per the no-empty-buckets rule.

    # RFC: wolfssl sends decode_error instead of RFC-mandated illegal_parameter for
    # HelloRetryRequest random detection. RFC 8446 §4.1.3: "If a client receives a
    # second ServerHello in the same connection and the ServerHello.random value is
    # the special HelloRetryRequest value, the client MUST abort the handshake with
    # an illegal_parameter alert." OpenSSL correctly sends illegal_parameter;
    # wolfssl sends decode_error.
    #
    # Tag: BENIGN (illegal_parameter vs decode_error; HRR magic appears in terms but is not
    #   the alert trigger — heterogeneous cipher/extension errors)
    # AUDIT 5b (2026-06-05): REVISION NEEDED → RESOLVED by REVERT to BENIGN (2026-06-10).
    #   Audit 5b correctly flagged the Audit-5 "AUDITED" as an error (mixed-role bucket).
    #   Orchestrator evaluated the split option and REJECTED it: even the 5,075 client-role
    #   subset is NOT a clean §4.1.3 finding. Full-bucket OSSL error distribution for
    #   client-role traces is dominated by cipher/session/extension errors —
    #   "ssl_cache_cipherlist:no ciphers specified" (1239), "set_client_ciphersuite:wrong
    #   cipher returned" (1227), "tls_process_server_hello:invalid session id" (935),
    #   "tls_collect_extensions:bad extension" (925) — and the §4.1.3 magic-random→
    #   illegal_parameter check does NOT appear (closest: tls_process_as_hello_retry_request
    #   "no change following hrr" (241, §4.1.4, different rule); tls_parse_stoc_key_share
    #   "bad key share" (32, §4.2.8)). OSSL's illegal_parameter is NOT §4.1.3-driven anywhere
    #   in this bucket; a role split would manufacture a bogus RFC sub-bucket. The
    #   fn_hello_retry_request_random term only means the magic value appears in the trace
    #   terms, not that it triggers the alert. Bug report RFC009 WITHDRAWN. VULN check PASS.
    # PENDING REVIEW
    "alert_illegal_param_ossl_vs_decode_error_hrr_random/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_hello_retry_request_random", last_input_executed=True),
    ),

    # BENIGN: Empty cipher suites list triggers illegal_parameter vs decode_error.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (InnerKnowledgeC +
    #   TermContainsC fn_new_cipher_suites + NotC fn_append_cipher_suite); all
    #   conditions root-cause-grounded for empty cipher suites scenario.
    "alert_illegal_param_ossl_vs_decode_error_empty_ciphers/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_new_cipher_suites", last_input_executed=True),
        NotC(
            TermContainsC(
                OSSL, "fn_append_cipher_suite", last_input_executed=True
            )
        ),
    ),

    # BENIGN: TLS 1.3 version field mixed with TLS 1.2 cipher suite.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (InnerKnowledgeC +
    #   TermContainsC fn_protocol_version13 + TermContainsC fn_cipher_suite12);
    #   root-cause-grounded for TLS 1.3 version + TLS 1.2 cipher mismatch.
    "alert_illegal_param_ossl_vs_decode_error_version_mismatch/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_protocol_version13", last_input_executed=True),
        TermContainsC(OSSL, "fn_cipher_suite12", last_input_executed=True),
    ),

    # BENIGN: Weak/export cipher suite triggers illegal_parameter vs decode_error.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (InnerKnowledgeC +
    #   TermContainsC fn_weak_export_cipher_suite); root-cause-grounded.
    "alert_illegal_param_ossl_vs_decode_error_weak_cipher/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_weak_export_cipher_suite", last_input_executed=True),
    ),

    # RFC: OpenSSL sends illegal_parameter instead of RFC-mandated decode_error for
    # duplicate extensions. RFC 8446 §4.2: "If there are multiple occurrences of a
    # known extension, MUST abort the handshake with a decode_error alert."
    # wolfssl correctly sends decode_error; OpenSSL sends illegal_parameter.
    #
    # Tag: BENIGN (illegal_parameter vs decode_error; mixed triggers, no single RFC violation)
    # AUDIT 5 (2026-06-05): REVISION NEEDED → RESOLVED by REVERT to BENIGN (2026-06-05).
    #   The 2026-06-04 reclassification to [RFC]/RFC004 was over-eager. Orchestrator
    #   re-verified the full bucket: OSSL errors are heterogeneous — "tls_collect_extensions:
    #   bad extension" (36) + "tls_process_server_hello:bad extension" (30) +
    #   "set_client_ciphersuite:wrong cipher returned" (29) + "invalid session id" (20).
    #   ~43% are wrong-cipher/invalid-session-id, NOT duplicate extensions; the condition
    #   (fn_server_extensions_append + fn_server_hello) does not isolate a duplicated
    #   extension. The §4.2 "duplicate → decode_error" claim does not hold for the bucket as
    #   defined; for the wrong-cipher plurality OSSL's illegal_parameter is defensible.
    #   Bug report RFC004 WITHDRAWN. VULN check PASS (0 authenticated Finished).
    # AUDITED (Audit 5b, 2026-06-05): revert to BENIGN CONFIRMED independently. Full bucket
    #   n=115 reproduced: bad extension 36 + tls_process_server_hello:bad extension 30 +
    #   wrong cipher 29 + invalid session id 20 (~43% non-duplicate). §4.2 does not govern. OK.
    "alert_illegal_param_ossl_vs_decode_error_duplicate_ext/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        TermContainsC(OSSL, "fn_server_extensions_append", last_input_executed=True),
        TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
    ),

    # BENIGN: Remaining illegal_parameter vs decode_error cases not matched above.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition InnerKnowledgeC +
    #   five NotC exclusions; residual catch-all for remaining IllegalParameter vs
    #   DecodeError cases after 5 sub-buckets above are carved off; conditions
    #   correct and non-overlapping.
    "alert_illegal_param_ossl_vs_decode_error_other/": AllC(
        InnerKnowledgeC("[Description(Different(IllegalParameter, DecodeError))]"),
        NotC(
            TermContainsC(
                OSSL, "fn_hello_retry_request_random", last_input_executed=True
            )
        ),
        NotC(TermContainsC(OSSL, "fn_new_cipher_suites", last_input_executed=True)),
        NotC(
            AllC(
                TermContainsC(
                    OSSL, "fn_protocol_version13", last_input_executed=True
                ),
                TermContainsC(OSSL, "fn_cipher_suite12", last_input_executed=True),
            )
        ),
        NotC(
            TermContainsC(
                OSSL, "fn_weak_export_cipher_suite", last_input_executed=True
            )
        ),
        NotC(
            AllC(
                TermContainsC(
                    OSSL, "fn_server_extensions_append", last_input_executed=True
                ),
                TermContainsC(OSSL, "fn_server_hello", last_input_executed=True),
            )
        ),
    ),

    # BENIGN: bad CertificateVerify signature — wolfssl fails with "certificate
    # verify failed"; OSSL also rejects (record-layer decryption error after
    # aborting the handshake). Both PUTs correctly enforce RFC 8446 §4.4.3.
    # The differential is error-string format only, not acceptance vs rejection.
    #
    # Tag: BENIGN (differential error reporting; both PUTs reject the bad signature)
    # Phase 3 Security Gate: all 5 gates PASS (no bypass). See audit_2_verdict.md §7.
    # OSSL also rejects — "decryption failed or bad record mac" at step 2/6 is a
    #   record-layer failure after OSSL aborts, not evidence of acceptance.
    # Note: authenticate_peer:false in OSSL Finished claims is an instrumentation
    #   artifact — fill_claim() in ssl_lib.c never sets claim->peer_authentication;
    #   the field stays 0. The OSSL Finished claim is the outbound ServerFinished
    #   emitted BEFORE the client CertificateVerify flight is received.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC: CheckAgentC
    #   TLS_1_3 + StatusC(WOLF, "certificate verify failed") + three TermContainsC
    #   (fn_find_server_certificate_request, fn_certificate_verify, fn_rsa_sign_client).
    #   All conditions root-cause-grounded; each TermContainsC names a specific
    #   function in the wolfssl CertificateVerify processing path. Granularity sound.
    "bad_signature_wolf/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(WOLF, in_error="certificate verify failed"),
        TermContainsC(WOLF, "fn_find_server_certificate_request"),
        TermContainsC(WOLF, "fn_certificate_verify"),
        TermContainsC(WOLF, "fn_rsa_sign_client"),
    ),
    # BENIGN: Both PUTs correctly reject the bad CertificateVerify signature.
    # wolfssl reports generic "certificate verify failed"; OSSL reports the more
    # specific "tls_process_cert_verify:bad signature". The differential here is
    # error-string specificity, not acceptance vs rejection.
    # Note: despite the fn_certificate_verify attacker term, neither PUT accepts
    # the forged signature — OSSL logs "bad signature" at the cert-verify layer.
    #
    # Tag: BENIGN (differential error reporting; both PUTs reject correctly)
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC
    #   (CheckAgentC V1_3 + StatusC WOLF cert-verify-failed + TermContainsC
    #   fn_certificate_verify + StatusC OSSL tls_process_cert_verify:bad signature);
    #   all four conditions root-cause-grounded; Gate 2 FAIL confirmed (both PUTs
    #   reject); no attack surface (Gate 3 FAIL: master_secret=[0,0,...]).
    # AUDITED [Audit 1 Pass 4]: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — 15/15 sampled OSSL
    #   logs: tls_process_cert_verify:bad signature; 15/15 wolfssl logs: certificate
    #   verify failed. Single root cause. Tag corrected to BENIGN (both PUTs reject).
    "bad_signature_wolf_ossl_cert_verify/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(WOLF, in_error="certificate verify failed"),
        TermContainsC(WOLF, "fn_certificate_verify"),
        StatusC(OSSL, in_error="tls_process_cert_verify:bad signature", first_to_fail=False),
    ),

    # BENIGN: wolfssl considers certificate invalid (fn_certificate_verify) but OSSL
    # fails with decryption failure on the subsequent record — likely a cascading
    # failure after wolfssl's cert rejection altered the session key material.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (CheckAgentC V1_3 +
    #   StatusC WOLF cert_verify_failed + TermContainsC fn_certificate_verify +
    #   StatusC OSSL decryption failed); four root-cause-grounded constraints;
    #   cascading failure pattern well-defined.
    "bad_signature_wolf_ossl_decrypt_fail/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(WOLF, in_error="certificate verify failed"),
        TermContainsC(WOLF, "fn_certificate_verify"),
        StatusC(OSSL, in_error="tls_get_more_records:decryption failed", first_to_fail=False),
    ),

    # BENIGN: wolfssl considers certificate invalid (fn_certificate_verify) and OSSL
    # gets a bad record type — likely cascading TLS 1.3 record-framing error after
    # wolfssl's cert rejection caused unexpected state.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (CheckAgentC V1_3 +
    #   StatusC WOLF cert_verify_failed + TermContainsC fn_certificate_verify +
    #   AnyC StatusC OSSL bad_record_type); all conditions root-cause-grounded.
    "bad_signature_wolf_ossl_bad_record_type/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(WOLF, in_error="certificate verify failed"),
        TermContainsC(WOLF, "fn_certificate_verify"),
        AnyC(
            StatusC(OSSL, in_error="tls13_validate_record_header:bad record type", first_to_fail=False),
            StatusC(OSSL, in_error="tls13_common_post_process_record:bad record type", first_to_fail=False),
        ),
    ),

    # BENIGN: wolfssl considers certificate invalid (fn_certificate_verify) in a TLS
    # 1.3 session, but OSSL does not match any of the specific named error patterns
    # above. Residual catch-all for minor variants (wrong signature type, unexpected
    # message, etc.).
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (CheckAgentC V1_3 +
    #   StatusC WOLF cert_verify_failed + TermContainsC fn_certificate_verify);
    #   residual catch-all for bad-signature/cert-verify traces with minor OSSL
    #   variants not covered by the 3 specific sub-buckets above.  Wolfssl root
    #   cause is consistent (cert verify failed in fn_certificate_verify, TLS 1.3).
    "bad_signature_wolf_other/": AllC(
        CheckAgentC(["protocol_config", "tls_version"], "V1_3"),
        StatusC(WOLF, in_error="certificate verify failed"),
        TermContainsC(WOLF, "fn_certificate_verify"),
    ),

    # BENIGN: OpenSSL fails with invalid record type; wolfssl fails with
    # decode_error from fn_encrypt12 injecting a TLS 1.2-style record into
    # a TLS 1.3 session.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   ssl3_read_bytes:unexpected message + TermContainsC fn_encrypt12 + AnyC
    #   wolfssl record-layer errors); both PUT constraints root-cause-grounded for
    #   TLS 1.2 record injected into TLS 1.3 session.
    "ssl3_unexpected_wolf_decode_error/": AllC(
        StatusC(
            OSSL, in_error="ssl3_read_bytes:unexpected message", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_encrypt12"),
        AnyC(
            StatusC(WOLF, in_error="record layer length error", first_to_fail=False),
            StatusC(WOLF, in_error="Decode handshake message error", first_to_fail=False),
            StatusC(WOLF, in_error="unknown type in record hdr", first_to_fail=False),
        ),
    ),
    # BENIGN: OpenSSL fails with ssl3_read_bytes:unexpected message when wolfssl
    # does NOT have any of the major named wolfssl errors. Traces where wolfssl also
    # fails with a named error (record layer length, out-of-order, close notify, etc.)
    # are caught by the wolfssl-specific buckets later in the ordering.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   ssl3_read_bytes:unexpected message + NotC exclusion of 6 wolfssl errors);
    #   sampled 5 traces: OSSL error consistently "ssl3_read_bytes:unexpected message".
    #   NotC conditions prevent overlap with wolfssl bootstrap buckets.
    "ssl3_read_bytes_unexpected_ossl/": AllC(
        StatusC(OSSL, in_error="ssl3_read_bytes:unexpected message", first_to_fail=False),
        NotC(AnyC(
            StatusC(WOLF, in_error="record layer length error", first_to_fail=False),
            StatusC(WOLF, in_error="Out of order message, fatal", first_to_fail=False),
            StatusC(WOLF, in_error="peer sent close notify alert", first_to_fail=False),
            StatusC(WOLF, in_error="Duplicate HandShake message Error", first_to_fail=False),
            StatusC(WOLF, in_error="Sanity Check on message order Error", first_to_fail=False),
            StatusC(WOLF, in_error="record layer version error", first_to_fail=False),
        )),
    ),

    # --------------------------------------------------------------------------
    # BENIGN — OpenSSL-side specific status errors (OSSL-only conditions)
    # --------------------------------------------------------------------------
    # BENIGN: OpenSSL (server) fails with "tls_read_record:records not released"
    # when fn_alert_close_notify is sent before the connection is fully up.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls_read_record:records not released + TermContainsC fn_alert_close_notify);
    #   root-cause-grounded for close_notify-before-connection scenario.
    "records_not_released_ossl/": AllC(
        StatusC(
            OSSL, in_error="tls_read_record:records not released", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_alert_close_notify"),
    ),

    # BENIGN: OpenSSL detects a bad TLS 1.3 record type header.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls13_validate_record_header:bad record type"; sampled 3 traces: OSSL
    #   error consistent. Single root cause.
    "bad_record_type_ossl/": StatusC(
        OSSL,
        in_error="tls13_validate_record_header:bad record type",
        first_to_fail=False,
    ),

    # BENIGN: OpenSSL reports decryption failure or bad MAC at the record layer.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls_get_more_records:decryption failed or bad record mac"; sampled 5 traces:
    #   all show identical OSSL error. Single root cause.
    "decryption_failed_ossl/": StatusC(
        OSSL,
        in_error="tls_get_more_records:decryption failed or bad record mac",
        first_to_fail=False,
    ),

    # BENIGN: OpenSSL refuses no shared cipher after ClientHello.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls_post_process_client_hello:no shared cipher"; sampled 5 traces: all
    #   show identical OSSL error. Single root cause.
    "no_shared_cipher_ossl/": StatusC(
        OSSL, in_error="tls_post_process_client_hello:no shared cipher"
    ),

    # BENIGN: OpenSSL client state machine sees unexpected message.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "ossl_statem_client_read_transition:unexpected message"; sampled 4 traces:
    #   OSSL error consistent. Single root cause.
    "ossl_statem_client_unexpected/": StatusC(
        OSSL,
        in_error="ossl_statem_client_read_transition:unexpected message",
        first_to_fail=False,
    ),

    # BENIGN: OpenSSL (acting as server) fails the server-side state-machine
    # read-transition check on an unexpected TLS message. Wolfssl may succeed,
    # fail with a different error, or fail at a different step.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "ossl_statem_server_read_transition:unexpected message"; sampled 4 traces:
    #   OSSL error consistent. Single root cause.
    "ossl_statem_server_unexpected/": StatusC(
        OSSL,
        in_error="ossl_statem_server_read_transition:unexpected message",
        first_to_fail=False,
    ),

    # BENIGN: OpenSSL fails in TLS 1.3 record post-processing.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls13_common_post_process_record:bad"; 911 traces; single root cause.
    "tls13_post_process_record_bad_ossl/": StatusC(
        OSSL, in_error="tls13_common_post_process_record:bad", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails collecting extensions from a flight.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function
    #   "tls_collect_extensions"; sampled 3 traces: all "tls_collect_extensions:
    #   unsolicited extension". 126,678 traces; single root cause confirmed.
    # NOTE (ADV-3, 2026-06-04): 100-trace sample shows two error reason subtypes —
    #   "bad extension" (57%) and "unsolicited extension" (43%). Both are correct
    #   OpenSSL rejection of crafted/malformed trace inputs; both share the same
    #   function and BENIGN classification. No split warranted; condition retained.
    "tls_collect_extensions_bad_ossl/": StatusC(
        OSSL, in_error="tls_collect_extensions", first_to_fail=False
    ),

    # BENIGN: OpenSSL Finished message MAC check fails.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls_process_finished:digest"; 2,009 traces; single root cause.
    "tls_process_finished_digest_ossl/": StatusC(
        OSSL, in_error="tls_process_finished:digest", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails post-processing server certificate (certificate
    # chain validation failure).
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function
    #   "tls_post_process_server_certificate"; 2,482 traces; single root cause.
    "tls_post_process_certificate_ossl/": StatusC(
        OSSL, in_error="tls_post_process_server_certificate", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails processing server certificate message.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function
    #   "tls_process_server_certificate"; sampled 2 traces: consistent
    #   "tls_process_server_certificate:length mismatch". 44,622 traces; single root cause.
    "tls_process_server_certificate_ossl/": StatusC(
        OSSL, in_error="tls_process_server_certificate", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails verifying a CertificateVerify signature.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls_process_cert_verify:bad signature"; 2,582 traces; single root cause.
    "tls_process_cert_verify_bad_signature_ossl/": StatusC(
        OSSL, in_error="tls_process_cert_verify:bad signature", first_to_fail=False
    ),

    # BENIGN: OpenSSL rejects a ServerHello whose length is inconsistent with
    # an HRR-random value.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls_process_server_hello:bad length + TermContainsC fn_hello_retry_request_random);
    #   sampled 3 traces: OSSL error consistent "tls_process_server_hello:bad length"
    #   (statem_clnt.c:1531). Root-cause-grounded.
    "tls_process_server_hello_bad_length/": AllC(
        StatusC(
            OSSL,
            in_error="tls_process_server_hello:bad length",
            first_to_fail=False,
        ),
        TermContainsC(OSSL, "fn_hello_retry_request_random"),
    ),

    # BENIGN: OpenSSL rejects an invalid ServerHello (malformed fields).
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls_process_server_hello:invalid"; 10,571 traces; single root cause.
    "tls_process_server_hello_invalid_ossl/": StatusC(
        OSSL, in_error="tls_process_server_hello:invalid", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails processing a CertificateRequest message.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function
    #   "tls_process_certificate_request"; 591 traces; single root cause.
    "tls_process_certificate_request_ossl/": StatusC(
        OSSL, in_error="tls_process_certificate_request", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails parsing a SCT extension.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls_parse_stoc_sct:bad"; 6,324 traces; single root cause.
    "tls_parse_stoc_sct_bad_ossl/": StatusC(
        OSSL, in_error="tls_parse_stoc_sct:bad", first_to_fail=False
    ),

    # BENIGN: OpenSSL rejects a bad key_share in a second ClientHello after HRR.
    # Wolfssl (as server) accepts the bad key_share and completes the handshake.
    #
    # Tag: BENIGN
    # Reported: wolfssl/wolfssl#9362 (closed) — RFC 8446 violation: wolfssl accepts
    #   ClientHello after HRR with an incorrect KeyShare extension.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls_parse_ctos_key_share:bad key share + TermContainsC fn_hello_retry_request_random);
    #   sampled 2 traces: OSSL error consistent. 42,814 traces; root-cause-grounded.
    "tls_parse_ctos_key_share_bad/": AllC(
        StatusC(
            OSSL,
            in_error="tls_parse_ctos_key_share:bad key share",
            first_to_fail=False,
        ),
        TermContainsC(OSSL, "fn_hello_retry_request_random"),
    ),

    # BENIGN: OpenSSL rejects a ClientHello because the supported_groups
    # extension is missing — different error sub-string from "bad key share".
    # Wolfssl (as server) accepts such a ClientHello without error.
    #
    # Tag: BENIGN
    # Reported: wolfssl/wolfssl#9247 (closed) — RFC 8446 violation: wolfssl accepts
    #   ClientHello without a SupportedGroups extension.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls_parse_ctos_key_share:missing supported groups extension";
    #   sampled 3 traces: OSSL error consistent. 91,835 traces; single root cause.
    "tls_parse_ctos_key_share_missing_groups/": StatusC(
        OSSL,
        in_error="tls_parse_ctos_key_share:missing supported groups extension",
        first_to_fail=False,
    ),

    # BENIGN: OpenSSL fails early processing a ClientHello with early_data.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls_early_post_process_client_hello + AnyC TermContainsC early_data);
    #   root-cause-grounded; 6,045 traces; single root cause.
    "tls_parse_ctos_early_data_bad_ossl/": AllC(
        StatusC(
            OSSL,
            in_error="tls_early_post_process_client_hello",
            first_to_fail=False,
        ),
        AnyC(
            TermContainsC(OSSL, "fn_early_data_indication"),
            TermContainsC(OSSL, "fn_early_data_extension"),
        ),
    ),

    # BENIGN: OpenSSL fails parsing a status_request extension.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls_parse_ctos_status_request:bad + TermContainsC fn_status_request_extension);
    #   sampled 2 traces: OSSL outer error consistently "tls_parse_ctos_status_request:
    #   bad extension" (inner ASN1 error varies but same root-cause function).
    #   48,149 traces; single root cause confirmed.
    "tls_parse_ctos_status_request_bad_ossl/": AllC(
        StatusC(
            OSSL, in_error="tls_parse_ctos_status_request:bad", first_to_fail=False
        ),
        TermContainsC(OSSL, "fn_status_request_extension"),
    ),

    # BENIGN: OpenSSL fails parsing a malformed ALPN extension.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls_parse_ctos_alpn:bad + TermContainsC fn_al_protocol_negotiation);
    #   sampled 3 traces: OSSL error consistent. 43,012 traces; root-cause-grounded.
    "tls_parse_ctos_alpn_bad_ossl/": AllC(
        StatusC(OSSL, in_error="tls_parse_ctos_alpn:bad", first_to_fail=False),
        TermContainsC(OSSL, "fn_al_protocol_negotiation"),
    ),

    # BENIGN: OpenSSL fails parsing a malformed supported_groups extension.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls_parse_ctos_supported_groups:bad + TermContainsC fn_support_group_extension_make);
    #   sampled 2 traces: OSSL error consistent. 109,173 traces; root-cause-grounded.
    "tls_parse_ctos_supported_groups_bad_ossl/": AllC(
        StatusC(
            OSSL,
            in_error="tls_parse_ctos_supported_groups:bad",
            first_to_fail=False,
        ),
        TermContainsC(OSSL, "fn_support_group_extension_make"),
    ),

    # BENIGN: OpenSSL fails parsing CA names from a CertificateRequest.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function
    #   "parse_ca_names"; 904 traces; single root cause.
    "parse_ca_names_bad_ossl/": StatusC(
        OSSL, in_error="parse_ca_names", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails with "excessive message size" at the state machine.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "read_state_machine:excessive"; 724 traces; single root cause.
    "read_state_machine_excessive_ossl/": StatusC(
        OSSL, in_error="read_state_machine:excessive", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails finding a shared signature algorithm.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "tls1_set_server_sigalgs:no shared"; sampled 3 traces: OSSL error consistent.
    #   34,494 traces; single root cause.
    "tls1_set_server_sigalgs_ossl/": StatusC(
        OSSL, in_error="tls1_set_server_sigalgs:no shared", first_to_fail=False
    ),

    # BENIGN: OpenSSL rejects an explicitly invalid signature algorithm.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls12_check_peer_sigalg + TermContainsC fn_invalid_signature_algorithm);
    #   both conditions root-cause-grounded; 94 traces; single root cause.
    "tls12_check_peer_sigalg_invalid_ossl/": AllC(
        StatusC(OSSL, in_error="tls12_check_peer_sigalg", first_to_fail=False),
        TermContainsC(OSSL, "fn_invalid_signature_algorithm"),
    ),

    # BENIGN: OpenSSL rejects a CertificateVerify where the key does not match
    # the certificate (fn_append_transcript used to build a mismatched transcript).
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   tls12_check_peer_sigalg + TermContainsC fn_certificate_verify + fn_append_transcript);
    #   all conditions root-cause-grounded; 62 traces; single root cause.
    "tls12_check_peer_sigalg_wrong_key_ossl/": AllC(
        StatusC(OSSL, in_error="tls12_check_peer_sigalg", first_to_fail=False),
        TermContainsC(OSSL, "fn_certificate_verify"),
        TermContainsC(OSSL, "fn_append_transcript"),
    ),

    # BENIGN: OpenSSL rejects an oversized record from fn_certificate_status.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 unchecked (5 traces only) — multi-condition
    #   (StatusC OSSL tls_get_more_records:packet length too long + TermContainsC
    #   fn_certificate_status); root-cause-grounded; too few traces for full C4.
    "tls_get_more_records_packet_too_long_ossl/": AllC(
        StatusC(
            OSSL,
            in_error="tls_get_more_records:packet length too long",
            first_to_fail=False,
        ),
        TermContainsC(OSSL, "fn_certificate_status"),
    ),

    # BENIGN: OpenSSL rejects an oversized record from fn_encrypt_handshake_opaque.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 unchecked (5 traces only) — multi-condition
    #   (StatusC OSSL tls_get_more_records:packet length too long + TermContainsC
    #   fn_encrypt_handshake_opaque); root-cause-grounded; too few traces for full C4.
    "tls_get_more_records_packet_too_long_other_ossl/": AllC(
        StatusC(
            OSSL,
            in_error="tls_get_more_records:packet length too long",
            first_to_fail=False,
        ),
        TermContainsC(OSSL, "fn_encrypt_handshake_opaque"),
    ),

    # BENIGN: OpenSSL rejects a record with invalid content type.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition (StatusC OSSL
    #   ssl3_read_bytes:invalid + AnyC TermContainsC fn_encrypt12/close_notify/cert_verify/
    #   append_transcript); all conditions root-cause-grounded; 1,747 traces.
    "ssl3_read_bytes_invalid_record_type_ossl/": AllC(
        StatusC(OSSL, in_error="ssl3_read_bytes:invalid", first_to_fail=False),
        AnyC(
            TermContainsC(OSSL, "fn_encrypt12"),
            TermContainsC(OSSL, "fn_alert_close_notify"),
            TermContainsC(OSSL, "fn_certificate_verify"),
            TermContainsC(OSSL, "fn_append_transcript"),
        ),
    ),

    # BENIGN: OpenSSL rejects a TLS 1.3 record that has an encrypted content
    # type in the wrong direction.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓
    #   7/19 traces sampled: all show identical OSSL error
    #   "tls13_validate_record_header:encrypted length too long" (statem_lib.c:269).
    #   Multi-condition (StatusC + AnyC TermContainsC). Single root cause.
    "tls13_validate_record_header_encrypted_ossl/": AllC(
        StatusC(
            OSSL,
            in_error="tls13_validate_record_header:encrypted",
            first_to_fail=False,
        ),
        AnyC(
            TermContainsC(OSSL, "fn_encrypt_handshake"),
            TermContainsC(OSSL, "fn_encrypt12"),
        ),
    ),

    # BENIGN: OpenSSL Finished message is "not on record boundary"
    # (fn_append_transcript + fn_rsa_sign_server injects Finished spanning records).
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓
    #   15/35 traces sampled: all show identical OSSL error
    #   "tls_process_finished:not on record boundary" (statem_lib.c:865).
    #   Multi-condition (StatusC + 2× TermContainsC). Single root cause confirmed.
    "tls_process_finished_wrong_mac_ossl/": AllC(
        StatusC(OSSL, in_error="tls_process_finished:not", first_to_fail=False),
        TermContainsC(OSSL, "fn_append_transcript"),
        TermContainsC(OSSL, "fn_rsa_sign_server"),
    ),

    # BENIGN: OpenSSL Finished message returns "bad digest length" with
    # fn_append_transcript injecting a mismatched-length transcript hash.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓
    #   10/25 traces sampled: all show identical OSSL error
    #   "tls_process_finished:bad digest length" (statem_lib.c:879).
    #   Multi-condition (StatusC + TermContainsC). Single root cause confirmed.
    "tls_process_finished_bad_mac_ossl/": AllC(
        StatusC(OSSL, in_error="tls_process_finished:bad", first_to_fail=False),
        TermContainsC(OSSL, "fn_append_transcript"),
    ),

    # BENIGN: OpenSSL refuses a ClientHello missing the psk_kex_modes extension.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific OSSL function+error
    #   "final_psk:missing"; 4,921 traces; single root cause (missing PSK extension).
    "final_psk_missing_ossl/": StatusC(
        OSSL, in_error="final_psk:missing", first_to_fail=False
    ),

    # --------------------------------------------------------------------------
    # BENIGN — Alert-pair differences: InnerKnowledgeC (adapted from boring)
    # Both PUTs reject; alert-code choice is implementation-defined.
    # --------------------------------------------------------------------------
    # BENIGN: decode_error vs illegal_parameter (reversed).
    # Reported: wolfssl/wolfssl#9640 (closed) — RFC 8446 violation: wolfssl returns
    #   illegal_parameter instead of decode_error for a malformed KeyShare extension.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_decode_error_ossl_vs_illegal_param_wolf/": InnerKnowledgeC(
        "[Description(Different(DecodeError, IllegalParameter))]"
    ),
    # BENIGN: unexpected_message vs illegal_parameter.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_unexpected_msg_ossl_vs_illegal_param_wolf/": InnerKnowledgeC(
        "[Description(Different(UnexpectedMessage, IllegalParameter))]"
    ),
    # BENIGN: unexpected_message vs decode_error.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 unchecked (2 traces) — specific named
    #   alert pair; too few traces for full C4 but condition exact-string match
    #   structurally guarantees single root cause.
    "alert_unexpected_msg_ossl_vs_decode_error_wolf/": InnerKnowledgeC(
        "[Description(Different(UnexpectedMessage, DecodeError))]"
    ),
    # BENIGN: handshake_failure vs illegal_parameter.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_handshake_failure_ossl_vs_illegal_param_wolf/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, IllegalParameter))]"
    ),
    # BENIGN: illegal_parameter vs handshake_failure.
    # Reported: wolfssl/wolfssl#9639 (closed) — RFC 8446 violation: wolfssl returns
    #   handshake_failure instead of illegal_parameter for an unoffered cipher suite.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_illegal_param_ossl_vs_handshake_failure_wolf/": InnerKnowledgeC(
        "[Description(Different(IllegalParameter, HandshakeFailure))]"
    ),
    # BENIGN: handshake_failure vs decode_error.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_handshake_failure_ossl_vs_decode_error_wolf/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, DecodeError))]"
    ),
    # BENIGN: decode_error vs handshake_failure.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_decode_error_ossl_vs_handshake_failure_wolf/": InnerKnowledgeC(
        "[Description(Different(DecodeError, HandshakeFailure))]"
    ),
    # BENIGN: missing_extension vs illegal_parameter.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 unchecked (1 trace) — specific named
    #   alert pair; structurally single root cause via exact-string InnerKnowledgeC.
    "alert_missing_ext_ossl_vs_illegal_param_wolf/": InnerKnowledgeC(
        "[Description(Different(MissingExtension, IllegalParameter))]"
    ),
    # BENIGN: illegal_parameter vs unexpected_message.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_illegal_param_ossl_vs_unexpected_msg_wolf/": InnerKnowledgeC(
        "[Description(Different(IllegalParameter, UnexpectedMessage))]"
    ),
    # RFC: OpenSSL sends decode_error instead of RFC-mandated missing_extension for
    # absent mandatory TLS 1.3 extension. RFC 8446 §9.2: MUST use missing_extension
    # when a mandatory extension (key_share, supported_groups, etc.) is absent.
    # wolfssl correctly sends missing_extension; OpenSSL sends decode_error.
    #
    # Tag: BENIGN (decode_error vs missing_extension; malformed PSK ext, not absent)
    # AUDIT 5 (2026-06-05): REVISION NEEDED → RESOLVED by REVERT to BENIGN (2026-06-05).
    #   The 2026-06-04 reclassification to [RFC]/RFC003 was over-eager. Orchestrator
    #   re-verified: all 111/111 OSSL errors are "tls_parse_ctos_psk:bad extension" — the PSK
    #   extension is PRESENT-but-malformed, so §9.2 (absent mandatory extension) does NOT
    #   govern, and decode_error is RFC-defensible for a malformed extension. Same reasoning
    #   that kept alert_illegal_param_ossl_vs_missing_ext_wolf BENIGN. Bug report RFC003
    #   WITHDRAWN. VULN check PASS (0 Finished). (Filesystem count = 111.)
    # AUDITED (Audit 5b, 2026-06-05): revert to BENIGN CONFIRMED independently. Full bucket
    #   n=111: 111/111 OSSL "tls_parse_ctos_psk:bad extension" — PSK ext present-but-malformed,
    #   §9.2 (absent ext) N/A, decode_error defensible. OK.
    "alert_decode_error_ossl_vs_missing_ext_wolf/": InnerKnowledgeC(
        "[Description(Different(DecodeError, MissingExtension))]"
    ),
    # BENIGN: handshake_failure vs unexpected_message.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_handshake_failure_ossl_vs_unexpected_msg_wolf/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, UnexpectedMessage))]"
    ),
    # BENIGN: protocol_version vs illegal_parameter.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_protocol_version_ossl_vs_illegal_param_wolf/": InnerKnowledgeC(
        "[Description(Different(ProtocolVersion, IllegalParameter))]"
    ),
    # RFC: wolfssl sends decode_error instead of RFC-mandated protocol_version for
    # version negotiation failure. RFC 8446 §4.1.2/4.1.3: MUST use protocol_version
    # when the negotiated TLS version is not supported. OpenSSL correctly sends
    # protocol_version; wolfssl sends decode_error.
    #
    # Tag: RFC (wolfssl violates RFC 8446 §4.1.2 — decode_error instead of protocol_version)
    # Bug report: BUGS/RFC007_wolfssl_wrong_alert_protocol_version.md
    # AUDITED: Gate 1 FAIL — 0 Finished claims in 3,934 traces; both PUTs abort.
    #          [RFC] CVSS 0.0 confirmed.
    # Reclassified 2026-06-04: BENIGN → [RFC] per benign_reclassification_report_2026-06-04.md
    # AUDIT 5 (2026-06-05): AUDITED — 35/40 sampled OSSL errors are
    #   "ssl_choose_client_version:unsupported protocol" (+4 "wrong ssl version") → a genuine
    #   version-negotiation failure for which protocol_version is correct; wolfSSL decode_error
    #   is wrong. Direction confirmed by OSSL's own error path. 769 Finished, 0 with
    #   authenticate_peer:true AND non-zero master_secret — VULN check PASS.
    "alert_protocol_version_ossl_vs_decode_error_wolf/": InnerKnowledgeC(
        "[Description(Different(ProtocolVersion, DecodeError))]"
    ),
    # RFC: OpenSSL sends handshake_failure instead of RFC-mandated missing_extension
    # for absent mandatory TLS 1.3 key_share extension. RFC 8446 §9.2: MUST use
    # missing_extension when a mandatory extension is absent. wolfssl correctly sends
    # missing_extension; OpenSSL sends generic handshake_failure.
    #
    # Tag: BENIGN (handshake_failure vs missing_extension; no-shared-cipher, key_share present)
    # AUDIT 5 (2026-06-05): REVISION NEEDED → RESOLVED by REVERT to BENIGN (2026-06-05).
    #   The 2026-06-04 reclassification to [RFC]/RFC003 was over-eager. Orchestrator
    #   re-verified the full bucket: all 3,424/3,424 OSSL errors are
    #   "tls_early_post_process_client_hello:no shared cipher", and key_share is PRESENT in
    #   2,240/3,424 (65%). The defect is excluded/unsupported cipher suites, for which
    #   handshake_failure is the RFC-appropriate alert — so OSSL is NOT RFC-wrong; the §9.2
    #   "missing key_share" premise is false. Bug report RFC003 WITHDRAWN. VULN check PASS
    #   (0 Finished claims).
    # AUDITED (Audit 5b, 2026-06-05): revert to BENIGN CONFIRMED independently. Full bucket
    #   n=3424: 3424/3424 OSSL "no shared cipher"; key_share PRESENT in 2196/3424 (64%). The
    #   defect is excluded ciphers; handshake_failure is RFC-appropriate; §9.2 premise false. OK.
    "alert_handshake_failure_ossl_vs_missing_ext_wolf/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, MissingExtension))]"
    ),
    # RFC: wolfssl sends decode_error instead of RFC-mandated missing_extension for
    # absent mandatory TLS 1.3 extension (key_share, signature_algorithms).
    # RFC 8446 §9.2: MUST use missing_extension when a mandatory extension is absent.
    # OpenSSL correctly sends missing_extension; wolfssl sends decode_error.
    #
    # Tag: RFC (wolfssl violates RFC 8446 §9.2 — decode_error instead of missing_extension)
    # Bug report: BUGS/RFC006_wolfssl_wrong_alert_absent_mandatory_ext.md
    # AUDITED: Gate 1 FAIL — 0 Finished claims in 1,092 traces; both PUTs abort.
    #          [RFC] CVSS 0.0 confirmed.
    # Reclassified 2026-06-04: BENIGN → [RFC] per benign_reclassification_report_2026-06-04.md
    # AUDIT 5 (2026-06-05): AUDITED — sampled OSSL errors are "final_sig_algs:missing sigalgs
    #   extension" (25/40) and "final_key_share:no suitable key share" (15/40): OSSL detects a
    #   genuinely absent mandatory extension and sends missing_extension (§9.2 correct);
    #   wolfSSL decode_error is wrong. Direction confirmed. 0 authenticated Finished — PASS.
    "alert_missing_ext_ossl_vs_decode_error_wolf/": InnerKnowledgeC(
        "[Description(Different(MissingExtension, DecodeError))]"
    ),

    # --------------------------------------------------------------------------
    # BENIGN — Alert-pair differences: NEW wolfssl-specific pairs
    # (high-volume patterns not present in the boring campaign)
    # --------------------------------------------------------------------------
    # RFC: wolfssl sends protocol_version instead of RFC-mandated illegal_parameter
    # for bad ServerHello key_share content. RFC 8446 §4.2.8: client MUST abort with
    # illegal_parameter if the server's key_share is invalid. OpenSSL correctly sends
    # illegal_parameter (triggered by tls_parse_stoc_key_share:bad key share);
    # wolfssl sends protocol_version.
    #
    # Tag: BENIGN (illegal_parameter vs protocol_version; aggregates ≥3 distinct triggers)
    # AUDIT 5 (2026-06-05): REVISION NEEDED → RESOLVED by REVERT to BENIGN (2026-06-05).
    #   The 2026-06-04 reclassification to [RFC]/RFC010 was over-eager. This pure alert-pair
    #   bucket (no term constraint) aggregates ≥3 distinct triggers: only ~12% are
    #   "tls_parse_stoc_key_share:bad key share" (the §4.2.8 case RFC010 cited); ~16% are
    #   "tls_parse_stoc_supported_versions:bad protocol version number" — a genuine version
    #   problem where wolfSSL's protocol_version is plausibly the CORRECT alert (direction
    #   INVERTS); the rest are cipher errors. No single RFC violation governs the bucket.
    #   Bug report RFC010 WITHDRAWN. (0 snapshot traces; live-only.) VULN check PASS.
    # AUDITED (Audit 5b, 2026-06-05): revert to BENIGN CONFIRMED independently. Sample n=300:
    #   only ~13% (38) "tls_parse_stoc_key_share:bad key share" (§4.2.8); ~14% (42)
    #   "tls_parse_stoc_supported_versions:bad protocol version number" where wolfSSL's
    #   protocol_version is plausibly CORRECT (direction inverts); rest cipher. No single RFC
    #   violation governs. OK.
    "alert_illegal_param_ossl_vs_protocol_version_wolf/": InnerKnowledgeC(
        "[Description(Different(IllegalParameter, ProtocolVersion))]"
    ),
    # BENIGN: decode_error vs protocol_version.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_decode_error_ossl_vs_protocol_version_wolf/": InnerKnowledgeC(
        "[Description(Different(DecodeError, ProtocolVersion))]"
    ),
    # RFC: wolfssl sends protocol_version instead of RFC-mandated missing_extension
    # for absent mandatory TLS 1.3 extensions (supported_versions, signature_algorithms).
    # RFC 8446 §9.2: MUST use missing_extension for absent mandatory extensions.
    # OpenSSL correctly sends missing_extension; wolfssl conflates this with a version
    # negotiation failure and sends protocol_version.
    #
    # Tag: RFC (wolfssl violates RFC 8446 §9.2 — protocol_version instead of missing_extension)
    # Bug report: BUGS/RFC006_wolfssl_wrong_alert_absent_mandatory_ext.md
    # AUDITED: Gate 1 FAIL — 0 Finished claims in 7,687 traces; both PUTs abort.
    #          [RFC] CVSS 0.0 confirmed.
    # Reclassified 2026-06-04: BENIGN → [RFC] per benign_reclassification_report_2026-06-04.md
    # AUDIT 5 (2026-06-05): AUDITED — sampled OSSL errors are "final_supported_versions:missing
    #   supported versions extension" (20/40), "final_sig_algs:missing sigalgs extension" (12),
    #   "final_key_share" (8): a genuinely absent mandatory §9.2 extension; OSSL sends
    #   missing_extension (correct), wolfSSL protocol_version is wrong (it misreads an absent
    #   extension as a version failure). Direction confirmed. 48 Finished, 0 authenticated — PASS.
    "alert_missing_ext_ossl_vs_protocol_version_wolf/": InnerKnowledgeC(
        "[Description(Different(MissingExtension, ProtocolVersion))]"
    ),
    # BENIGN: handshake_failure vs protocol_version.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_handshake_failure_ossl_vs_protocol_version_wolf/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, ProtocolVersion))]"
    ),
    # RFC: wolfssl sends handshake_failure instead of RFC-mandated protocol_version for
    # unsupported protocol version. RFC 8446 §4.1.2: MUST use protocol_version alert
    # when the legacy version presented by the client is not supported. OpenSSL
    # correctly sends protocol_version (tls_early_post_process_client_hello:unsupported
    # protocol); wolfssl falls back to generic handshake_failure.
    #
    # Tag: RFC (wolfssl violates RFC 8446 §4.1.2 — handshake_failure instead of protocol_version)
    # Bug report: BUGS/RFC007_wolfssl_wrong_alert_protocol_version.md
    # AUDITED: Gate 1 FAIL — 0 Finished claims in 2,686 traces; both PUTs abort.
    #          [RFC] CVSS 0.0 confirmed.
    # Reclassified 2026-06-04: BENIGN → [RFC] per benign_reclassification_report_2026-06-04.md
    # AUDIT 5 (2026-06-05): AUDITED (with caveat) — 40/40 sampled OSSL errors are
    #   "tls_early_post_process_client_hello:unsupported protocol" → protocol_version is the
    #   precise alert; wolfSSL handshake_failure is a generic fallback. This is the WEAKEST of
    #   the wolfSSL violation claims (handshake_failure is not strictly forbidden); note the
    #   asymmetry with the BENIGN-retained reverse bucket
    #   alert_handshake_failure_ossl_vs_protocol_version_wolf. Direction defensible given the
    #   confirmed "unsupported protocol" trigger. 0 Finished — VULN check PASS.
    "alert_protocol_version_ossl_vs_handshake_failure_wolf/": InnerKnowledgeC(
        "[Description(Different(ProtocolVersion, HandshakeFailure))]"
    ),
    # BENIGN: unexpected_message vs handshake_failure (15,751 traces).
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair;
    #   InnerKnowledgeC exact-string guarantees single root cause.
    "alert_unexpected_msg_ossl_vs_handshake_failure_wolf/": InnerKnowledgeC(
        "[Description(Different(UnexpectedMessage, HandshakeFailure))]"
    ),
    # BENIGN: decrypt_error vs handshake_failure.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_decrypt_error_ossl_vs_handshake_failure_wolf/": InnerKnowledgeC(
        "[Description(Different(DecryptError, HandshakeFailure))]"
    ),
    # BENIGN: handshake_failure vs bad_certificate.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓
    #   6/49 traces sampled: all show BothAlert([Description(Different(HandshakeFailure,
    #   BadCertificate))]). Specific named alert pair; single differential pattern.
    "alert_handshake_failure_ossl_vs_bad_certificate_wolf/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, BadCertificate))]"
    ),
    # BENIGN: bad_certificate vs unknown_ca.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert pair.
    "alert_bad_certificate_ossl_vs_unknown_ca_wolf/": InnerKnowledgeC(
        "[Description(Different(BadCertificate, UnknownCA))]"
    ),
    # BENIGN: handshake_failure vs unknown_ca.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓
    #   6/37 traces sampled: all show BothAlert([Description(Different(HandshakeFailure,
    #   UnknownCA))]). Specific named alert pair; single differential pattern.
    "alert_handshake_failure_ossl_vs_unknown_ca_wolf/": InnerKnowledgeC(
        "[Description(Different(HandshakeFailure, UnknownCA))]"
    ),
    # RFC: wolfssl sends illegal_parameter (or variant) instead of RFC-mandated
    # record_overflow for oversized TLS records. RFC 8446 §5.2: "If an implementation
    # receives a record that violates these length restrictions, it MUST terminate
    # the connection with a record_overflow alert." OpenSSL correctly sends
    # record_overflow; wolfssl exits through a different validation path and sends
    # illegal_parameter.
    #
    # Tag: RFC (wolfssl violates RFC 8446 §5.2 — wrong alert for oversized record)
    # Bug report: BUGS/RFC008_wolfssl_wrong_alert_record_overflow.md
    # AUDITED: Gate 1 FAIL — 0 Finished claims in 373 traces; both PUTs abort.
    #          [RFC] CVSS 0.0 confirmed.
    # Reclassified 2026-06-04: BENIGN → [RFC] per benign_reclassification_report_2026-06-04.md
    # AUDIT 5 (2026-06-05): AUDITED — sampled OSSL errors are "tls_get_more_records:packet
    #   length too long" (23/40) and "tls_validate_record_header:data length too long" (17/40):
    #   a genuine oversized-record condition for which §5.2 MANDATES record_overflow; OSSL is
    #   correct, wolfSSL illegal_parameter (early-exit path) is wrong. 0 Finished — VULN PASS.
    "alert_record_overflow_ossl_vs_wolf/": InnerKnowledgeC(
        "[Description(Different(RecordOverflow,"
    ),

    # --------------------------------------------------------------------------
    # BENIGN — wolfssl-specific: Fatal→Warning renegotiation divergence
    # wolfssl sends Warning/NoRenegotiation (close_notify-like) while OpenSSL
    # sends a Fatal alert.  wolfssl interprets the condition as a renegotiation
    # refusal (Warning) rather than an immediate fatal abort.
    # --------------------------------------------------------------------------
    # 13,849 traces: OSSL Fatal/UnexpectedMessage vs wolfssl Warning/NoRenegotiation.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — InnerKnowledgeC exact-string
    #   captures both the Level (Fatal vs Warning) and Description (UnexpectedMessage
    #   vs NoRenegotiation); single root cause (alert level + description mismatch).
    "wolf_close_notify_vs_ossl_unexpected_msg/": InnerKnowledgeC(
        "[Level(Different(Fatal, Warning)), Description(Different(UnexpectedMessage, NoRenegotiation))]"
    ),
    # 1,556 traces: OSSL Fatal/IllegalParameter vs wolfssl Warning/NoRenegotiation.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert-level+description pair.
    "wolf_close_notify_vs_ossl_illegal_param/": InnerKnowledgeC(
        "[Level(Different(Fatal, Warning)), Description(Different(IllegalParameter, NoRenegotiation))]"
    ),
    # OSSL Fatal/ProtocolVersion vs wolfssl Warning/NoRenegotiation.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert-level+description pair.
    "wolf_close_notify_vs_ossl_protocol_version/": InnerKnowledgeC(
        "[Level(Different(Fatal, Warning)), Description(Different(ProtocolVersion, NoRenegotiation))]"
    ),
    # OSSL Fatal/HandshakeFailure vs wolfssl Warning/NoRenegotiation.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert-level+description pair.
    "wolf_close_notify_vs_ossl_handshake_failure/": InnerKnowledgeC(
        "[Level(Different(Fatal, Warning)), Description(Different(HandshakeFailure, NoRenegotiation))]"
    ),
    # OSSL Fatal/DecodeError vs wolfssl Warning/NoRenegotiation.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — specific named alert-level+description pair.
    "wolf_close_notify_vs_ossl_decode_error/": InnerKnowledgeC(
        "[Level(Different(Fatal, Warning)), Description(Different(DecodeError, NoRenegotiation))]"
    ),
    # BENIGN: wolfssl sends close_notify (Warning level) while OSSL receives a
    # DecryptError alert (Fatal level). The alert level difference (Fatal vs Warning)
    # combined with the DecryptError/NoRenegotiation description mismatch is
    # spec-permitted behaviour — both implementations handle TLS record mac errors
    # differently at the alert level.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ (16 traces, all confirm this pattern)
    # PENDING REVIEW
    # Fixed (RN-1, 2026-06-04): added Level(Different(Fatal, Warning)) prefix to match
    #   the full knowledge string BothAlert([Level(...), Description(...)]) and align
    #   with all 5 sibling wolf_close_notify_vs_ossl_* buckets.
    "wolf_close_notify_vs_ossl_decrypt_error/": InnerKnowledgeC(
        "[Level(Different(Fatal, Warning)), Description(Different(DecryptError, NoRenegotiation))]"
    ),

    # --------------------------------------------------------------------------
    # BENIGN — HRR cipher suite and ServerHello KeyShare group divergence
    # --------------------------------------------------------------------------
    # 3,246 traces: Both PUTs see an HRR but with different cipher suite chosen
    # (AES_128_GCM_SHA256 vs AES_256_GCM_SHA384).
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — InnerKnowledgeC prefix match on
    #   "BothHelloRetryRequest([CipherSuite(Different(" captures HRR cipher suite
    #   mismatch; specific named pattern; single root cause.
    "wolf_hrr_cipher_suite_mismatch/": InnerKnowledgeC(
        "BothHelloRetryRequest([CipherSuite(Different("
    ),
    # 614 traces: Both PUTs see a ServerHello but with different KeyShare group
    # (secp384r1 vs secp256r1).
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — InnerKnowledgeC prefix match on
    #   "BothServerHello([SortedExtensions(ServerExtensionsChange" captures KeyShare
    #   group mismatch in ServerHello; specific named pattern; single root cause.
    "wolf_server_hello_key_share_group_mismatch/": InnerKnowledgeC(
        "BothServerHello([SortedExtensions(ServerExtensionsChange"
    ),

    # --------------------------------------------------------------------------
    # BENIGN — Unknown/malformed alert values (wolfssl-specific)
    # wolfssl may emit non-standard alert level/description bytes that cannot
    # be parsed into known enum variants.
    # --------------------------------------------------------------------------
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — InnerKnowledgeC prefix match on
    #   "BothAlert([Level(BothUnknown" captures non-standard alert level bytes
    #   in both PUTs; specific named pattern; single root cause.
    "wolf_both_unknown_alert/": InnerKnowledgeC("BothAlert([Level(BothUnknown"),

    # Sub-buckets for claim_finished_wolf_only: wolfssl finishes but OSSL fails
    # with specific named OSSL errors. Placed before the generic bucket so that
    # traces with specific OSSL error fingerprints are more precisely classified.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC: DifferentClaimC
    #   ((), Finished) + StatusC(OSSL, "ssl3_read_bytes:unexpected record"); both
    #   conditions root-cause-grounded; 294 traces; specific OSSL error narrows cause.
    "claim_finished_wolf_ossl_unexpected_record/": AllC(
        DifferentClaimC(in_first_type="()", in_second_type="Finished"),
        StatusC(OSSL, in_error="ssl3_read_bytes:unexpected record", first_to_fail=False),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC: DifferentClaimC
    #   ((), Finished) + StatusC(OSSL, "ssl_choose_client_version:unsupported protocol");
    #   both conditions root-cause-grounded; specific OSSL error narrows cause.
    "claim_finished_wolf_ossl_unsupported_proto/": AllC(
        DifferentClaimC(in_first_type="()", in_second_type="Finished"),
        StatusC(OSSL, in_error="ssl_choose_client_version:unsupported protocol", first_to_fail=False),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC: DifferentClaimC
    #   ((), Finished) + AnyC(StatusC OSSL tls_process_cke_ecdhe:|tls_process_ske_ecdhe:);
    #   all conditions root-cause-grounded; specific ECDHE function narrows cause.
    "claim_finished_wolf_ossl_ecdhe/": AllC(
        DifferentClaimC(in_first_type="()", in_second_type="Finished"),
        AnyC(
            StatusC(OSSL, in_error="tls_process_cke_ecdhe:", first_to_fail=False),
            StatusC(OSSL, in_error="tls_process_ske_ecdhe:", first_to_fail=False),
        ),
    ),
    # --------------------------------------------------------------------------
    # BENIGN/RFC — Claim differences (Finished present in one PUT only)
    # One PUT completes the handshake (has a Finished claim) while the other
    # aborts.  High-volume wolfssl-specific pattern.
    # --------------------------------------------------------------------------
    # 78,970 traces: wolfssl (PUT2) has Finished claim, openssl (PUT1) doesn't.
    # Sub-buckets for specific OSSL errors are placed above this entry.
    # Catch-all for remaining wolfssl-finishes/OSSL-fails traces not matched above.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — DifferentClaimC((), Finished) is
    #   explicitly listed as acceptable in C1 table (Anti-pattern D exception).
    #   Catch-all position after 3 sub-buckets with more specific OSSL conditions;
    #   first-match-wins ensures sub-buckets take priority.
    "claim_finished_wolf_only/": DifferentClaimC(
        in_first_type="()", in_second_type="Finished"
    ),
    # 9,705 traces: openssl (PUT1) has Finished, wolfssl (PUT2) doesn't.
    # Pre-filter: traces where the harness itself failed to evaluate a term or
    # execute a function symbol for wolfssl. OSSL completed (Finished) before
    # the harness error, so DifferentClaimC fires. These are harness artifacts,
    # not genuine TLS protocol differences.
    # Note: placing this BEFORE claim_finished_ossl_only/ is required because
    # DifferentClaimC(Finished, ()) fires FIRST in the first-match-wins ordering;
    # function_eval_error/ at the end of the script would NEVER catch these.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — AllC(DifferentClaimC + AnyC(wolfssl
    #   harness StatusC pairs)); both harness error strings root-cause-grounded;
    #   first_to_fail=False reads per-PUT display-execute error (knowledge-diff style).
    # AUDITED [Audit 1 Pass 5]: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — corpus check: 1528×
    #   "executing a function symbol" + 607× "evaluating a term" = 2135/2135 (100%)
    #   wolfssl harness artifacts; 15/15 OSSL files have Finished claims; 0 TLS errors.
    "claim_finished_ossl_harness_artifact/": AllC(
        DifferentClaimC(in_first_type="Finished", in_second_type="()"),
        AnyC(
            StatusC(WOLF, in_error="error evaluating a term", first_to_fail=False),
            StatusC(WOLF, in_error="error executing a function symbol", first_to_fail=False),
        ),
    ),
    # 9,705 traces (before pre-filter): openssl (PUT1) has Finished, wolfssl (PUT2) doesn't.
    # Genuine TLS differential: wolfssl received messages but rejected them for
    # TLS-level reasons (Out of order message, malformed buffer input, unknown type
    # in record hdr, Bad ECC Peer Key, etc.). Harness-artifact traces are now
    # routed to claim_finished_ossl_harness_artifact/ above via first-match-wins.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 deferred — DifferentClaimC(Finished, ())
    #   is the correct catch-all for traces where OSSL completes (Finished) and
    #   wolfssl fails for genuine TLS reasons. Harness pre-filter above ensures
    #   harness artifacts are separated. Residual wolfssl error heterogeneity
    #   (Out of order / malformed / Bad ECC) is expected for a designed catch-all.
    # AUDITED [Audit 1 Pass 5]: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — wolfssl errors:
    #   record layer length 363, unknown type 316, malformed 277, Out of order 249,
    #   Sanity check ciphertext 203, Bad ECC 90, close notify 10, Decode 1;
    #   186/1696 wolfssl no error; 1/1696 (0.06%) harness artifact slippage (negligible).
    "claim_finished_ossl_only/": DifferentClaimC(
        in_first_type="Finished", in_second_type="()"
    ),

    # Sub-buckets for knowledge_msg_ossl_vs_none_wolf: OSSL has MessagePayload
    # knowledge but wolfssl has unit, combined with specific OSSL error fingerprints.
    # Covers the top 7 OSSL error sub-populations (~79% of the bucket).
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC:
    #   KnowledgeDiffC(MessagePayload, ()) + StatusC(OSSL,
    #   "tls_process_client_certificate:ASN1 lib"); both conditions root-cause-grounded;
    #   specific OSSL error function narrows root cause; 12,048 traces.
    "knowledge_msg_ossl_asn1_lib/": AllC(
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
        StatusC(OSSL, in_error="tls_process_client_certificate:ASN1 lib", first_to_fail=False),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC:
    #   KnowledgeDiffC(MessagePayload, ()) + StatusC(OSSL,
    #   "final_key_share:no suitable key share"); both root-cause-grounded.
    "knowledge_msg_ossl_final_key_share/": AllC(
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
        StatusC(OSSL, in_error="final_key_share:no suitable key share", first_to_fail=False),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC:
    #   KnowledgeDiffC(MessagePayload, ()) + AnyC(StatusC OSSL wrong/unknown cipher);
    #   both root-cause-grounded; specific OSSL cipher error narrows cause.
    "knowledge_msg_ossl_wrong_cipher/": AllC(
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::alert::AlertMessagePayload", "()"),
        AnyC(
            StatusC(OSSL, in_error="set_client_ciphersuite:wrong cipher returned", first_to_fail=False),
            StatusC(OSSL, in_error="set_client_ciphersuite:unknown cipher returned", first_to_fail=False),
        ),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC:
    #   KnowledgeDiffC(MessagePayload, ()) + StatusC(OSSL,
    #   "final_sig_algs:missing sigalgs extension"); both root-cause-grounded.
    "knowledge_msg_ossl_missing_sigalgs/": AllC(
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
        StatusC(OSSL, in_error="final_sig_algs:missing sigalgs extension", first_to_fail=False),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC:
    #   KnowledgeDiffC(MessagePayload, ()) + StatusC(OSSL,
    #   "ssl_cache_cipherlist:no ciphers specified"); both root-cause-grounded.
    "knowledge_msg_ossl_no_ciphers/": AllC(
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
        StatusC(OSSL, in_error="ssl_cache_cipherlist:no ciphers specified", first_to_fail=False),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC:
    #   KnowledgeDiffC(MessagePayload, ()) + StatusC(OSSL,
    #   "tls_get_message_header:bad change cipher spec"); both root-cause-grounded.
    "knowledge_msg_ossl_bad_ccs/": AllC(
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
        StatusC(OSSL, in_error="tls_get_message_header:bad change cipher spec", first_to_fail=False),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC:
    #   KnowledgeDiffC(MessagePayload, ()) + StatusC(OSSL,
    #   "tls_early_post_process_client_hello:no shared cipher"); both root-cause-grounded.
    "knowledge_msg_ossl_no_shared_cipher/": AllC(
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
        StatusC(OSSL, in_error="tls_early_post_process_client_hello:no shared cipher", first_to_fail=False),
    ),
    # --------------------------------------------------------------------------
    # BENIGN — MessagePayload knowledge differences
    # One PUT received/generated a message payload that the other PUT did not see.
    # These are the highest-volume patterns in the corpus (~102K + ~21K traces).
    # --------------------------------------------------------------------------
    # OSSL has MessagePayload knowledge, wolfssl has unit — catch-all for OSSL error
    # patterns not covered by the 7 sub-buckets above. Covers the remaining ~21% of
    # the original bucket population across 22 distinct OSSL error patterns.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — AllC(KnowledgeDiffC + AnyC(22 specific
    #   OSSL StatusC conditions)); each OSSL error in the AnyC is root-cause-grounded.
    #   Error frequency distribution validated against 14,440 traces: top error
    #   ssl3_read_bytes:unexpected message covers 56% (8,061), followed by
    #   tls_process_server_hello:bad extension 9% (1,268),
    #   tls_process_client_certificate:invalid context 8% (1,118), etc.
    #   AnyC covers ≥99% of the observed residual population.
    # AUDITED [Audit 1 Pass 4]: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — 15/15 sampled OSSL
    #   errors match AnyC conditions; 0 harness pollution; 0 unclassified errors.
    #   Anti-pattern A resolved by AnyC(22 specific OSSL StatusC).
    "knowledge_msg_ossl_vs_none_wolf/": AllC(
        KnowledgeDiffC("tlspuffin::tls::rustls::msgs::message::MessagePayload", "()"),
        AnyC(
            StatusC(OSSL, in_error="ssl3_read_bytes:unexpected message", first_to_fail=False),
            StatusC(OSSL, in_error="tls_process_server_hello:bad extension", first_to_fail=False),
            StatusC(OSSL, in_error="tls_process_client_certificate:invalid context", first_to_fail=False),
            StatusC(OSSL, in_error="tls_get_more_records:packet length too long", first_to_fail=False),
            StatusC(OSSL, in_error="tls_parse_ctos_sig_algs:bad extension", first_to_fail=False),
            StatusC(OSSL, in_error="tls_parse_ctos_key_share:bad key share", first_to_fail=False),
            StatusC(OSSL, in_error="ssl3_read_bytes:unexpected record", first_to_fail=False),
            StatusC(OSSL, in_error="tls_early_post_process_client_hello:unsupported protocol", first_to_fail=False),
            StatusC(OSSL, in_error="tls_process_server_hello:unexpected message", first_to_fail=False),
            StatusC(OSSL, in_error="tls_parse_ctos_key_share:bad ecpoint", first_to_fail=False),
            StatusC(OSSL, in_error="tls_choose_sigalg:no suitable signature algorithm", first_to_fail=False),
            StatusC(OSSL, in_error="tls_parse_stoc_key_share:bad key share", first_to_fail=False),
            StatusC(OSSL, in_error="tls_validate_record_header:data length too long", first_to_fail=False),
            StatusC(OSSL, in_error="tls_early_post_process_client_hello:not on record boundary", first_to_fail=False),
            StatusC(OSSL, in_error="tls_parse_stoc_key_share:length mismatch", first_to_fail=False),
            StatusC(OSSL, in_error="tls_process_as_hello_retry_request:no change following hrr", first_to_fail=False),
            StatusC(OSSL, in_error="ssl_choose_client_version:wrong ssl version", first_to_fail=False),
            StatusC(OSSL, in_error="tls_parse_ctos_early_data:bad extension", first_to_fail=False),
            StatusC(OSSL, in_error="tls_parse_ctos_key_share:length mismatch", first_to_fail=False),
            StatusC(OSSL, in_error="final_renegotiate:unsafe legacy renegotiation disabled", first_to_fail=False),
            StatusC(OSSL, in_error="tls1_cipher:internal error", first_to_fail=False),
            StatusC(OSSL, in_error="ssl_choose_client_version:unsupported protocol", first_to_fail=False),
        ),
    ),
    # wolfssl has MessagePayload knowledge, OSSL has unit. The dominant OSSL
    # pattern is version-negotiation failure: OSSL rejects the trace's TLS
    # version as unsupported while wolfssl processes the message normally.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — AllC(KnowledgeDiffC("()", MessagePayload)
    #   + AnyC(StatusC OSSL unsupported protocol variants)); covers ~32% of the
    #   bucket population. OSSL error strings are root-cause-grounded (version
    #   negotiation failure at the pre-client-hello or server-hello layer).
    # AUDITED [Audit 1 Pass 4]: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — 15/15 sampled OSSL
    #   errors: OSSL version-negotiation failures (unsupported protocol / wrong ssl
    #   version). Single root cause. No harness pollution.
    "knowledge_none_ossl_unsupported_proto/": AllC(
        KnowledgeDiffC("()", "tlspuffin::tls::rustls::msgs::message::MessagePayload"),
        AnyC(
            StatusC(OSSL, in_error="tls_early_post_process_client_hello:unsupported protocol", first_to_fail=False),
            StatusC(OSSL, in_error="ssl_choose_client_version:unsupported protocol", first_to_fail=False),
            StatusC(OSSL, in_error="ssl_choose_client_version:wrong ssl version", first_to_fail=False),
        ),
    ),
    # wolfssl has MessagePayload knowledge, OSSL has unit — residual catch-all
    # after the unsupported-protocol sub-bucket above. Harness artifact traces
    # (15/15 in Audit 1 Pass 4 sample: error evaluating a term, error executing
    # a function symbol) are excluded by NotC and routed to function_eval_error/
    # at the end of the script. Residual is genuine knowledge-diff traces where
    # wolfssl receives/processes a message OSSL did not.
    # Option A (NotC harness filter) applied per Pass 4 REVISION NEEDED.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 deferred (pending re-run to confirm
    #   residual population is non-empty and genuinely TLS-differential).
    # AUDITED [Audit 1 Pass 5]: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — 398/667 (59.7%) both
    #   PUTs complete with no error (pure knowledge-diff); OSSL errors: wrong sig type
    #   124, not on record boundary 92, no change following HRR 53; wolfssl errors:
    #   malformed buffer 134, record layer version 108, Out of order 12; 0 harness
    #   artifacts (NotC filter confirmed). Optional future: sub-bucket OSSL errors.
    "knowledge_none_vs_msg_wolf/": AllC(
        KnowledgeDiffC("()", "tlspuffin::tls::rustls::msgs::message::MessagePayload"),
        NotC(AnyC(
            StatusC(OSSL, in_error="error evaluating a term", first_to_fail=False),
            StatusC(OSSL, in_error="error executing a function symbol", first_to_fail=False),
            StatusC(WOLF, in_error="error evaluating a term", first_to_fail=False),
            StatusC(WOLF, in_error="error executing a function symbol", first_to_fail=False),
        )),
    ),

    # --------------------------------------------------------------------------
    # BENIGN — wolfssl-specific status errors (loose bootstrap conditions)
    # Each wolfssl error string is given its own bucket.  Phase 2 will tighten
    # these with multi-condition criteria.
    # --------------------------------------------------------------------------
    # 304,847 traces: wolfssl rejects a record with bad length.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "record layer
    #   length error"); wolfssl-only error constraint; consistent wolfssl error
    #   function across traces; OSSL variation irrelevant.
    "wolf_record_layer_length_error/": StatusC(
        WOLF, in_error="record layer length error", first_to_fail=False
    ),
    # 119,651 traces: wolfssl receives close_notify unexpectedly.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "peer sent
    #   close notify alert"); wolfssl-only error constraint; consistent.
    "wolf_peer_close_notify/": StatusC(
        WOLF, in_error="peer sent close notify alert", first_to_fail=False
    ),
    # 81,466 traces: wolfssl rejects a bad record-layer version field.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "record layer
    #   version error"); wolfssl-only error constraint; consistent.
    "wolf_record_layer_version_error/": StatusC(
        WOLF, in_error="record layer version error", first_to_fail=False
    ),
    # Sub-buckets for wolf_sanity_check_message_order: wolfssl "Sanity Check on
    # message order Error" combined with specific OSSL co-error fingerprints.
    # Covers the top 4 OSSL co-error sub-populations (~52% of the bucket).
    # Reported: wolfssl/wolfssl#9331 (closed) — RFC 8446 violation: wolfssl accepts
    #   HelloRetryRequest with a changing cipher suite across HRR and ServerHello.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC: StatusC(WOLF,
    #   "Sanity Check on message order Error") + AnyC(StatusC OSSL wrong/unknown cipher);
    #   both conditions root-cause-grounded; specific OSSL cipher co-error narrows cause.
    "wolf_sanity_ossl_wrong_cipher/": AllC(
        StatusC(WOLF, in_error="Sanity Check on message order Error", first_to_fail=False),
        AnyC(
            StatusC(OSSL, in_error="set_client_ciphersuite:wrong cipher returned", first_to_fail=False),
            StatusC(OSSL, in_error="set_client_ciphersuite:unknown cipher returned", first_to_fail=False),
        ),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC: StatusC(WOLF,
    #   "Sanity Check on message order Error") + StatusC(OSSL,
    #   "tls_process_as_hello_retry_request:no change following hrr"); both root-cause-grounded.
    # Reported: wolfssl/wolfssl#9240 (closed) — RFC 8446 violation: wolfssl sends an
    #   identical ClientHello after receiving a HelloRetryRequest (no key_share update).
    "wolf_sanity_ossl_hrr_no_change/": AllC(
        StatusC(WOLF, in_error="Sanity Check on message order Error", first_to_fail=False),
        StatusC(OSSL, in_error="tls_process_as_hello_retry_request:no change following hrr", first_to_fail=False),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC: StatusC(WOLF,
    #   "Sanity Check on message order Error") + AnyC(StatusC OSSL renegotiate mismatch
    #   client|server); both conditions root-cause-grounded; specific OSSL renegotiation
    #   co-error narrows cause.
    "wolf_sanity_ossl_renegotiation/": AllC(
        StatusC(WOLF, in_error="Sanity Check on message order Error", first_to_fail=False),
        AnyC(
            StatusC(OSSL, in_error="tls_parse_ctos_renegotiate:renegotiation mismatch", first_to_fail=False),
            StatusC(OSSL, in_error="tls_parse_stoc_renegotiate:renegotiation mismatch", first_to_fail=False),
        ),
    ),
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — multi-condition AllC: StatusC(WOLF,
    #   "Sanity Check on message order Error") + StatusC(OSSL,
    #   "tls_choose_sigalg:no suitable signature algorithm"); both root-cause-grounded.
    "wolf_sanity_ossl_sigalg/": AllC(
        StatusC(WOLF, in_error="Sanity Check on message order Error", first_to_fail=False),
        StatusC(OSSL, in_error="tls_choose_sigalg:no suitable signature algorithm", first_to_fail=False),
    ),

    # wolfssl state machine receives a message in wrong order — catch-all for traces
    # not captured by the 4 specific sub-buckets above. These are lower-frequency
    # OSSL co-error patterns or cases where OSSL does not return an error.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Sanity Check on
    #   message order Error"); catch-all after 4 specific multi-condition sub-buckets;
    #   wolfssl error consistent; OSSL variation irrelevant for this bucket.
    "wolf_sanity_check_message_order/": StatusC(
        WOLF, in_error="Sanity Check on message order Error", first_to_fail=False
    ),
    # 31,185 traces: wolfssl out-of-order message (fatal variant).
    # Reported: wolfssl/wolfssl#9531 (closed) — RFC 8446 violation: wolfssl does not
    #   send an Alert when receiving an encrypted out-of-order handshake message.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Out of order
    #   message, fatal"); wolfssl-only error constraint; consistent.
    "wolf_out_of_order_message/": StatusC(
        WOLF, in_error="Out of order message, fatal", first_to_fail=False
    ),
    # 22,880 traces: wolfssl detects a duplicate handshake message.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Duplicate
    #   HandShake message Error"); wolfssl-only constraint; consistent.
    "wolf_duplicate_handshake/": StatusC(
        WOLF, in_error="Duplicate HandShake message Error", first_to_fail=False
    ),
    # 16,970 traces: wolfssl AES-GCM authentication tag check failure.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "AES-GCM
    #   Authentication check fail"); wolfssl-only constraint; consistent.
    "wolf_aes_gcm_auth_fail/": StatusC(
        WOLF, in_error="AES-GCM Authentication check fail", first_to_fail=False
    ),
    # 6,631 traces: wolfssl sees an unknown record content type.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "unknown type
    #   in record hdr"); wolfssl-only constraint; consistent.
    "wolf_unknown_type_record_hdr/": StatusC(
        WOLF, in_error="unknown type in record hdr", first_to_fail=False
    ),
    # 6,220 traces: wolfssl certificate verification failure.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "certificate
    #   verify failed"); wolfssl-only constraint; consistent. (Note: the more specific
    #   bad_signature_wolf/ bucket above captures the AllC-constrained subset.)
    "wolf_certificate_verify_failed/": StatusC(
        WOLF, in_error="certificate verify failed", first_to_fail=False
    ),
    # 4,903 traces: wolfssl handshake message exceeds size limit.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Handshake
    #   message too large Error"); wolfssl-only constraint; consistent.
    "wolf_handshake_msg_too_large/": StatusC(
        WOLF, in_error="Handshake message too large Error", first_to_fail=False
    ),
    # 4,454 traces: wolfssl session ticket size error.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Bad session
    #   ticket message Size Error"); wolfssl-only constraint; consistent.
    "wolf_bad_session_ticket/": StatusC(
        WOLF, in_error="Bad session ticket message Size Error", first_to_fail=False
    ),
    # 3,616 traces: wolfssl rejects a bad ECC peer key.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Bad ECC Peer
    #   Key"); wolfssl-only constraint; consistent.
    "wolf_bad_ecc_peer_key/": StatusC(
        WOLF, in_error="Bad ECC Peer Key", first_to_fail=False
    ),
    # 2,103 traces: wolfssl fatal I/O error at the TLS layer.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "fatal I/O
    #   error in TLS layer"); wolfssl-only constraint; consistent.
    "wolf_fatal_io_error/": StatusC(
        WOLF, in_error="fatal I/O error in TLS layer", first_to_fail=False
    ),
    # 1,526 traces: wolfssl detects a duplicate TLS extension.
    # Reported: wolfssl/wolfssl#9520 (closed) — RFC 8446 violation: wolfssl does not
    #   send an Alert when receiving a ServerHello with duplicate extensions.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Duplicate TLS
    #   extension in message."); wolfssl-only constraint; consistent.
    "wolf_duplicate_tls_extension/": StatusC(
        WOLF, in_error="Duplicate TLS extension in message.", first_to_fail=False
    ),
    # 829 traces: wolfssl malformed buffer input.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "malformed
    #   buffer input error"); wolfssl-only constraint; consistent.
    "wolf_malformed_buffer/": StatusC(
        WOLF, in_error="malformed buffer input error", first_to_fail=False
    ),
    # 611 traces: wolfssl header parse error.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "parse error
    #   on header"); wolfssl-only constraint; consistent.
    "wolf_parse_error_header/": StatusC(
        WOLF, in_error="parse error on header", first_to_fail=False
    ),
    # 421 traces: wolfssl security parameter invalid.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "The security
    #   parameter is invalid"); wolfssl-only constraint; consistent.
    "wolf_security_param_invalid/": StatusC(
        WOLF, in_error="The security parameter is invalid", first_to_fail=False
    ),
    # 294 traces: wolfssl decode handshake message error.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Decode
    #   handshake message error"); wolfssl-only constraint; consistent.
    "wolf_decode_handshake_error/": StatusC(
        WOLF, in_error="Decode handshake message error", first_to_fail=False
    ),
    # 44 traces: wolfssl ciphertext sanity check failure.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(WOLF, "Sanity check
    #   on ciphertext failed"); wolfssl-only constraint; consistent.
    "wolf_sanity_ciphertext_failed/": StatusC(
        WOLF, in_error="Sanity check on ciphertext failed", first_to_fail=False
    ),

    # --------------------------------------------------------------------------
    # BENIGN — Additional OSSL-side status errors (residual patterns from
    # Phase 0.5 bootstrap pass + Phase 1 refinement)
    # --------------------------------------------------------------------------

    # BENIGN: catch-all for tls_parse_ctos_key_share errors NOT captured by
    # the specific tls_parse_ctos_key_share_bad (requires fn_key_share_deterministic_extension)
    # or tls_parse_ctos_key_share_missing_groups buckets above.
    # Covers "bad key share" (13K traces), "bad ecpoint" (572), and other sub-variants.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "tls_parse_ctos_key_share:"); catch-all after two specific multi-condition
    #   sub-buckets; OSSL error prefix names the specific function family.
    "tls_parse_ctos_key_share_bad_catch_all/": StatusC(
        OSSL, in_error="tls_parse_ctos_key_share:", first_to_fail=False
    ),

    # BENIGN: OpenSSL rejects the protocol version negotiated in
    # tls_early_post_process_client_hello. Covers "unsupported protocol" (3K),
    # "bad cipher" (58), and other sub-variants.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "tls_early_post_process_client_hello:"); function prefix names the specific
    #   OSSL processing stage; OSSL-only constraint.
    "tls_early_post_process_unsupported/": StatusC(
        OSSL, in_error="tls_early_post_process_client_hello:", first_to_fail=False
    ),

    # BENIGN: OpenSSL client rejects a bad extension in the ServerHello.
    # Covers "bad extension" (2.2K). Different from tls_process_server_hello_bad_length
    # and tls_process_server_hello_invalid_ossl which have distinct conditions.
    # Reported: wolfssl/wolfssl#9229 (closed) — RFC 8446 violation: wolfssl accepts
    #   incorrect/unknown extensions in the ServerHello.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "tls_process_server_hello:bad extension"); specific named OSSL error.
    "tls_process_server_hello_bad_ext_ossl/": StatusC(
        OSSL, in_error="tls_process_server_hello:bad extension", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails TLS 1.2 ECDHE server/client key exchange processing.
    # Covers tls_process_cke_ecdhe:EC lib (608) and tls_process_ske_ecdhe:wrong curve (292).
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — AnyC(StatusC OSSL tls_process_cke_ecdhe:|
    #   tls_process_ske_ecdhe:); specific named OSSL functions; all root-cause-grounded.
    "tls_process_ecdhe_ossl/": AnyC(
        StatusC(OSSL, in_error="tls_process_cke_ecdhe:", first_to_fail=False),
        StatusC(OSSL, in_error="tls_process_ske_ecdhe:", first_to_fail=False),
    ),

    # BENIGN: OpenSSL client fails parsing a ServerHello key_share extension.
    # Covers "bad key share" (560), "length mismatch" (56), "bad ecpoint" (12).
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "tls_parse_stoc_key_share:"); specific named OSSL function family.
    "tls_parse_stoc_key_share_ossl/": StatusC(
        OSSL, in_error="tls_parse_stoc_key_share:", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails in final_key_share negotiation (no suitable key share).
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL, "final_key_share:");
    #   specific named OSSL function; OSSL-only constraint.
    "final_key_share_ossl/": StatusC(
        OSSL, in_error="final_key_share:", first_to_fail=False
    ),

    # BENIGN: OpenSSL ssl_choose_client_version fails with wrong ssl version.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "ssl_choose_client_version:"); specific named OSSL function; OSSL-only constraint.
    "ssl_choose_client_version_ossl/": StatusC(
        OSSL, in_error="ssl_choose_client_version:", first_to_fail=False
    ),

    # BENIGN: OpenSSL HRR handler rejects ClientHello2 that is identical to
    # ClientHello1 — "no change following hrr". Wolfssl may succeed or fail
    # differently (BENIGN: OSSL enforces HRR non-repetition guard).
    # Reported: wolfssl/wolfssl#9240 (closed) — RFC 8446 violation: wolfssl sends an
    #   identical ClientHello after receiving a HelloRetryRequest (no key_share update).
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "tls_process_as_hello_retry_request:no change following hrr"); specific
    #   named OSSL error; OSSL-only constraint.
    "tls_process_hrr_no_change/": StatusC(
        OSSL,
        in_error="tls_process_as_hello_retry_request:no change following hrr",
        first_to_fail=False,
    ),

    # BENIGN: OpenSSL client state-machine rejects a wrong cipher suite
    # returned in a ServerHello. Wolfssl may fail with "Bad KEA type" or
    # succeed at a later step.
    # Reported: wolfssl/wolfssl#9331 (closed) — RFC 8446 violation: wolfssl accepts
    #   HelloRetryRequest with a changing cipher suite across HRR and ServerHello.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "set_client_ciphersuite:wrong cipher returned"); specific named OSSL error.
    "set_client_ciphersuite_wrong_cipher/": StatusC(
        OSSL,
        in_error="set_client_ciphersuite:wrong cipher returned",
        first_to_fail=False,
    ),

    # BENIGN: OpenSSL rejects a renegotiation_info extension received in a
    # ServerHello (client-side parse). Wolfssl may react differently.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "tls_parse_stoc_renegotiate"); specific named OSSL function.
    "tls_parse_stoc_renegotiate_ossl/": StatusC(
        OSSL, in_error="tls_parse_stoc_renegotiate", first_to_fail=False
    ),

    # BENIGN: OpenSSL rejects a renegotiation_info extension received in a
    # ClientHello (server-side parse). Wolfssl may react differently.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "tls_parse_ctos_renegotiate"); specific named OSSL function.
    "tls_parse_ctos_renegotiate_ossl/": StatusC(
        OSSL, in_error="tls_parse_ctos_renegotiate", first_to_fail=False
    ),

    # BENIGN: OpenSSL fails signature-algorithm selection. Wolfssl may succeed
    # or fail with "wrong client/server type" or a different error.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "tls_choose_sigalg"); specific named OSSL function.
    "tls_choose_sigalg_ossl/": StatusC(
        OSSL, in_error="tls_choose_sigalg", first_to_fail=False
    ),

    # BENIGN: OpenSSL rejects the negotiated protocol version in
    # final_supported_versions check. Wolfssl may succeed or fail differently.
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — single StatusC(OSSL,
    #   "final_supported_versions"); specific named OSSL function.
    "final_supported_versions_ossl/": StatusC(
        OSSL, in_error="final_supported_versions", first_to_fail=False
    ),

    # BENIGN: Harness function evaluation errors from the tlspuffin rustls engine.
    # Placed last as a catch-all for harness errors not already classified by a
    # protocol-level bucket. "error evaluating a term" uses first_to_fail=False
    # so it also fires for knowledge-diff traces where the STATUS field is None.
    # NOTE: "error evaluating a term" with first_to_fail=False is deliberately
    # broad — placing this bucket last ensures protocol-level buckets take
    # priority. Known C4 issue: knowledge_none_vs_msg_wolf and claim_finished_ossl_only
    # contain harness-polluted traces that cannot be cleanly pre-filtered without
    # also intercepting legitimate protocol-level traces.
    #
    # Tag: BENIGN
    # AUDITED: C1 ✓ / C2 ✓ / C3 ✓ / C4 ✓ — intentional catch-all placed last;
    #   AnyC of 4 specific harness-error StatusC conditions; last-position in
    #   first-match-wins ordering guarantees protocol-level buckets take priority.
    #   C4 heterogeneity is documented and accepted for a catch-all bucket.
    "function_eval_error/": AnyC(
        StatusC(
            OSSL, in_error="error executing a function symbol", first_to_fail=False
        ),
        StatusC(
            WOLF, in_error="error executing a function symbol", first_to_fail=False
        ),
        StatusC(WOLF, in_error="error evaluating a term", first_to_fail=False),
        StatusC(OSSL, in_error="error evaluating a term", first_to_fail=False),
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
