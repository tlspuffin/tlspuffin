#!/bin/bash


OUTDIR=objective_ablation_study/

mkdir $OUTDIR

cp -r objective/ossl_unsafe_legacy_renegotiation $OUTDIR
cp -r objective/ossl_missing_ext_libre_illegal_param $OUTDIR
cp -r objective/alert_handshake_failure_vs_missing_ext_reverse $OUTDIR
cp -r objective/alert_missing_ext_vs_illegal_param_reverse $OUTDIR
cp -r objective/libre_accepts_wrong_cipher_suite $OUTDIR
cp -r objective/ossl_truly_succeeds_libre_fails_tls13 $OUTDIR
cp -r objective/ossl_alert_silent_server_unexpected_msg $OUTDIR
cp -r objective/ossl_alert_silent_no_key_share $OUTDIR
cp -r objective/ossl_record_failure_libre_accepts $OUTDIR
cp -r objective/ossl_alert_silent_ecdh_error $OUTDIR
cp -r objective/ossl_alert_silent_client_unexpected_msg $OUTDIR
cp -r objective/ossl_alert_silent_hrr_key_share_length_mismatch $OUTDIR
cp -r objective/libre_bad_length_ossl_proceeds $OUTDIR
cp -r objective/libre_record_overflow_bypass $OUTDIR
cp -r objective/alert_missing_ext_vs_protocol_version $OUTDIR
cp -r objective/ossl_alert_silent_version_mismatch $OUTDIR
cp -r objective/ossl_alert_silent_hrr_key_share_bad_group $OUTDIR
cp -r objective/ossl_alert_silent_extension_error $OUTDIR
cp -r objective/libre_parse_tlsext_ossl_proceeds $OUTDIR
cp -r objective/ossl_alert_silent_hrr_no_change $OUTDIR
cp -r objective/ossl_alert_silent_unsupported_protocol $OUTDIR
cp -r objective/libre_v12_sh_v13_cipher_zero_keys $OUTDIR
cp -r objective/ossl_record_too_long_libre_proceeds $OUTDIR
cp -r objective/libre_finished_claim_silent_ossl $OUTDIR
cp -r objective/ossl_alert_silent_client_cert_req_length $OUTDIR
cp -r objective/ossl_alert_silent_excessive_msg_size $OUTDIR
cp -r objective/ossl_alert_silent_ctos_key_share_length $OUTDIR
cp -r objective/ossl_alert_silent_invalid_alert $OUTDIR
cp -r objective/ossl_alert_silent_stoc_ecpoint $OUTDIR
cp -r objective/ossl_alert_silent_client_cipher_select $OUTDIR
cp -r objective/ossl_alert_silent_missing_sigalgs $OUTDIR
cp -r objective/ossl_alert_silent_client_record_too_long $OUTDIR

