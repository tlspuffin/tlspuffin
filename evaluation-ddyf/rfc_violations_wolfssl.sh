#!/usr/bin/env bash


OUTDIR=objective_ablation_study/

mkdir $OUTDIR

cp -r objective/wolf_sanity_ossl_hrr_no_change $OUTDIR
cp -r objective/tls_parse_ctos_key_share_missing_groups $OUTDIR
cp -r objective/wolf_sanity_ossl_wrong_cipher $OUTDIR
cp -r objective/tls_parse_ctos_key_share_bad $OUTDIR
cp -r objective/alert_unsupported_ext_ossl_vs_illegal_param_wolf $OUTDIR
cp -r objective/alert_missing_ext_ossl_vs_handshake_failure_wolf $OUTDIR
cp -r objective/wolf_duplicate_tls_extension $OUTDIR
cp -r objective/wolf_out_of_order_message $OUTDIR
cp -r objective/alert_illegal_param_ossl_vs_handshake_failure_wolf $OUTDIR
cp -r objective/alert_decode_error_ossl_vs_illegal_param_wolf $OUTDIR
cp -r objective/alert_protocol_version_ossl_vs_decode_error_wolf $OUTDIR
cp -r objective/alert_record_overflow_ossl_vs_wolf $OUTDIR
cp -r objective/alert_illegal_param_ossl_vs_unsupported_ext_wolf_bad_extension $OUTDIR
cp -r objective/tls13_hello_request $OUTDIR
cp -r objective/alert_illegal_param_ossl_vs_missing_ext_key_share $OUTDIR
cp -r objective/alert_missing_ext_ossl_vs_protocol_version_wolf $OUTDIR
