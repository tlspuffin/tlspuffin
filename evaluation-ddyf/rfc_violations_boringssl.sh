#!/bin/bash


OUTDIR=objective_ablation_study/

mkdir $OUTDIR

cp -r objective/ossl_ok_boring_unexpected_message $OUTDIR
cp -r objective/alert_illegal_param_ossl_vs_missing_ext_key_share $OUTDIR
cp -r objective/ossl_ok_boring_duplicate_key_share $OUTDIR
cp -r objective/ossl_ok_boring_unexpected_extension $OUTDIR
cp -r objective/alert_illegal_param_ossl_vs_missing_ext_supported_groups $OUTDIR
cp -r objective/ossl_ok_boring_parse_tlsext_error $OUTDIR
cp -r objective/ossl_ok_boring_unexpected_record $OUTDIR
cp -r objective/ossl_ok_boring_clienthello_parse_failed $OUTDIR
cp -r objective/ossl_ok_boring_digest_check_failed $OUTDIR
cp -r objective/ossl_ok_boring_no_common_sig_algs $OUTDIR
cp -r objective/ossl_ok_boring_too_much_early_data $OUTDIR
cp -r objective/ossl_ok_boring_decode_error_generic $OUTDIR
cp -r objective/alert_decode_error_ossl_vs_handshake_failure_boring $OUTDIR
cp -r objective/alert_illegal_param_ossl_vs_unsupported_ext_boring $OUTDIR
cp -r objective/alert_handshake_failure_ossl_vs_decode_error_boring $OUTDIR
cp -r objective/alert_missing_ext_ossl_vs_handshake_failure_boring $OUTDIR
cp -r objective/alert_handshake_failure_ossl_vs_unsupported_ext_boring $OUTDIR
cp -r objective/alert_missing_ext_ossl_vs_unsupported_ext_boring $OUTDIR
cp -r objective/alert_unexpected_msg_ossl_vs_illegal_param_boring $OUTDIR
cp -r objective/alert_unsupported_ext_ossl_vs_illegal_param_boring $OUTDIR
cp -r objective/alert_unsupported_ext_ossl_vs_decode_error_boring $OUTDIR
cp -r objective/alert_missing_ext_ossl_vs_illegal_param_boring $OUTDIR
