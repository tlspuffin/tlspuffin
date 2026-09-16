#!/usr/bin/env bash


OUTDIR=objective_ablation_study/

mkdir $OUTDIR

cp -r objective/alert_missing_ext_ossl_vs_handshake_failure_boring $OUTDIR
cp -r objective/alert_illegal_param_ossl_vs_unsupported_ext_boring $OUTDIR
cp -r objective/tls13_hello_request $OUTDIR
cp -r objective/alert_illegal_param_ossl_vs_missing_ext_key_share $OUTDIR
cp -r objective/tls12_renegotiation_info_boring_ok $OUTDIR
