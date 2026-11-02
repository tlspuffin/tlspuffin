#!/bin/bash


OUTDIR=objective_ablation_study/

mkdir $OUTDIR

cp -r objective/no_change_hrr $OUTDIR
cp -r objective/no_supported_groups_in_ch $OUTDIR
cp -r objective/hrr_changing_cipher $OUTDIR
cp -r objective/keyshare_not_requested_hrr $OUTDIR
cp -r objective/alert_unsupported_ext_illegal_param_server_psk $OUTDIR
cp -r objective/alert_missing_ext_handshake_failure $OUTDIR
cp -r objective/duplicate_ext_sh $OUTDIR
cp -r objective/encrypted_out_of_order $OUTDIR
cp -r objective/alert_illegalparameter_handshakefailure $OUTDIR
cp -r objective/alert_decodeerror_illegalparameter $OUTDIR
cp -r objective/alert_unsupported_ext_illegal_param_sh_status_request $OUTDIR
