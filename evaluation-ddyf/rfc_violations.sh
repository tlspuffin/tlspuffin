#!/bin/bash


OUTDIR=objective_ablation_study/

mkdir $OUTDIR

cp -r seeds/no_change_hrr $OUTDIR
cp -r seeds/no_supported_groups_in_ch $OUTDIR
cp -r seeds/hrr_changing_cipher $OUTDIR
cp -r seeds/keyshare_not_requested_hrr $OUTDIR
cp -r seeds/alert_unsupported_ext_illegal_param_server_psk $OUTDIR
cp -r seeds/alert_missing_ext_handshake_failure $OUTDIR
cp -r seeds/duplicate_ext_sh $OUTDIR
cp -r seeds/encrypted_out_of_order $OUTDIR
cp -r seeds/alert_illegalparameter_handshakefailure $OUTDIR
cp -r seeds/alert_decodeerror_illegalparameter $OUTDIR
cp -r seeds/alert_unsupported_ext_illegal_param_sh_status_request $OUTDIR
