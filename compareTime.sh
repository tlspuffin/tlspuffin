#!/bin/bash

find **/*ABLATION*/objective -not -empty -type d -prune | while read d; do
    echo "Treating folder: $d"
    df=$(ls $d | head -1);
    # echo "Found ${d}/${df}"
    # ls -lrth "${d}/${df}"

    date1=$(find "./${d}/../README.md" -printf "%TY-%Tm-%Td %TH:%TM:%TS\n")
    # ls -ldc $d
    date2=$(find "${d}/${df}" -printf "%TY-%Tm-%Td %TH:%TM:%TS\n")
    echo "Comparing $date1 with $date2"

    date1=$(find "./${d}/../README.md" -printf "%TY%Tm%Td%TH%TM%TS\n")
    # ls -ldc $d
    date2=$(find "${d}/${df}" -printf "%TY%Tm%Td%TH%TM%TS\n")
    dateutils.ddiff -i '%Y%m%d%H%M%S' $date1 $date2
done
