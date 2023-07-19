#!/bin/bash

find **/*ABLATION*/objective -not -empty -type d -prune | while read d; do
    echo "Treating folder: $d"
    df=$(ls $d | head -1);
    # echo "Found ${d}/${df}"
    # ls -lrth "${d}/${df}"

    date1=$(find "./${d}/../README.md" -printf "%TY-%Tm-%Td %TH:%TM:%TS\n")
    # ls -ldc $d
    date2=$(find "${d}/${df}" -printf "%TY-%Tm-%Td %TH:%TM:%TS\n")
#    echo "Comparing $date1 with $date2"

    date1=$(find "./${d}/../README.md" -printf "%TY%Tm%Td%TH%TM%TS\n")
    # ls -ldc $d
    date2=$(find "${d}/${df}" -printf "%TY%Tm%Td%TH%TM%TS\n")
    diffDate=$(dateutils.ddiff -i '%Y%m%d%H%M%S' $date1 $date2 | cut -ds -f1)
    echo -n "  Elapsed seconds: "
    printf "%'.0f\n" $diffDate
    
    total_execs=$(cat "${d}/../stats.json" | grep -E -o '"objective_size":1.{0,100}' | head -n 1 |  grep -E -o '"total_execs":.{0,12}' | cut -c15- | cut -d, -f1)
    echo -n "  Total executions: "
    printf "%'.0f\n" $total_execs
done
