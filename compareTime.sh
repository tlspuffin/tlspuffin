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

    LOG=$(cat "${d}/../stats.json" | awk '/"objective_size":1/ {
    match($0, /"objective_size":1/); print substr($0, RSTART - 0, RLENGTH + 200);
}')
    if [ -z "$LOG" ]
    then
	    LOG=$(cat "${d}/../stats.json" | awk '/"objective_size":2/ {
    match($0, /"objective_size":1/); print substr($0, RSTART - 0, RLENGTH + 200);
}')
    fi
#    echo "$LOG"
    total_execs=$(echo "$LOG" | grep -E -o '"total_execs":.{0,12}' | cut -c15- | cut -d, -f1)
    date_found=$(echo "$LOG" | grep -E -o '"secs_since_epoch":.{0,10}' | cut -c20- | head -c -0 |  sed  's/^/@/' | xargs date -d)
#    echo "$LOG"
    echo -n "  Total executions: "
    printf "%'.0f" $total_execs
    echo "      [at ${date_found}]"
done
