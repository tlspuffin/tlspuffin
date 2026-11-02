#!/bin/bash

folder="experiments"

result_file="cve_list.csv"

rm $result_file
echo "Campaign name,CVE,Date,Trace name" >> $result_file

for exp in $folder/*; do
    # iterate over the experience folder
        echo "Experience : $exp"
        total=$(find $exp/objective -maxdepth 1 -type f -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?' | wc -l)

        echo "non triaged : $total"
        campaign=$(basename $exp)
        for d in $exp/objective/*; do
            #iterate over the CVE folders
          if [ -d "$d" ];
            then
            cve=$(basename $d)
            num=0
            for f in $(find $d -maxdepth 1 -type f -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?');
            do
                # list all traces and time found
                trace_name=$(basename $f)
                date=$(ls -lah --time-style +'%Y-%m-%d_%H-%M-%S' $f| grep -oP '([0-9]{4})-([0-9]{2})-([0-9]{2})_([0-9]{2})-([0-9]{2})-([0-9]{2})')

                echo "$campaign,$cve,$date,$trace_name" >> $result_file
                num=$((num+1))
            done
            echo "$d : $num";
          fi;
        done
done
