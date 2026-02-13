#!/bin/bash

folder="objective"

if [ "$#" -eq 1 ]; then
    folder="$1"
fi

total=$(find $folder -maxdepth 1 -type f -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?' | wc -l)

echo "non triaged : $total"

for d in $folder/*; do
  if [ -d "$d" ];
    then
    num=$(find $d -maxdepth 1 -type f -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?' | wc -l)
    total=$((total+num))
    echo "$d : $num";
  fi;
done

echo "total: $(($total))"
