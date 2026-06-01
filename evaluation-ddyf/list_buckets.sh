#!/bin/bash

# This script is used to list the number of triaged files in each bucket of the
# given objective folder, and the total number of triaged files. This allows to
# have an overview of the triaging campaign progress, and to identify how many
# objectives are still to be triaged

folder="objective"

if [ "$#" -eq 1 ]; then
    folder="$1"
fi

local total=$(find "$folder" -maxdepth 1 -type f -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?' | wc -l)

echo "non triaged : $total"

for d in "$folder"/*; do
  if [ -d "$d" ];
    then
    local num=$(find "$d" -maxdepth 1 -type f -regextype posix-egrep -regex '.*\.trace(-[0-9]+)?' | wc -l)
    total=$((total+num))
    echo "$d : $num";
  fi;
done

echo "total: $(($total))"
