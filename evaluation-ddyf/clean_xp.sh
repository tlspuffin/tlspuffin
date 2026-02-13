#!/bin/bash

folder="objective"

if [ "$#" -eq 1 ]; then
    folder="$1"
fi

for d in $folder/*; do
  if [ -d "$d" ];
    then

    echo "Triaging objectives in $d/objective"
    python -m DDYF.find_known_cves $d/objective


    # removing traces that are not interesting to save disk space
    rm -rf $d/objective/trash
    rm -rf $d/corpus

  fi;
done


