#!/bin/bash

folder="objective"
[ -e evaluation_ddyf ] || ln -s evaluation-ddyf evaluation_ddyf  # importable package name (see README)

if [ "$#" -eq 1 ]; then
    folder="$1"
fi

for d in $folder/*; do
  if [ -d "$d" ];
    then

    echo "Triaging objectives in $d/objective"
    python -m evaluation_ddyf.tls.find_known_cves $d/objective


    # removing traces that are not interesting to save disk space
    rm -rf $d/objective/trash
    rm -rf $d/corpus

  fi;
done


