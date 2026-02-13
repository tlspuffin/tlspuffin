#!/bin/bash

folder="objective"

if [ "$#" -eq 1 ]; then
    folder="$1"
fi

WD=$(pwd)

for d in $folder/*; do
  if [ -d "$d" ];
    then
    cd $d
    pwd
    ls | xargs -L 2000 mv -t ..
    cd $WD
  fi;
done

find $folder -maxdepth 1 -type d | tail -n +2| xargs rmdir

