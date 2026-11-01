#!/bin/bash

# This script is used to move all triaged files of the given objective folder
# to the objective folder, and then remove the empty buckets. This allows to run a
# triaging campaign from scratch when changing the triaging queries

folder="objective"

if [ "$#" -eq 1 ]; then
    folder="$1"
fi

WD=$(pwd)

for d in "$folder"/*; do
  if [ -d "$d" ];
    then
    cd "$d"
    pwd
    ls | xargs -L 2000 mv -t ..
    cd $WD
  fi;
done

find $folder -maxdepth 1 -type d | tail -n +2| xargs rmdir
