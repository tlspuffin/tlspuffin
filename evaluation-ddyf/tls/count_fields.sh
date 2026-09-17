#!/bin/bash

# Use ast-grep to count all rustls struct/enum fields and those who are ignored

scriptDir=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")

types=$(ast-grep scan -r $scriptDir/count_tls_types.yml  -C 100 --report-style medium  tlspuffin/src/tls | wc -l)
all=$(ast-grep scan -r $scriptDir/count_tls_fields.yml  -C 100 --report-style medium  tlspuffin/src/tls | wc -l)
ignored=$(ast-grep scan -r $scriptDir/count_tls_ignored_fields.yml  -C 100 --report-style medium  tlspuffin/src/tls | wc -l)

echo "Number of TLS types: $types"
echo "Number of TLS struct fields: $all"
echo "Number of ignored TLS struct fields: $ignored"
