#!/bin/bash

crash_dir="./experiments/$1/crashes"
find "$crash_dir" -name "*.trace" -exec sh -c 'target/x86_64-unknown-linux-gnu/debug/tlspuffin plot --tree $1 svg $1.svg' _ {} \;

#cat crashes/*_all.svg > crashes/index.html
#xdg-open crashes/index.html
