#!/bin/bash

find ./crashes -name "*.trace" -exec sh -c 'target/x86_64-unknown-linux-gnu/debug/tlspuffin plot --tree $1 svg $1.svg' _ {} \;

#cat crashes/*_all.svg > crashes/index.html
#xdg-open crashes/index.html
