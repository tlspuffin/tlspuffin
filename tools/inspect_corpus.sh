#!/bin/bash

find corpus_inspection -name "*.trace" -exec target/debug/tlspuffin plot --tree {} svg {}.svg \;
cat corpus_inspection/*_all.svg > corpus_inspection.html
xdg-open corpus_inspection.html
