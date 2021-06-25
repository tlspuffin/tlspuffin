#!/bin/bash

tlspuffin="$(dirname "$0")/.."
rsync --progress -r "mammann@pesto-calc.loria.fr:/local-homes/mammann/tlspuffin/experiments" "$tlspuffin"
