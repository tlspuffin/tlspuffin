#!/bin/bash

tlspuffin="$(dirname "$0")/.."

# --delete to delte files which have been removed from source
rsync --exclude 'tlspuffin.log' --progress -r "mammann@pesto-calc.loria.fr:/local-homes/mammann/tlspuffin/experiments/." "$tlspuffin/experiments-pesto/"
rsync --exclude 'tlspuffin.log' --progress -r "max@cassis-calc.loria.fr:/home/max/tlspuffin/experiments/." "$tlspuffin/experiments-cassis/"
