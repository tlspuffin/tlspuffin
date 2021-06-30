#!/bin/bash

tlspuffin="$(dirname "$0")/.."
rsync --delete --exclude 'tlspuffin-log.json' --progress -r "mammann@pesto-calc.loria.fr:/local-homes/mammann/tlspuffin/experiments/." "$tlspuffin/experiments-pesto/"
rsync --delete --exclude 'tlspuffin-log.json' --progress -r "max@cassis-calc.loria.fr:/home/max/tlspuffin/experiments/." "$tlspuffin/experiments-cassis/"