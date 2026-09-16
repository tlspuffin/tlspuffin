#!/bin/sh
# Run a command -- or an interactive shell -- inside the pre-built nix-shell.
#
# The shell is entered through its pre-instantiated derivation, so no nixpkgs
# evaluation (and therefore no network access) is needed at runtime.
#
# Everything here runs *outside* the nix-shell, in the bare image, so it must
# not rely on anything beyond shell built-ins and coreutils.
set -eu

# Single-quote one argument so that the shell re-parses it as a single word.
quote() {
    rest=$1
    done_=""

    while :; do
        case ${rest} in
            *\'*)
                done_="${done_}${rest%%\'*}'\\''"
                rest=${rest#*\'}
                ;;
            *)
                break
                ;;
        esac
    done

    printf "'%s'" "${done_}${rest}"
}

drv=$(cat "${DDYF_ENV_DIR:-/opt/ddyf-env}/shell.drv")

if [ "$#" -eq 0 ]; then
    exec nix-shell "${drv}"
fi

# `nix-shell --run` takes a single command string: re-quote the arguments.
cmd=""
for arg in "$@"; do
    cmd="${cmd} $(quote "${arg}")"
done

exec nix-shell "${drv}" --run "${cmd}"
