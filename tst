#!/usr/bin/env bash
set -euo pipefail

# Résout les symlinks pour retrouver le fichier réel.
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)"
if [[ -z "${SCRIPT_PATH}" ]]; then
  # Fallback si readlink -f n'est pas dispo (rare sur Linux, mais bon).
  SCRIPT_PATH="${BASH_SOURCE[0]}"
fi

ROOT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
SELF_NAME="$(basename "$0")"

# If `just` is not available, re-run *this* command inside nix-shell (for every command).
# Avoid infinite recursion by relying on IN_NIX_SHELL set by nix.
if ! command -v just >/dev/null 2>&1; then
  if [[ -z "${IN_NIX_SHELL:-}" ]]; then
    cmd=( "${SELF_NAME}" "$@" )
    printf -v run_str '%q ' "${cmd[@]}"
    exec nix-shell --run "${run_str}"
  fi
fi

usage() {
  cat <<EOF
Usage:
  ${SELF_NAME} [--help]
  ${SELF_NAME} clean
  ${SELF_NAME} target [prog] [-a] [--help]
  ${SELF_NAME} build
  ${SELF_NAME} seeds
  ${SELF_NAME} fuzz [prog] [-a] [--help]
  ${SELF_NAME} just
  ${SELF_NAME} fmt
  ${SELF_NAME} c <crate>
  ${SELF_NAME} jt

prog (target/fuzz):
  open | wolf | libre | boring

crate (c):
  puffin | security-claims | tlspuffin | sshpuffin

Notes:
  - Pour 'target' et 'fuzz': l'option -a n'est autorisée que si prog est fourni.
  - Sans -a, on ajoute automatiquement le suffixe '-asan' au progvalue.
EOF
}

die() {
  echo "error: $*" >&2
  echo "hint: ${SELF_NAME} --help" >&2
  exit 2
}

warn() {
  echo "warning: $*" >&2
}

preflight_exec() {
  # Affiche la commande (avec quoting) puis exec.
  # Usage: preflight_exec <prog> [args...]
  if [[ $# -lt 1 ]]; then
    die "erreur interne: preflight_exec sans programme"
  fi
  printf '[tst] exec:' >&2
  local arg
  for arg in "$@"; do
    printf ' %q' "${arg}" >&2
  done
  printf '\n' >&2
  exec "$@"
}

require_file() {
  local path="$1"
  local what="$2"
  if [[ ! -e "${path}" ]]; then
    die "${what} introuvable: ${path}"
  fi
}

require_exec() {
  local path="$1"
  local what="$2"
  require_file "${path}" "${what}"
  if [[ ! -x "${path}" ]]; then
    die "${what} n'est pas exécutable: ${path} (faites: chmod +x ${path})"
  fi
}

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    die "commande requise introuvable dans le PATH: ${cmd}"
  fi
}

# For `target`: with prefix and ':' (openssl:openssl312, etc.)
map_target_progvalue() {
  local prog="$1"
  case "$prog" in
    open)   echo "openssl:openssl312" ;;
    wolf)   echo "wolfssl:wolfssl510" ;;
    libre)  echo "libressl:libressl333" ;;
    boring) echo "boringssl:boringssl202311" ;;
    *) die "prog inconnu: '$prog' (attendu: open|wolf|libre|boring)" ;;
  esac
}

# For `fuzz`: without prefix (openssl312, etc.)
map_fuzz_progvalue() {
  local prog="$1"
  case "$prog" in
    open)   echo "openssl312" ;;
    wolf)   echo "wolfssl510" ;;
    libre)  echo "libressl333" ;;
    boring) echo "boringssl202311" ;;
    *) die "prog inconnu: '$prog' (attendu: open|wolf|libre|boring)" ;;
  esac
}

# Rule requested:
# - "-a" only valid if prog is defined
# - if "-a" NOT present => append "-asan" (no space)
# - if "-a" present     => keep progvalue as-is
apply_asan_rule() {
  local progvalue="$1"
  local a_present="$2" # "yes" or "no"
  if [[ "${a_present}" == "yes" ]]; then
    echo "${progvalue}"
  else
    echo "${progvalue}-asan"
  fi
}

# ---- global help
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || "${1:-}" == "help" ]]; then
  usage
  exit 0
fi

method="${1:-}"
shift || true

case "${method}" in
  "")
    die "aucune commande fournie"
    ;;

  clean)
    if [[ $# -ne 0 ]]; then
      die "clean ne prend pas d'arguments (reçu: $*)"
    fi
    cd "${ROOT_DIR}"
    rm -rf target vendor seeds objective experiments corpus
    ;;

  target)
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
      usage
      exit 0
    fi

    # Default prog is "open". `-a` is allowed even if prog isn't provided.
    prog="open"
    prog_set="no"
    a_present="no"

    # Accept (order-independent):
    #   tst target
    #   tst target <prog>
    #   tst target -a
    #   tst target <prog> -a
    #   tst target -a <prog>
    while [[ $# -gt 0 ]]; do
      case "${1}" in
        -a)
          a_present="yes"
          shift || true
          ;;
        --*)
          die "option inconnue pour target: '${1}'"
          ;;
        *)
          if [[ "${prog_set}" == "yes" ]]; then
            die "arguments en trop pour 'target' (reçu: $*)"
          fi
          prog="${1}"
          prog_set="yes"
          shift || true
          ;;
      esac
    done

    cd "${ROOT_DIR}"
    require_exec "./tools/mk_vendor" "outil mk_vendor"

    base="$(map_target_progvalue "${prog}")"
    put="$(apply_asan_rule "${base}" "${a_present}")"
    preflight_exec ./tools/mk_vendor make "${put}"
    ;;

  build)
    if [[ $# -ne 0 ]]; then
      die "build ne prend pas d'arguments (reçu: $*)"
    fi
    cd "${ROOT_DIR}"
    require_command cargo
    preflight_exec cargo build --release --bin=tlspuffin --features=cputs
    ;;

  seeds)
    if [[ $# -ne 0 ]]; then
      die "seeds ne prend pas d'arguments (reçu: $*)"
    fi
    cd "${ROOT_DIR}"
    require_exec "./target/release/tlspuffin" "binaire tlspuffin (release)"
    preflight_exec ./target/release/tlspuffin seed
    ;;

  fuzz)
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
      usage
      exit 0
    fi

    prog="open"           # default
    prog_provided="no"
    a_present="no"

    # Accept:
    #   tst fuzz
    #   tst fuzz <prog>
    #   tst fuzz <prog> -a
    # Reject:
    #   tst fuzz -a
    if [[ $# -gt 0 ]]; then
      case "${1}" in
        -a) die "usage invalide: '-a' nécessite un prog (ex: '${SELF_NAME} fuzz open -a')" ;;
        --*) die "option inconnue pour fuzz: '${1}'" ;;
        *)
          prog="${1}"
          prog_provided="yes"
          shift || true
          ;;
      esac
    fi

    if [[ "${1:-}" == "-a" ]]; then
      a_present="yes"
      shift || true
    elif [[ "${1:-}" == --* ]]; then
      die "option inconnue pour fuzz: '${1}'"
    fi

    if [[ $# -ne 0 ]]; then
      die "arguments en trop pour 'fuzz' (reçu: $*)"
    fi

    if [[ "${a_present}" == "yes" && "${prog_provided}" != "yes" ]]; then
      die "-a ne peut être utilisé que si prog est défini (ex: '${SELF_NAME} fuzz open -a')"
    fi

    cd "${ROOT_DIR}"
    require_exec "./target/release/tlspuffin" "binaire tlspuffin (release)"

    base="$(map_fuzz_progvalue "${prog}")"
    put="$(apply_asan_rule "${base}" "${a_present}")"
    preflight_exec ./target/release/tlspuffin --put "${put}" --cores=0-3 --tui quick-experiment
    ;;

  just)
    if [[ $# -ne 0 ]]; then
      die "just ne prend pas d'arguments (reçu: $*)"
    fi
    cd "${ROOT_DIR}"
    require_command just
    preflight_exec just check-workspace
    ;;

  fmt)
    if [[ $# -ne 0 ]]; then
      die "fmt ne prend pas d'arguments (reçu: $*)"
    fi
    cd "${ROOT_DIR}"
    require_command just
    preflight_exec just fmt
    ;;

  c)
    crate="${1:-}"
    shift || true

    if [[ -z "${crate}" ]]; then
      die "il faut fournir un crate: puffin|security-claims|tlspuffin|sshpuffin"
    fi
    if [[ $# -ne 0 ]]; then
      die "arguments en trop pour 'c' (reçu: $*)"
    fi

    case "${crate}" in
      puffin|security-claims|tlspuffin|sshpuffin) ;;
      *) die "crate inconnu: '${crate}' (attendu: puffin|security-claims|tlspuffin|sshpuffin)" ;;
    esac

    cd "${ROOT_DIR}"
    require_command cargo
    preflight_exec cargo test -p "${crate}" --target x86_64-unknown-linux-gnu --features ""
    ;;

  jt)
    if [[ $# -ne 0 ]]; then
      die "jt ne prend pas d'arguments (reçu: $*)"
    fi
    cd "${ROOT_DIR}"
    require_command cargo
    preflight_exec cargo test -p tlspuffin --target x86_64-unknown-linux-gnu --features ",cputs"
    ;;

  *)
    die "commande inconnue: '${method}'"
    ;;
esac