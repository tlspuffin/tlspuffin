#!/usr/bin/env bash
# setup.sh -- one-shot bootstrap for the fingerprinting pipeline.
#
# From a fresh clone, builds everything the scripts expect at their DEFAULT paths:
#   - every vendored per-version library + server (OpenSSL `bin/openssl`, and the WolfSSL
#     example `bin/server`) under  <repo>/vendor/<name>/   (puts.Config.vendor default),
#   - the tlspuffin prober/fuzzer at <repo>/target/release/tlspuffin (puts.Config.prober default),
#   - a throwaway localhost cert the OpenSSL s_server needs.
#
# Run from the repo root inside the dev shell:
#     nix-shell ./shell.nix --run ./evaluation-ddyf/fingerprinting/setup.sh
#
# This is a LONG build (it vendors ~90 OpenSSL/WolfSSL versions and compiles tlspuffin). It is
# idempotent: mk_vendor skips versions already built, so it is safe to re-run. Select a subset with
#   PUTS="openssl"           # only OpenSSL
#   VERSIONS_OPENSSL="3.6.2"  VERSIONS_WOLFSSL="5.9.1"   # only specific versions (space-separated)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

# LibAFL edge-map sizes the harness build expects (override via env if needed).
export LIBAFL_EDGES_MAP_DEFAULT_SIZE="${LIBAFL_EDGES_MAP_DEFAULT_SIZE:-67108864}"
export LIBAFL_EDGES_MAP_SIZE="${LIBAFL_EDGES_MAP_SIZE:-67108864}"
export LIBAFL_EDGES_MAP_ALLOCATED_SIZE="${LIBAFL_EDGES_MAP_ALLOCATED_SIZE:-67108864}"

PUTS="${PUTS:-openssl wolfssl}"

# Fail early with a clear message if the toolchain is missing (the usual cause is running outside the
# nix dev shell). mk_vendor and the harness build both need cargo.
command -v cargo >/dev/null 2>&1 || {
  echo "[setup] ERROR: 'cargo' not found in PATH -- run this script INSIDE the dev shell:"
  echo "         nix-shell ./shell.nix     # then re-run ./evaluation-ddyf/fingerprinting/setup.sh"
  exit 1
}

# ---- 1) vendor each version named in the presets (mk_vendor builds the lib + bin tools) ---------
for vendor in $PUTS; do
  presets="puffin-build/vendors/$vendor/presets.toml"
  [ -f "$presets" ] || { echo "[setup] missing $presets"; exit 1; }
  # The committed presets.toml ships only a few upstream presets, so without this setup would vendor
  # a tiny subset (e.g. 3 OpenSSL versions). presets_gen.py appends the FULL per-version preset set
  # (idempotent: skips presets already present) so all 61 OpenSSL / 26 WolfSSL versions are buildable.
  if [ -f "$HERE/presets_gen.py" ]; then
    python3 "$HERE/presets_gen.py" "$vendor" >/dev/null 2>&1 \
      && echo "[setup] $vendor: presets.toml now defines $(grep -cE "^\[${vendor}[0-9]+\]" "$presets") version presets" \
      || echo "[setup] WARN presets_gen.py $vendor failed (presets.toml left as-is)"
  fi
  # default: every preset in the toml; override with VERSIONS_OPENSSL / VERSIONS_WOLFSSL (dotted)
  override_var="VERSIONS_${vendor^^}"
  if [ -n "${!override_var:-}" ]; then
    presets_list=""
    for v in ${!override_var}; do presets_list="$presets_list ${vendor}${v//./}"; done
  else
    # Fingerprinting scope is ONE major line per PUT (openssl 3.x, wolfssl 5.x). Restrict to it so we
    # never vendor out-of-scope versions like wolfssl 4.3.0, whose old headers don't match the 5.x
    # harness (put.c uses WOLFSSL_TIMEVAL / wc_CryptoInfo etc. -> compile error on 4.x). The `[0-9]+\]`
    # tail already excludes the -asan and 1.1.1u presets.
    case "$vendor" in openssl) ln=3;; wolfssl) ln=5;; *) ln="";; esac
    presets_list="$(grep -oE "^\[${vendor}${ln}[0-9]+\]" "$presets" | tr -d '[]')"
  fi
  # success marker of a completed mk_vendor build (per vendor); a failed build leaves an empty
  # vendor/<preset> stub that mk_vendor would treat as "already built" and skip on re-run.
  case "$vendor" in
    openssl) marker_rel="bin/openssl";;
    wolfssl) marker_rel="lib/libwolfssl.a";;
    *)       marker_rel="";;
  esac
  for preset in $presets_list; do
    if [ -d "vendor/$preset" ] && [ -n "$marker_rel" ] && [ ! -e "vendor/$preset/$marker_rel" ]; then
      echo "[setup] removing broken stub vendor/$preset (missing $marker_rel) so mk_vendor retries"
      rm -rf "vendor/$preset"
    fi
    echo "[setup] vendoring $vendor:$preset"
    ./tools/mk_vendor make "$vendor:$preset" >/dev/null 2>&1 || echo "[setup] WARN $preset build failed"
  done
done

# ---- 2) build the tlspuffin prober/fuzzer (used by run_campaigns + all probing) -----------------
echo "[setup] building tlspuffin (cargo build --release --bin tlspuffin --features cputs)"
cargo build --release --bin tlspuffin --features cputs || { echo "[setup] harness build FAILED"; exit 1; }
echo "[setup] prober -> $REPO/target/release/tlspuffin"

# ---- 3) compile the WolfSSL example servers (live targets) -------------------------------------
if echo "$PUTS" | grep -qw wolfssl; then
  echo "[setup] building WolfSSL example servers"
  "$HERE/build_wolfssl_servers.sh" || echo "[setup] WARN some WolfSSL servers failed"
fi

# ---- 4) throwaway localhost cert for the OpenSSL s_server --------------------------------------
cert="$HERE/lab_validation/server.crt"; key="$HERE/lab_validation/server.key"
if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
  echo "[setup] generating throwaway lab cert (localhost)"
  mkdir -p "$HERE/lab_validation"
  openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$cert" -days 3650 -nodes \
    -subj "/CN=localhost" >/dev/null 2>&1
fi

# ---- 5) sanity: show the resolved configuration ------------------------------------------------
echo "[setup] done. Resolved configuration:"
python3 "$HERE/puts.py" --put $PUTS
echo "[setup] next: python3 $HERE/run_fingerprint.py --put $PUTS"
