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

# ---- 1) vendor each version named in the presets (mk_vendor builds the lib + bin tools) ---------
for vendor in $PUTS; do
  presets="puffin-build/vendors/$vendor/presets.toml"
  [ -f "$presets" ] || { echo "[setup] missing $presets"; exit 1; }
  # default: every preset in the toml; override with VERSIONS_OPENSSL / VERSIONS_WOLFSSL (dotted)
  override_var="VERSIONS_${vendor^^}"
  if [ -n "${!override_var:-}" ]; then
    presets_list=""
    for v in ${!override_var}; do presets_list="$presets_list ${vendor}${v//./}"; done
  else
    presets_list="$(grep -oE "^\[${vendor}[0-9]+\]" "$presets" | tr -d '[]')"
  fi
  for preset in $presets_list; do
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
