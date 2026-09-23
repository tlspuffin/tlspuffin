#!/usr/bin/env bash
#
# Build wolfSSL + wolfSSH from source and stage them as a sshpuffin vendor
# (vendor/wolfssh150-asan/) discoverable by build.rs.
#
# ⚠ NOT SUITABLE FOR DIFFERENTIAL FUZZING. This standalone script builds a
# wolfSSH PUT that is MISSING two things the puffin-build preset applies:
#   1. CUSTOM_RAND_GENERATE_SEED (deterministic RNG) — without it the PUT is
#      nondeterministic, so even self-vs-self differential runs diverge.
#   2. the session-id claim instrumentation (+ the `claimer` metadata tag) —
#      without it no exchange-hash (H) claim is emitted, so the cross-vendor
#      s2c decryption recipe cannot source H and produces no transcript.
# Because build.rs accepts an existing vendor/wolfssh150-asan BEFORE invoking the
# preset, dropping this script's output there yields a silently-broken PUT.
#
# PREFER THE PRESET BUILDER for anything that feeds the differential:
#     just mk_vendor wolfssh wolfssh150-asan      # applies RNG hook + claim instrumentation
# (build.rs also builds it automatically from the `wolfssh` preset when no vendor
# is present.) This script is retained ONLY as a minimal, dependency-mapping
# reference for the raw wolfSSL/wolfSSH autotools build; it is guarded below so
# it cannot be used unknowingly.
#
# Usage: SSHPUFFIN_ALLOW_RAW_WOLFSSH_BUILD=1 \
#          harness/wolfssh/build_wolfssh_vendor.sh [WOLFSSL_TAG] [WOLFSSH_TAG]
# The tags default to the pins read from puffin-build (see below); pass them only
# to deliberately build another version.
# Env:   PRESET (wolfssh150-asan; the presets.toml section to read the wolfSSH pin
#        from, also names the default vendor dir), CC (clang), LIBTOOL_BIN (dir
#        containing libtoolize), SCRATCH (clone/build dir; default under the
#        repo's target/), VENDOR_DIR (default vendor/$PRESET).
set -euo pipefail

if [ "${SSHPUFFIN_ALLOW_RAW_WOLFSSH_BUILD:-}" != "1" ]; then
    cat >&2 <<'MSG'
error: build_wolfssh_vendor.sh produces a PUT WITHOUT the deterministic-RNG hook
       and session-id claim instrumentation, so it is unusable for differential
       fuzzing (nondeterministic; no H claim => decryption recipe fails).

       Use the preset builder instead:
           just mk_vendor wolfssh wolfssh150-asan

       If you really want this raw build anyway (e.g. dependency mapping only),
       re-run with:
           SSHPUFFIN_ALLOW_RAW_WOLFSSH_BUILD=1 harness/wolfssh/build_wolfssh_vendor.sh ...
MSG
    exit 1
fi

# Version source of truth — READ from puffin-build, never forked here:
#   * wolfSSH  -> puffin-build/vendors/wolfssh/presets.toml, `branch` of [$PRESET]
#                 (the v1.5.0-stable RELEASE, NOT master: presets.toml documents
#                 that a newer master regresses the handshake with WS_BUFFER_E)
#   * wolfSSL  -> puffin-build/vendors/wolfssh/build_wolfssl_dep.sh (WOLFSSL_TAG default)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PRESETS_TOML="$PROJECT_DIR/puffin-build/vendors/wolfssh/presets.toml"
WOLFSSL_DEP_SH="$PROJECT_DIR/puffin-build/vendors/wolfssh/build_wolfssl_dep.sh"
PRESET="${PRESET:-wolfssh150-asan}"

# `branch = "..."` of the [$PRESET] section (first match before the next section).
preset_wolfssh_tag() {
    awk -v sec="[$PRESET]" '
        $0 == sec { in_sec = 1; next }
        /^\[/    { in_sec = 0 }
        in_sec && match($0, /branch *= *"[^"]+"/) {
            v = substr($0, RSTART, RLENGTH); sub(/^branch *= *"/, "", v); sub(/"$/, "", v)
            print v; exit
        }' "$PRESETS_TOML"
}
# The `${WOLFSSL_TAG:-<default>}` default in build_wolfssl_dep.sh.
preset_wolfssl_tag() {
    sed -n 's/^WOLFSSL_TAG="\${WOLFSSL_TAG:-\([^}]*\)}"$/\1/p' "$WOLFSSL_DEP_SH" | head -1
}

WOLFSSL_TAG="${1:-$(preset_wolfssl_tag)}"
WOLFSSH_TAG="${2:-$(preset_wolfssh_tag)}"
if [ -z "$WOLFSSL_TAG" ] || [ -z "$WOLFSSH_TAG" ]; then
    echo "error: could not read the wolfSSL/wolfSSH pins (preset [$PRESET] in $PRESETS_TOML," >&2
    echo "       WOLFSSL_TAG default in $WOLFSSL_DEP_SH); pass them as arguments." >&2
    exit 1
fi
echo "wolfSSL $WOLFSSL_TAG, wolfSSH $WOLFSSH_TAG (preset $PRESET)"
# Per-tag scratch under the (gitignored) target/ dir, so cached clones never mix versions.
SCRATCH="${SCRATCH:-$PROJECT_DIR/target/wolfssh-raw-build/$WOLFSSL_TAG-$WOLFSSH_TAG}"
VENDOR_DIR="${VENDOR_DIR:-$PROJECT_DIR/vendor/$PRESET}"
CC="${CC:-clang}"
# ASAN iff the preset says `asan = true` (sancov is on for every wolfSSH preset).
if awk -v sec="[$PRESET]" '$0 == sec { f = 1; next } /^\[/ { f = 0 } f && /^asan *= *true/ { ok = 1 } END { exit !ok }' "$PRESETS_TOML"; then
    CFLAGS="-g -fPIC -fsanitize=address -fsanitize-coverage=trace-pc-guard"
    INSTRUMENTATION='["sancov","asan"]'
else
    CFLAGS="-g -fPIC -fsanitize-coverage=trace-pc-guard"
    INSTRUMENTATION='["sancov"]'
fi

# libtoolize must be on PATH for wolfSSL/wolfSSH autogen.sh.
if [ -n "${LIBTOOL_BIN:-}" ]; then export PATH="$LIBTOOL_BIN:$PATH"; fi
command -v libtoolize >/dev/null || { echo "libtoolize not found; set LIBTOOL_BIN"; exit 1; }

mkdir -p "$SCRATCH"
cd "$SCRATCH"

[ -d wolfssl ] || git clone --depth 1 --branch "$WOLFSSL_TAG" https://github.com/wolfSSL/wolfssl.git
[ -d wolfssh ] || git clone --depth 1 --branch "$WOLFSSH_TAG"  https://github.com/wolfSSL/wolfssh.git

# wolfSSL with --enable-ssh
( cd wolfssl
  rm -rf "$SCRATCH/wolfssl_install"; mkdir -p "$SCRATCH/wolfssl_install"
  ./autogen.sh
  CC="$CC" ./configure --enable-static --disable-shared --enable-ssh \
      --enable-curve25519 --enable-ed25519 \
      --prefix="$SCRATCH/wolfssl_install" CFLAGS="$CFLAGS"
  make -j"$(nproc)" install )

# wolfSSH against that wolfSSL
( cd wolfssh
  make distclean 2>/dev/null || true
  rm -rf "$SCRATCH/wolfssh_install"; mkdir -p "$SCRATCH/wolfssh_install"
  ./autogen.sh
  CC="$CC" ./configure --enable-static --disable-shared --disable-examples \
      --with-wolfssl="$SCRATCH/wolfssl_install" \
      --prefix="$SCRATCH/wolfssh_install" CFLAGS="$CFLAGS"
  make -j"$(nproc)" install )

# Stage the vendor directory (lib/ + include/ + metadata).
rm -rf "$VENDOR_DIR"; mkdir -p "$VENDOR_DIR/lib" "$VENDOR_DIR/include"
cp "$SCRATCH/wolfssh_install/lib/libwolfssh.a" "$VENDOR_DIR/lib/"   # before wolfssl (link order)
cp "$SCRATCH/wolfssl_install/lib/libwolfssl.a" "$VENDOR_DIR/lib/"
cp -r "$SCRATCH/wolfssh_install/include/wolfssh" "$VENDOR_DIR/include/"
cp -r "$SCRATCH/wolfssl_install/include/wolfssl" "$VENDOR_DIR/include/"
WVER="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "$SCRATCH/wolfssh_install/include/wolfssh/version.h" | head -1)"
cat > "$VENDOR_DIR/.metadata" <<EOF
vendor = "wolfssh"
version = "${WVER:-unknown}"
instrumentation = ${INSTRUMENTATION}
known_vulnerabilities = []
fixed_vulnerabilities = []
capabilities = []
EOF
echo "Staged wolfSSH vendor at $VENDOR_DIR (version ${WVER})"
