#!/usr/bin/env bash
#
# Build wolfSSL + wolfSSH from source and stage them as a sshpuffin vendor
# (vendor/wolfssh-asan/) discoverable by build.rs.
#
# wolfSSH depends on wolfSSL built with --enable-ssh (sets WOLFSSL_WOLFSSH and
# the crypto wolfSSH needs). wolfSSH itself is autotools-only (no CMake), so it
# needs libtoolize. Both are built static with ASAN + sancov to match the other
# sshpuffin PUTs.
#
# Usage: harness/wolfssh/build_wolfssh_vendor.sh [WOLFSSL_TAG] [WOLFSSH_TAG]
# Env:   CC (clang), LIBTOOL_BIN (dir containing libtoolize), VENDOR_DIR.
set -euo pipefail

WOLFSSL_TAG="${1:-v5.7.6-stable}"
WOLFSSH_TAG="${2:-master}"
SCRATCH="${SCRATCH:-/tmp/wolf_scratch}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VENDOR_DIR="${VENDOR_DIR:-$PROJECT_DIR/vendor/wolfssh-asan}"
CC="${CC:-clang}"
CFLAGS="-g -fPIC -fsanitize=address -fsanitize-coverage=trace-pc-guard"

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
instrumentation = ["sancov","asan"]
known_vulnerabilities = []
fixed_vulnerabilities = []
capabilities = []
EOF
echo "Staged wolfSSH vendor at $VENDOR_DIR (version ${WVER})"
