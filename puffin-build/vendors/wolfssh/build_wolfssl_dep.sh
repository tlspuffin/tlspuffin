#!/usr/bin/env bash
#
# Build wolfSSL (--enable-ssh) as a build-time dependency of the wolfSSH vendor.
# Invoked by vendors/wolfssh/builder.cmake as the first configure step.
#
# Args: <install-prefix> <cflags> <cc>
set -euo pipefail

PREFIX="$1"
CFLAGS="$2"
CC="${3:-clang}"
WOLFSSL_TAG="${WOLFSSL_TAG:-v5.7.6-stable}"

# Route wolfCrypt's entropy through our deterministic seed function
# (puffin_wolfssl_seed, defined in the wolfSSH harness). This makes wolfSSH's KEX
# randomness reproducible so the differential gets identical runs across PUT
# instances (no encrypted-layer false positives) and campaigns are deterministic.
# A force-included header supplies the prototype so wolfSSL's random.c compiles
# under its -Werror (-Wimplicit-function-declaration).
SEED_PROTO="$(cd "$(dirname "$0")" && pwd)/puffin_seed_proto.h"
CFLAGS="$CFLAGS -DCUSTOM_RAND_GENERATE_SEED=puffin_wolfssl_seed -include $SEED_PROTO"

# Already built? (idempotent across re-configures)
if [ -f "$PREFIX/lib/libwolfssl.a" ]; then
    echo "[wolfssh] wolfSSL already built at $PREFIX"
    exit 0
fi

SRC="$(dirname "$PREFIX")/wolfssl_src"
rm -rf "$SRC"
git clone --depth 1 --branch "$WOLFSSL_TAG" https://github.com/wolfSSL/wolfssl.git "$SRC"

cd "$SRC"
./autogen.sh
CC="$CC" ./configure \
    --enable-static --disable-shared --enable-ssh \
    --enable-curve25519 --enable-ed25519 \
    --disable-examples --disable-crypttests \
    --prefix="$PREFIX" CFLAGS="$CFLAGS"
make -j"$(nproc)" install
echo "[wolfssh] wolfSSL built at $PREFIX"
