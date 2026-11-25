#!/usr/bin/env bash
# Builds client.c against the vendored LibreSSL (ASAN) build.
# Usage: build_client.sh [preset]   (default: libressl362-asan)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
preset="${1:-libressl362-asan}"
vendor="$root/vendor/$preset"
[ -d "$vendor/lib" ] || { echo "missing $vendor: run 'just mk_vendor libressl $preset'" >&2; exit 1; }
clang -g -fsanitize=address -I"$vendor/include" "$here/client.c" \
  "$vendor/lib/libssl.a" "$vendor/lib/libcrypto.a" -lpthread -o "$here/client-$preset"
echo "built $here/client-$preset"
