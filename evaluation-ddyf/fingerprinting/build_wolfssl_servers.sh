#!/usr/bin/env bash
# Build the wolfSSL example server (examples/server/server) for every vendored
# wolfSSL version, so build_live_matrix.py --server-cmd wolfssl can probe a real
# server of each version over TCP.
#
# The vendored libwolfssl.a is sancov-instrumented and expects the application to
# provide a few timer/coverage symbols; sancov_stub.c supplies no-op stubs. The
# example server is run from the wolfSSL source root (ChangeToWolfRoot needs certs/).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
STUB="$HERE/sancov_stub.c"
CORES="${BUILD_CORES:-24-25}"

built=0; failed=0
for d in "$REPO"/vendor/wolfssl*/; do
  v="$(basename "$d")"
  case "$v" in *-asan) continue;; esac          # skip asan variants
  lib="$d/lib/libwolfssl.a"
  src="$d/src/vendor"
  cfg="$d/bin/wolfssl-config"
  [ -f "$lib" ] && [ -d "$src/examples/server" ] && [ -x "$cfg" ] || { echo "skip $v (incomplete)"; continue; }
  out="$d/bin/server"
  compile() {  # $1 = extra defines
    ( cd "$src" && taskset -c "$CORES" cc $1 examples/server/server.c "$STUB" \
        $("$cfg" --cflags) -I"$src" $("$cfg" --libs) -lm -o "$out" ) 2>"/tmp/wolfbuild_$v.err"
  }
  vnum="${v#wolfssl}"
  extra_flags=""
  if [[ "$vnum" > "499" ]]; then
      extra_flags="-DUSER_TICKS"
      if [[ "$vnum" < "520" ]]; then
          extra_flags="$extra_flags -DXTIME=time_cb"
      fi
  fi

  # some versions' example server references earlyData under a mismatched guard
  if compile "$extra_flags" || compile "$extra_flags -DWOLFSSL_EARLY_DATA"; then
    # Smoke-test: does it actually serve? Must run from the wolfSSL source root ($src) with the
    # same flags the pipeline uses (-x continue-on-error, -d no-client-cert, -i loop, -b any-addr),
    # because ChangeToWolfRoot() looks for certs/ in the cwd. Running it from elsewhere exits
    # immediately and used to be misreported as "crashes on launch" (a false negative).
    ( cd "$src" && "$out" -x -d -i -b -p 27599 ) >/dev/null 2>&1 &
    pid=$!
    sleep 0.3
    if kill -0 $pid 2>/dev/null; then
      kill -9 $pid 2>/dev/null
      echo "OK   $v -> $out"
      built=$((built+1))
    else
      echo "FAIL $v (server exits immediately even from \$src -- see /tmp/wolfbuild_$v.err)"; failed=$((failed+1))
    fi
  else
    echo "FAIL $v (compile error, see /tmp/wolfbuild_$v.err)"; failed=$((failed+1))
  fi
done
echo "=== built $built, failed $failed ==="
