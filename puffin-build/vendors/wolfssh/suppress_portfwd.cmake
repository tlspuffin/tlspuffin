# Suppress the examples/portfwd example program.
#
# wolfSSH's `examples/portfwd/portfwd` is gated by `if BUILD_FWD` (NOT
# BUILD_EXAMPLES), so `--enable-fwd` builds it even under `--disable-examples`. As
# a full executable it links against the puffin harness RNG shim
# (`puffin_wolfssl_seed`, an unresolved symbol in the static libs that only the
# final harness link provides), so the example link fails and breaks `make install`
# — dropping the whole wolfSSH PUT. We only need the LIBRARY (the harness links it),
# never the example, so neutralise its include.am. Idempotent (PATCH_COMMANDS may
# re-run against already-patched source).
#
# Invoked with -DFILE=<SOURCE_DIR>/examples/portfwd/include.am.

file(READ "${FILE}" content)

if(content MATCHES "PUFFIN portfwd suppressed")
  message(STATUS "PUFFIN wolfssh: portfwd already suppressed in ${FILE}; skipping")
else()
  # Replace the whole file with a no-op: the `if BUILD_FWD ... endif` block that
  # adds examples/portfwd/portfwd to noinst_PROGRAMS is removed entirely.
  file(WRITE "${FILE}"
"# vim:ft=automake\n# PUFFIN portfwd suppressed: the portfwd example is not built (it cannot link\n# against the harness RNG shim). The wolfSSH library still compiles with\n# --enable-fwd; only this example executable is dropped.\n")
  message(STATUS "PUFFIN wolfssh: suppressed portfwd example in ${FILE}")
endif()
