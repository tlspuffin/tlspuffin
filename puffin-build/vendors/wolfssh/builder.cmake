# wolfSSH builder.
#
# wolfSSH depends on wolfSSL built with --enable-ssh (which defines
# WOLFSSL_WOLFSSH and the crypto wolfSSH needs). puffin-build has no
# cross-vendor dependency mechanism and fetches a single source (wolfSSH), so we
# build wolfSSL ourselves as the first configure step, then build wolfSSH
# against it. Both are static, with ASAN/sancov to match the other PUTs. The
# wolfSSL archive + headers are copied into the install dir so the resulting
# vendor is self-contained for the harness link.
#
# Both projects are autotools-only, so autogen.sh needs libtoolize; we locate it
# (it may live outside /usr/bin, e.g. a Nix store) and put its dir on PATH.

use_languages(C)

include(ExternalProject)

# ── locate libtoolize (autotools dependency) ─────────────────────────────────
find_program(LIBTOOLIZE_EXE NAMES libtoolize glibtoolize)
if(NOT LIBTOOLIZE_EXE)
  message(FATAL_ERROR "wolfssh builder: libtoolize not found (needed by autogen.sh)")
endif()
get_filename_component(LIBTOOLIZE_DIR "${LIBTOOLIZE_EXE}" DIRECTORY)
set(BUILD_PATH "${LIBTOOLIZE_DIR}:$ENV{PATH}")

# ── assemble CFLAGS (instrumentation toggled by options) ─────────────────────
set(WS_CFLAGS "-g -fPIC")
if(asan)
  set(WS_CFLAGS "${WS_CFLAGS} -fsanitize=address -static-libsan")
endif()
if(sancov)
  set(WS_CFLAGS "${WS_CFLAGS} -fsanitize-coverage=trace-pc-guard")
endif()

# Expose the session id (exchange hash H of the first KEX, RFC 4253 §7.2) to the
# claim layer so the decryption recipe can source H from the PUT instead of
# reconstructing it from a (mutation-stale) hard-coded client KEXINIT. Mirrors
# the libssh instrument. Pure observation; no behaviour change. src/ssh.c
# already includes <wolfssh/internal.h>, so the WOLFSSH struct is in scope.
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -DFILE=<SOURCE_DIR>/src/ssh.c -P "${CMAKE_CURRENT_LIST_DIR}/instrument_claims.cmake")

set(WOLFSSL_PREFIX "${CMAKE_BINARY_DIR}/wolfssl_install")

# ── step 1: build wolfSSL (--enable-ssh) before configuring wolfSSH ──────────
# Delegated to a helper script (robust quoting) and run as the first CONFIGURE
# command so ordering is guaranteed within the single `vendor` ExternalProject.
list(APPEND CONFIGURE_COMMANDS COMMAND
  ${CMAKE_COMMAND} -E env "PATH=${BUILD_PATH}"
    bash "${CMAKE_CURRENT_LIST_DIR}/build_wolfssl_dep.sh"
      "${WOLFSSL_PREFIX}" "${WS_CFLAGS}" "${CMAKE_C_COMPILER}"
)

# ── step 2: build wolfSSH against that wolfSSL ───────────────────────────────
autotools_builder(
  ENV
    "PATH=${BUILD_PATH}"
  FEATURES
    --enable-static
    --disable-shared
    --disable-examples
    --with-wolfssl=${WOLFSSL_PREFIX}
  CFLAGS
    -g
    -fPIC
    $<$<BOOL:${asan}>:-fsanitize=address>
    $<$<BOOL:${asan}>:-static-libsan>
    $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>
)

# ── step 3: make the install self-contained (bundle wolfSSL) ─────────────────
list(APPEND INSTALL_COMMANDS
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_INSTALL_PREFIX}/lib"
  COMMAND ${CMAKE_COMMAND} -E copy "${WOLFSSL_PREFIX}/lib/libwolfssl.a" "${CMAKE_INSTALL_PREFIX}/lib/"
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${WOLFSSL_PREFIX}/include/wolfssl" "${CMAKE_INSTALL_PREFIX}/include/wolfssl"
)

# Capabilities advertised in .metadata (none special yet).
