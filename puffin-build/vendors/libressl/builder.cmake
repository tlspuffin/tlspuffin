use_languages(C)

# CVE-2023-35784: ssl3_free() does not NULL verified_chain (field introduced in 3.5.0,
# fixed in 3.6.3 / 3.7.3). SSL_clear() on a connection whose method was changed during
# version negotiation runs ssl_free+ssl_new, leaving a dangling verified_chain.
if(VENDOR_VERSION VERSION_GREATER_EQUAL "3.5.0" AND VENDOR_VERSION VERSION_LESS "3.6.3")
  declare_vulnerability("CVE-2023-35784" PATCH ${CMAKE_CURRENT_LIST_DIR}/patches/fix-CVE-2023-35784.patch)
endif()

list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/common/arc4random_prng.c" "<SOURCE_DIR>/crypto/compat/arc4random.c")
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/common/arc4random_prng.h" "<SOURCE_DIR>/crypto/compat/arc4random.h")

# Prevent LibreSSL from zeroing intermediate TLS 1.3 secrets (extracted_early,
# extracted_handshake, extracted_master) after derivation.  The `insecure` flag
# in tls13_secrets disables the explicit_bzero calls in tls13_key_schedule.c.
# We set it at creation time so the harness can read all secrets for claims.
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -DFILE=<SOURCE_DIR>/ssl/tls13_key_schedule.c -P "${CMAKE_CURRENT_LIST_DIR}/common/patch_insecure.cmake")

# Reorder default signature algorithm preference to put SHA256 first (matching
# OpenSSL), since LibreSSL does not expose an API to configure sigalgs at runtime.
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -DFILE=<SOURCE_DIR>/ssl/ssl_sigalgs.c -P "${CMAKE_CURRENT_LIST_DIR}/common/patch_sigalgs.cmake")

foreach(CVE IN LISTS fix)
  if(NOT HAS_${CVE})
    message(FATAL_ERROR "Requested fix for unknown CVE '${CVE}'")
  endif()

  if(NOT PATCH_${CVE})
    message(FATAL_ERROR "Requested fix for CVE '${CVE}' but no patch is known")
  endif()

  patch(FILE ${PATCH_${CVE}})
  list(APPEND FIXED_VULNERABILITIES ${CVE})
endforeach()

cmake_builder(
  CMAKE_FLAGS
    -DBUILD_SHARED_LIBS=OFF
    -DLIBRESSL_APPS=OFF
    -DLIBRESSL_TESTS=OFF
    -DHAVE_ARC4RANDOM_BUF=0

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden

    # SANCOV
    $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>

    # ASAN
    $<$<BOOL:${asan}>:-fsanitize=address>
    $<$<BOOL:${asan}>:-static-libsan>

    # LLVM_COV
    $<$<BOOL:${llvm_cov}>:-fprofile-instr-generate>
    $<$<BOOL:${llvm_cov}>:-fcoverage-mapping>
    $<$<BOOL:${llvm_cov}>:-O0>

    # GCOV
    $<$<BOOL:${gcov}>:-ftest-coverage>
    $<$<BOOL:${gcov}>:-fprofile-arcs>
    $<$<BOOL:${gcov}>:-O0>
)

# Copy internal SSL headers to install prefix so the harness can access
# LibreSSL internal structures (transcript hash, TLS 1.3 secrets, etc.)
# without patching the library.
set(INTERNAL_DIR "${CMAKE_INSTALL_PREFIX}/include/libressl_internal")
list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E make_directory "${INTERNAL_DIR}")
if(VENDOR_VERSION VERSION_GREATER_EQUAL "4.0.0")
  list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy
    "<SOURCE_DIR>/ssl/ssl_local.h"
    "<SOURCE_DIR>/ssl/tls13_internal.h"
    "<SOURCE_DIR>/ssl/tls_internal.h"
    "<SOURCE_DIR>/ssl/tls12_internal.h"
    "<SOURCE_DIR>/ssl/tls_content.h"
    "<SOURCE_DIR>/ssl/bytestring.h"
    "${INTERNAL_DIR}/"
  )
else()
  # 3.x names the main header ssl_locl.h; it is installed as ssl_local.h to match the 4.x name
  # used by the harness.
  list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy
    "<SOURCE_DIR>/ssl/ssl_locl.h"
    "${INTERNAL_DIR}/ssl_local.h"
  )
  list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy
    "<SOURCE_DIR>/ssl/ssl_sigalgs.h"
    "<SOURCE_DIR>/ssl/ssl_tlsext.h"
    "<SOURCE_DIR>/ssl/srtp.h"
    "<SOURCE_DIR>/ssl/tls13_handshake.h"
    "<SOURCE_DIR>/ssl/tls13_internal.h"
    "<SOURCE_DIR>/ssl/tls13_record.h"
    "<SOURCE_DIR>/ssl/bytestring.h"
    "${INTERNAL_DIR}/"
  )
  # tls_internal.h / tls_content.h appeared after 3.3.x and are included by tls13_internal.h
  if(VENDOR_VERSION VERSION_GREATER_EQUAL "3.5.0")
    list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy
      "<SOURCE_DIR>/ssl/tls_internal.h"
      "<SOURCE_DIR>/ssl/tls_content.h"
      "${INTERNAL_DIR}/"
    )
  endif()
  # In 3.5.x - 3.x, libtls.a bundles its own copies of libssl/libcrypto objects, which clash at
  # link time (the harness links every lib/*.a and does not use the tls_* API).
  if(VENDOR_VERSION VERSION_GREATER_EQUAL "3.5.0")
    list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E remove -f "${CMAKE_INSTALL_PREFIX}/lib/libtls.a")
  endif()
endif()

set(tls12 yes)
set(tls13 yes)
set(tls12_session_resumption yes)
# LibreSSL does not support TLS 1.3 session resumption, only 0-RTT
set(tls13_session_resumption no)
set(transcript_extraction yes)
set(client_authentication_transcript_extraction yes)
set(allow_setting_tls12_ciphers yes)
set(allow_setting_tls13_ciphers yes)
