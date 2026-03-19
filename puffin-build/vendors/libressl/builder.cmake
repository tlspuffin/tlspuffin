use_languages(C)

list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/arc4random_prng.c" "<SOURCE_DIR>/crypto/compat/arc4random.c")
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/arc4random_prng.h" "<SOURCE_DIR>/crypto/compat/arc4random.h")

if(VENDOR_VERSION VERSION_GREATER_EQUAL "4.0.0")
  # LibreSSL >= 4.x uses cmake and has restructured internal headers

  list(APPEND PATCH_COMMANDS COMMAND sh -c "echo ${VENDOR_VERSION} > <SOURCE_DIR>/VERSION")
  list(APPEND PATCH_COMMANDS COMMAND sh -c "echo ${VENDOR_VERSION} > <SOURCE_DIR>/crypto/VERSION")
  list(APPEND PATCH_COMMANDS COMMAND sh -c "echo ${VENDOR_VERSION} > <SOURCE_DIR>/ssl/VERSION")
  list(APPEND PATCH_COMMANDS COMMAND sh -c "echo ${VENDOR_VERSION} > <SOURCE_DIR>/tls/VERSION")

  list(APPEND PATCH_COMMANDS COMMAND sh -c "echo SSL_new > <SOURCE_DIR>/ssl/ssl.sym")
  list(APPEND PATCH_COMMANDS COMMAND sh -c "echo CRYPTO_new_ex_data > <SOURCE_DIR>/crypto/crypto.sym")
  list(APPEND PATCH_COMMANDS COMMAND sh -c "echo tls_init > <SOURCE_DIR>/tls/tls.sym")

  # Prevent LibreSSL from zeroing intermediate TLS 1.3 secrets (extracted_early,
  # extracted_handshake, extracted_master) after derivation.  The `insecure` flag
  # in tls13_secrets disables the explicit_bzero calls in tls13_key_schedule.c.
  # We set it at creation time so the harness can read all secrets for claims.
  list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -DFILE=<SOURCE_DIR>/ssl/tls13_key_schedule.c -P "${CMAKE_CURRENT_LIST_DIR}/patch_insecure.cmake")

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
      -I${CMAKE_SOURCE_DIR}/../../tlspuffin-claims

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
  list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_INSTALL_PREFIX}/include/libressl_internal")
  list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy
    "<SOURCE_DIR>/ssl/ssl_local.h"
    "<SOURCE_DIR>/ssl/tls13_internal.h"
    "<SOURCE_DIR>/ssl/tls_internal.h"
    "<SOURCE_DIR>/ssl/tls12_internal.h"
    "<SOURCE_DIR>/ssl/tls_content.h"
    "<SOURCE_DIR>/ssl/bytestring.h"
    "${CMAKE_INSTALL_PREFIX}/include/libressl_internal/"
  )

  set(client_authentication_transcript_extraction yes)
  set(allow_setting_tls12_ciphers yes)
  set(allow_setting_tls13_ciphers yes)

else()
  # LibreSSL < 4.x uses autotools

  patch(PATTERN "s/USE_BUILTIN_ARC4RANDOM=no/USE_BUILTIN_ARC4RANDOM=yes/g" <SOURCE_DIR>/m4/check-os-options.m4)
  patch(PATTERN [===[s/\\$ac_cv_func_arc4random_buf/no/g]===] <SOURCE_DIR>/m4/check-libc.m4)

  autotools_builder(
    FEATURES
      --enable-static
      --disable-shared
      --disable-tests

    CFLAGS
      -g
      -fPIC
      -fvisibility=hidden
      -I${CMAKE_SOURCE_DIR}/../../tlspuffin-claims

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

endif()

set(tls12 yes)
set(tls13 yes)
set(tls12_session_resumption yes)
# LibreSSL does not support TLS 1.3 session resumption, only 0-RTT
set(tls13_session_resumption no)
set(transcript_extraction yes)
