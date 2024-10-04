use_languages(C)

option(postauth "Build with post-auth" ON)

if(VENDOR_VERSION VERSION_LESS "5.2.0")
  declare_vulnerability("CVE-2022-25638" PATCH ${CMAKE_CURRENT_LIST_DIR}/patches/fix-CVE-2022-25638.patch)
  declare_vulnerability("CVE-2022-25640" PATCH ${CMAKE_CURRENT_LIST_DIR}/patches/fix-CVE-2022-25640.patch)
endif()

if(VENDOR_VERSION VERSION_LESS "5.5.0" AND NOT postauth)
  declare_vulnerability("CVE-2022-38152")
endif()

if(VENDOR_VERSION VERSION_LESS "5.5.1")
  declare_vulnerability("CVE-2022-39173" PATCH ${CMAKE_CURRENT_LIST_DIR}/patches/fix-CVE-2022-39173.patch)
endif()

if(VENDOR_VERSION VERSION_LESS "5.5.2")
  declare_vulnerability("CVE-2022-42905" PATCH ${CMAKE_CURRENT_LIST_DIR}/patches/fix-CVE-2022-42905.patch)
endif()

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

autotools_builder(
  FEATURES
    --enable-static
    --disable-shared
    --enable-debug
    --enable-opensslall
    --enable-opensslextra
    --enable-keygen  # support for RSA certs
    --enable-certgen # support x509 decoding
    --enable-tls13
    --enable-dtls
    --enable-sp
    --disable-sha3
    --enable-curve25519
    --enable-secure-renegotiation
    --enable-psk # FIXME only 4.3.0
    --disable-examples

    $<$<VERSION_GREATER_EQUAL:${VENDOR_VERSION},5.0.0>:--enable-context-extra-user-data>
    $<$<VERSION_GREATER_EQUAL:${VENDOR_VERSION},5.0.0>:--enable-dtls-mtu>

    $<$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>:--enable-intelasm>
    $<$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>:--enable-sp-asm>
    $<$<STREQUAL:${CMAKE_SYSTEM_PROCESSOR},x86_64>:--enable-aesni>

    $<IF:$<BOOL:${postauth}>,--enable-postauth,--disable-postauth>

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden
    -I${CMAKE_SOURCE_DIR}/../../tlspuffin-claims

    -DHAVE_EX_DATA                # FIXME only 4.3.0
    -DWOLFSSL_CALLBACKS           # FIXME else some msg callbacks are not called
    # FIXME broken: -DHAVE_EX_DATA_CLEANUP_HOOKS  # required for cleanup of ex data
    # FIXME broken: -DWC_RNG_SEED_CB              # makes test test_seed_cve_2022_38153 fail, but should be used when evaluating coverage to get same coverage than other fuzzers which use this flag to disable determinism
    # FIXME broken: -DWOLFSSL_GENSEED_FORTEST     # makes test test_seed_cve_2022_38153 fail, but should be used when evaluating coverage to get same coverage than other fuzzers which use this flag to disable determinism

    # sancov
    $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>

    # ASAN
    $<$<BOOL:${asan}>:-fsanitize=address>
    $<$<BOOL:${asan}>:-static-libsan>

    # llvm_cov
    $<$<BOOL:${llvm_cov}>:-fprofile-instr-generate>
    $<$<BOOL:${llvm_cov}>:-fcoverage-mapping>
    $<$<BOOL:${llvm_cov}>:-O0>

    # gcov
    $<$<BOOL:${gcov}>:-ftest-coverage>
    $<$<BOOL:${gcov}>:-fprofile-arcs>
    $<$<BOOL:${gcov}>:-O0>
)

