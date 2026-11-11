use_languages(C)

option(postauth "Build with post-auth" ON)

# Patches of every build of a version (the claims instrumentation, AllowClaim): presets.toml's [[patches]]. Known
# vulnerabilities and their fix patches: vulnerabilities.toml. puffin-build applies both after the patches below.

set(v440_or_later "$<VERSION_GREATER_EQUAL:${VENDOR_VERSION_ORDER},4.4.0>")
set(before_v520 "$<VERSION_LESS:${VENDOR_VERSION_ORDER},5.2.0>")
set(require_define_xtime "$<AND:$<AND:${CPUT},${v440_or_later}>,${before_v520}>")

set(require_user_ticks "${CPUT}")

# The RDSEED/RDRAND inline assembly does not mark its output as early-clobber: the compiler may
# reuse the output register to address the status flag, which crashes the library when it is
# built with ASAN. The constraint is fixed in every version that has it (present in 4.3.0 and 5.x).
patch(PATTERN [===[s/"=r"\\((\\*\\w+)\\), "=qm"\\(ok\\)/"=&r"($1), "=qm"(ok)/]===] <SOURCE_DIR>/wolfcrypt/src/random.c)

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
    --enable-renegotiation-indication # Adds a security layer above secure-renegotiation
    # --enable-secure-renegotiation   => cannot be used in conjunction of enable-renegotiation-indication
    --enable-psk # FIXME only 4.3.0
    --disable-examples
    --disable-crypttests # to be able to build with -DUSER_TICKS
    $<$<VERSION_GREATER_EQUAL:${VENDOR_VERSION_ORDER},4.4.0>:--enable-cryptocb>

    $<$<VERSION_GREATER_EQUAL:${VENDOR_VERSION_ORDER},5.0.0>:--enable-context-extra-user-data>
    $<$<VERSION_GREATER_EQUAL:${VENDOR_VERSION_ORDER},5.0.0>:--enable-dtls-mtu>

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
    -DHAVE_CURVE25519
    $<${require_user_ticks}:-DUSER_TICKS>         # to ensure deterministic behaviour
    $<${require_define_xtime}:-DXTIME=time_cb>    # to ensure deterministic behaviour with version >= 4.4.0 and < 5.2.0
    $<$<VERSION_GREATER_EQUAL:${VENDOR_VERSION_ORDER},4.4.0>:-DHAVE_SECRET_CALLBACK>
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

# Extract internal.h from source to install include location
list(APPEND INSTALL_COMMANDS
  COMMAND ${CMAKE_COMMAND} -E copy "<SOURCE_DIR>/wolfssl/internal.h" "<INSTALL_DIR>/include/wolfssl/"
)

set(tls12 yes)
set(tls13 yes)
set(transcript_extraction yes)
set(client_authentication_transcript_extraction yes)
if(VENDOR_VERSION_ORDER VERSION_GREATER_EQUAL "5.0")
  set(tls12_session_resumption yes)
  set(tls13_session_resumption yes)
  set(psk_ke_support yes)
endif()
set(allow_setting_tls12_ciphers yes)
set(allow_setting_tls13_ciphers yes)

if(NOT postauth)
  set(disable_postauth yes)
endif()
