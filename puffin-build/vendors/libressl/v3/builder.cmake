# LibreSSL 3.x: autotools-based build.

# tlspuffin claims instrumentation (see patches/README.md):
#  - puffin_claims.c is appended to ssl/ssl_lib.c (claim registration and extraction)
#  - the patch adds the claim hooks and threads the TLS 1.3 context through the key schedule
list(APPEND PATCH_COMMANDS COMMAND sh -c "cat '${CMAKE_CURRENT_LIST_DIR}/puffin_claims.c' >> '<SOURCE_DIR>/ssl/ssl_lib.c'")
patch(FILE "${CMAKE_CURRENT_LIST_DIR}/patches/tls13-claims.patch")

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

set(transcript_extraction yes)
