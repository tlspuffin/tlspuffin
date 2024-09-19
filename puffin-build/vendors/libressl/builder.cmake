use_languages(C)

option(asan "Build with address-sanitizer" OFF)
option(sancov "Build with sancov" OFF)
option(gcov "Build with instrumentation for gcov coverage" OFF)
option(llvm_cov "Build with instrumentation for llvm coverage" OFF)

patch(PATTERN "s/USE_BUILTIN_ARC4RANDOM=no/USE_BUILTIN_ARC4RANDOM=yes/g" <SOURCE_DIR>/m4/check-os-options.m4)
patch(PATTERN [===[s/\\$ac_cv_func_arc4random_buf/no/g]===] <SOURCE_DIR>/m4/check-libc.m4)

list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/arc4random_prng.c" "<SOURCE_DIR>/crypto/compat/arc4random.c")
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/arc4random_prng.h" "<SOURCE_DIR>/crypto/compat/arc4random.h")

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
