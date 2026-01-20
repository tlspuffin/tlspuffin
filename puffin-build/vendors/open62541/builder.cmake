use_languages(C)

patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Modifications-of-CLI-client-and-server.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Instrumentation-to-debug.patch)
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Memory-leak.patch)

cmake_builder(
  TARGETS
    install

  CMAKE_FLAGS
    -DUA_ARCHITECTURE=none
    -DUA_BUILD_EXAMPLES=OFF
    -DUA_ENABLE_DA=OFF
    -DUA_ENABLE_DISCOVERY=OFF
    -DUA_ENABLE_PUBSUB=OFF
    -DUA_ENABLE_ENCRYPTION=OPENSSL
    -DUA_MULTITHREADING=0
    -DUA_NAMESPACE_ZERO=MINIMAL

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden

    # SANCOV
    $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>

    # ASAN
    $<$<BOOL:${asan}>:-DOPENSSL_NO_BUF_FREELISTS>
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

