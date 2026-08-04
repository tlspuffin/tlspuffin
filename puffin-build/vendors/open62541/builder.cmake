use_languages(C)

patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Modifications-of-CLI-client-and-server.patch)
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Instrumentation-to-debug.patch)
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-fix-of-ClientUserId.patch)

# Bug injection:
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Buffer_overflow.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-Certificate-Thumbprint.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-bad-certificate.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-bad-policy.patch)
#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-bad-switch.patch)
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Bug-dead-session.patch)

cmake_builder(
  TARGETS
    install

  CMAKE_FLAGS
    -DCMAKE_BUILD_TYPE=Debug
    -DUA_ARCHITECTURE=none
    -DUA_BUILD_EXAMPLES=OFF
    -DUA_ENABLE_DA=OFF
    -DUA_ENABLE_DISCOVERY=ON
    -DUA_ENABLE_PUBSUB=OFF
    -DUA_ENABLE_PUBSUB_INFORMATIONMODEL=OFF
    -DUA_ENABLE_SUBSCRIPTIONS_EVENTS=OFF
    -DUA_ENABLE_ENCRYPTION=OPENSSL
    -DUA_MULTITHREADING=0
    -DUA_NAMESPACE_ZERO=MINIMAL
    -DUA_ENABLE_DEBUG_SANITIZER=$<IF:$<BOOL:${asan}>,ON,OFF>

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden
    -Wstrict-prototypes

    # SANCOV
    $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>

    # ASAN / UBSAN
    $<$<BOOL:${asan}>:-DOPENSSL_NO_BUF_FREELISTS>
    $<$<BOOL:${asan}>:-fsanitize=address,undefined>
    $<$<BOOL:${asan}>:-static-libsan>
    $<$<NOT:$<BOOL:${asan}>>:-fno-sanitize=all>

    # LLVM_COV
    $<$<BOOL:${llvm_cov}>:-fprofile-instr-generate>
    $<$<BOOL:${llvm_cov}>:-fcoverage-mapping>
    $<$<BOOL:${llvm_cov}>:-O0>

    # LLVM GCOV
    $<$<BOOL:${gcov}>:-ftest-coverage>
    $<$<BOOL:${gcov}>:-fprofile-arcs>
    $<$<BOOL:${gcov}>:-O0>

)

