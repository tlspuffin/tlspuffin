use_languages(C CXX)

patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/no_asan.patch)
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/extract_transcript.patch)
patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/reset_drbg.patch)

cmake_builder(
  TARGETS
    ssl
    crypto

  CMAKE_FLAGS
    -DBUILD_SHARED_LIBS=OFF

    # NOTE need both flags FUZZ and NO_FUZZER_MODE
    #
    # The FUZZ flag will enable deterministic mode in BoringSSL but disables all encryption.
    # To prevent BoringSSL from disabling encryption we also pass the NO_FUZZER_MODE flag.
    #
    # See https://github.com/google/boringssl/blob/master/FUZZING.md for details
    -DFUZZ=1
    -DNO_FUZZER_MODE=1

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden
    -I${CMAKE_SOURCE_DIR}/../../tlspuffin-claims
    -Wno-error
    -Wstrict-prototypes

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

  CXXFLAGS
    -g
    -fPIC
    -fvisibility=hidden
    -I${CMAKE_SOURCE_DIR}/../../tlspuffin-claims
    -Wno-error
    -Wstrict-prototypes

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

list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E make_directory "<INSTALL_DIR>/${CMAKE_INSTALL_LIBDIR}/")
list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E make_directory "<INSTALL_DIR>/${CMAKE_INSTALL_INCLUDEDIR}/")
list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "<BINARY_DIR>/crypto/libcrypto.a" "<INSTALL_DIR>/${CMAKE_INSTALL_LIBDIR}/")
list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "<BINARY_DIR>/ssl/libssl.a"       "<INSTALL_DIR>/${CMAKE_INSTALL_LIBDIR}/")
list(APPEND INSTALL_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy_directory "<SOURCE_DIR>/include"  "<INSTALL_DIR>/${CMAKE_INSTALL_INCLUDEDIR}")
