use_languages(C)


cmake_builder(
  TARGETS
    install

  CMAKE_FLAGS
    -DWITH_EXAMPLES=OFF
    -DWITH_GSSAPI=OFF
    -DWITH_SFTP=OFF
    -DWITH_NACL=OFF
    -DBUILD_SHARED_LIBS=OFF
    # libssh 0.8.x builds its main target shared unconditionally and only emits a
    # static archive under these knobs; newer libssh (0.9+) ignores them and uses
    # BUILD_SHARED_LIBS=OFF. Setting both keeps every version producing libssh.a.
    -DBUILD_STATIC_LIB=ON
    -DWITH_STATIC_LIB=ON
    -DCMAKE_POLICY_DEFAULT_CMP0148:STRING=OLD

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
)
