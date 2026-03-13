use_languages(C)

patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/0001-Puffin-dependency.patch)

cmake_builder(
  TARGETS
    install

  CMAKE_FLAGS
    -DCMAKE_BUILD_TYPE=Debug
    -DENABLE_FUZZING=OFF
    -DENABLE_PROGRAMS=OFF
    -DENABLE_SAMPLES=OFF
    -DENABLE_TESTING=OFF # To remove the dependency to Check lib.
    -DFETCHCONTENT_QUIET=OFF
    -DS2OPC_NANO_PROFILE=ON
    -DS2OPC_CLIENTSERVER_ONLY=ON
    -DS2OPC_CRYPTO_MBEDTLS=ON
    -DWITH_ASAN=OFF # Mutually exclusive with source coverage why???
    -DWITH_CLANG_SOURCE_COVERAGE=OFF
    -DWITH_PYS2OPC=OFF #No Python and hopefully no need of expat lib.
    -DPUFFIN=ON

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden
    -Wstrict-prototypes

)
