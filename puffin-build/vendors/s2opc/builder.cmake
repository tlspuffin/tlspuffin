use_languages(C)

#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Modifications-of-CLI-client-and-server.patch)

cmake_builder(
  TARGETS
    install

  CMAKE_FLAGS
    -DENABLE_SAMPLES=OFF
    -DENABLE_TESTING=OFF
    -DS2OPC_NANO_PROFILE=ON
    -DS2OPC_CLIENTSERVER_ONLY=ON
    -DS2OPC_CRYPTO_MBEDTLS=ON
    -DWITH_ASAN=OFF # Mutually exclusive with source coverage why???
    -DWITH_CLANG_SOURCE_COVERAGE=ON

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden
)
