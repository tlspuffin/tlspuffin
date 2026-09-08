use_languages(C)

#patch(FILE ${CMAKE_CURRENT_LIST_DIR}/patches/Modifications-of-CLI-client-and-server.patch)

include(FetchContent)

set(MBEDTLS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_TLS1_3 ON CACHE BOOL "" FORCE)

FetchContent_Declare(
  mbedtls
  GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
  GIT_TAG v3.6.5
  )

FetchContent_MakeAvailable(mbedtls)

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
    -DMBEDTLS_INCLUDE_DIR=${mbedtls_SOURCE_DIR}/include
    -DMBEDTLS_LIBRARY=${mbedtls_SOURCE_DIR}/library
    -DMBEDX509_LIBRARY=${mbedtls_SOURCE_DIR}/library
    -DMBEDCRYPTO_LIBRARY=${mbedtls_SOURCE_DIR}/library

  CFLAGS
    -g
    -fPIC
    -fvisibility=hidden
)
