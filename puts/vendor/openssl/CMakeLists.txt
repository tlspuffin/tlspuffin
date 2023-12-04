cmake_minimum_required(VERSION 3.15)

project(openssl VERSION 0.1)

if(NOT DEFINED OPENSSL_GIT_REF)
  message(
    FATAL_ERROR
      "Mandatory variable OPENSSL_VERSION is not set.\n Try `cmake -DOPENSSL_VERSION=<ref> ...`"
  )
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  # NOTE avoid interactions with system libraries
  #
  # The default value of CMAKE_INSTALL_PREFIX lies outside of the project
  # directory (e.g. /usr/local on UNIX platforms). This prefix is usually part
  # of the system-wide configuration and might break the system libraries or
  # their downstream dependencies.
  #
  # To be on the safe side, if no prefix is explicitly provided by the caller,
  # we install the library in an isolated prefix.
  set(CMAKE_INSTALL_PREFIX
      "${CMAKE_BINARY_DIR}/install"
      CACHE PATH "installation directory" FORCE)
endif()

include(ExternalProject)
ExternalProject_Add(
  openssl
  GIT_REPOSITORY https://github.com/openssl/openssl
  GIT_TAG ${OPENSSL_GIT_REF}
  GIT_SHALLOW TRUE
  UPDATE_DISCONNECTED TRUE
  PREFIX ${CMAKE_INSTALL_PREFIX}
  CONFIGURE_COMMAND
    <SOURCE_DIR>/Configure no-dso no-shared no-tests --prefix=<INSTALL_DIR>
    --openssldir=<INSTALL_DIR> --libdir=lib
  BUILD_COMMAND make --debug=b
  INSTALL_COMMAND make install_sw)
