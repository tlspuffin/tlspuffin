cmake_minimum_required(VERSION 3.15)

project(
  openssl
  VERSION 0.1
  LANGUAGES C)

if(NOT DEFINED OPENSSL_GIT_REF)
  message(
    FATAL_ERROR
      "Mandatory variable OPENSSL_GIT_REF is not set.\n Try `cmake -DOPENSSL_GIT_REF=<ref> ...`"
  )
endif()

if(NOT DEFINED OPENSSL_GIT_REPO)
  # TODO (question) should we replace forked repo with patches?
  set(OPENSSL_GIT_REPO "https://github.com/tlspuffin/openssl")
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

set(CONFIGURE_FEATURES no-dso no-shared no-tests)
set(CONFIGURE_FLAGS --debug --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>
                    --libdir=lib)
set(CONFIGURE_EXTRA -I${CMAKE_SOURCE_DIR}/../../../tlspuffin-claims)

if(DEFINED OPENSSL_TARGET)
  set(CONFIGURE_COMMAND <SOURCE_DIR>/Configure ${CONFIGURE_FEATURES}
                        ${CONFIGURE_FLAGS} ${OPENSSL_TARGET} ${CONFIGURE_EXTRA})
else()
  # Fallback to letting OpenSSL try to guess the target platform
  set(CONFIGURE_COMMAND <SOURCE_DIR>/config ${CONFIGURE_FEATURES}
                        ${CONFIGURE_FLAGS} ${CONFIGURE_EXTRA})
endif()

include(ExternalProject)
ExternalProject_Add(
  openssl
  GIT_REPOSITORY ${OPENSSL_GIT_REPO}
  GIT_TAG ${OPENSSL_GIT_REF}
  GIT_SHALLOW TRUE
  UPDATE_DISCONNECTED TRUE
  PREFIX ${CMAKE_INSTALL_PREFIX}
  CONFIGURE_COMMAND ${CONFIGURE_COMMAND}
  BUILD_COMMAND make --debug=b
  INSTALL_COMMAND make install_sw)
