function(find_openssl _openssl_root)
  # NOTE search for OpenSSL in _openssl_root
  #
  #   Try to infer libdir and incdir by checking in order:
  #
  #     1. use cmake built-in FindOpenSSL.cmake module
  #
  #     2. if a pkg-config file named openssl.pc exists in standard locations
  #        in the directory
  #
  #     3. if files libssl.a/libcrypto.a (for libdir) and openssl/ssl.h (for
  #        incdir) exist in the directory
  #

  cmake_parse_arguments(PARSE_ARGV 1 "PARSED" "" "NAME_PREFIX" "")

  # FIXME using FindOpenSSL is broken when ZLIB is not found

  # find_openssl_with_cmake(${_openssl_root})
  # if(FP_OPENSSL_FOUND)
  #   set(${PARSED_NAME_PREFIX}_VERSION "${FP_OPENSSL_VERSION}" PARENT_SCOPE)
  #   set(${PARSED_NAME_PREFIX}_INCLUDE_DIRS "${FP_OPENSSL_INCLUDE_DIRS}" PARENT_SCOPE)
  #   set(${PARSED_NAME_PREFIX}_LIBRARIES "${FP_OPENSSL_LINK_LIBRARIES}" PARENT_SCOPE)
  #   set(${PARSED_NAME_PREFIX}_HAS_CLAIMS "${FP_OPENSSL_HAS_CLAIMS}" PARENT_SCOPE)
  #   return()
  # endif()

  find_openssl_with_pkgconfig(${_openssl_root})
  if(PC_OPENSSL_FOUND)
    set(${PARSED_NAME_PREFIX}_VERSION "${PC_OPENSSL_VERSION}" PARENT_SCOPE)
    set(${PARSED_NAME_PREFIX}_INCLUDE_DIRS "${PC_OPENSSL_INCLUDE_DIRS}" PARENT_SCOPE)
    set(${PARSED_NAME_PREFIX}_LIBRARIES "${PC_OPENSSL_LINK_LIBRARIES}" PARENT_SCOPE)
    set(${PARSED_NAME_PREFIX}_HAS_CLAIMS "${PC_OPENSSL_HAS_CLAIMS}" PARENT_SCOPE)
    return()
  endif()

  find_openssl_with_names(${_openssl_root})
  if(NN_OPENSSL_FOUND)
    set(${PARSED_NAME_PREFIX}_VERSION "${NN_OPENSSL_VERSION}" PARENT_SCOPE)
    set(${PARSED_NAME_PREFIX}_INCLUDE_DIRS "${NN_OPENSSL_INCLUDE_DIRS}" PARENT_SCOPE)
    set(${PARSED_NAME_PREFIX}_LIBRARIES "${NN_OPENSSL_LINK_LIBRARIES}" PARENT_SCOPE)
    set(${PARSED_NAME_PREFIX}_HAS_CLAIMS "${NN_OPENSSL_HAS_CLAIMS}" PARENT_SCOPE)
    return()
  endif()
endfunction()

function(find_openssl_with_cmake _openssl_root)
  unset(OpenSSL_FOUND CACHE)
  unset(OPENSSL_FOUND CACHE)
  unset(OPENSSL_VERSION CACHE)
  unset(OpenSSL_VERSION CACHE)
  unset(OPENSSL_CRYPTO_LIBRARY CACHE)
  unset(OPENSSL_INCLUDE_DIR CACHE)
  unset(OPENSSL_FIND_VERSION CACHE)

  set(OPENSSL_ROOT_DIR ${_openssl_root})
  set(OPENSSL_USE_STATIC_LIBS ON)
  find_package(OpenSSL COMPONENTS Crypto SSL)

  set(_FP_OPENSSL_FOUND "${OPENSSL_FOUND}")
  set(_FP_OPENSSL_INCLUDE_DIRS "${OPENSSL_INCLUDE_DIR}")
  set(_FP_OPENSSL_LINK_LIBRARIES "${OPENSSL_SSL_LIBRARY};${OPENSSL_CRYPTO_LIBRARY}")

  check_openssl_has_claims(_FP_OPENSSL "${_FP_OPENSSL_INCLUDE_DIRS}"
                           "${_FP_OPENSSL_LINK_LIBRARIES}")
  check_openssl_version(_FP_OPENSSL "${_FP_OPENSSL_INCLUDE_DIRS}" "${_FP_OPENSSL_LINK_LIBRARIES}")
  if(NOT DEFINED _FP_OPENSSL_VERSION)
    # fallback to cmake-provided version
    message(AUTHOR_WARNING "version not found")
    set(_FP_OPENSSL_VERSION ${OPENSSL_VERSION})
  endif()

  set(FP_OPENSSL_FOUND ${_FP_OPENSSL_FOUND} PARENT_SCOPE)
  set(FP_OPENSSL_VERSION ${_FP_OPENSSL_VERSION} PARENT_SCOPE)
  set(FP_OPENSSL_HAS_CLAIMS ${_FP_OPENSSL_HAS_CLAIMS} PARENT_SCOPE)
  set(FP_OPENSSL_INCLUDE_DIRS ${_FP_OPENSSL_INCLUDE_DIRS} PARENT_SCOPE)
  set(FP_OPENSSL_LINK_LIBRARIES ${_FP_OPENSSL_LINK_LIBRARIES} PARENT_SCOPE)
endfunction()

function(find_openssl_with_pkgconfig _openssl_root)
  unset(_PC_OPENSSL_FOUND CACHE)

  # NOTE this indirectly adds _openssl_root to PKG_CONFIG_PATH
  #
  #     CMAKE_PREFIX_PATH is appended to PKG_CONFIG_PATH, resulting in
  #     OPENSSL_ROOT being the preferred search location when calling
  #     `pkg_check_modules`.
  set(CMAKE_PREFIX_PATH ${_openssl_root})

  find_package(PkgConfig QUIET)
  pkg_check_modules(_PC_OPENSSL QUIET openssl)

  if(NOT _PC_OPENSSL_FOUND)
    set(PC_OPENSSL_FOUND FALSE PARENT_SCOPE)
    return()
  endif()

  cmake_path(IS_PREFIX _openssl_root "${_PC_OPENSSL_PREFIX}/" NORMALIZE is_own_openssl)
  if(NOT is_own_openssl)
    # NOTE avoid defaulting to system OpenSSL
    #
    # There is no easy and portable way to set pkg-config to only look at
    # packages in the OPENSSL_ROOT folder, so we need to extra-check that we
    # don't default to the system OpenSSL if it exists.
    #
    # Our strategy is to set OPENSSL_ROOT as the preferred search path for
    # pkg-config and check afterwards that the found version is actually in this
    # folder.
    set(PC_OPENSSL_FOUND FALSE PARENT_SCOPE)
    return()
  endif()

  check_openssl_has_claims(_PC_OPENSSL "${_PC_OPENSSL_INCLUDE_DIRS}"
                           "${_PC_OPENSSL_LINK_LIBRARIES}")
  check_openssl_version(_PC_OPENSSL "${_PC_OPENSSL_INCLUDE_DIRS}" "${_PC_OPENSSL_LINK_LIBRARIES}")
  if(NOT DEFINED _PC_OPENSSL_VERSION)
    # fallback to pkgconfig-provided version
    message(AUTHOR_WARNING "version not found")
    set(_PC_OPENSSL_VERSION ${PC_OPENSSL_VERSION})
  endif()

  set(PC_OPENSSL_FOUND ${_PC_OPENSSL_FOUND} PARENT_SCOPE)
  set(PC_OPENSSL_VERSION ${_PC_OPENSSL_VERSION} PARENT_SCOPE)
  set(PC_OPENSSL_HAS_CLAIMS ${_PC_OPENSSL_HAS_CLAIMS} PARENT_SCOPE)
  set(PC_OPENSSL_INCLUDE_DIRS ${_PC_OPENSSL_INCLUDE_DIRS} PARENT_SCOPE)
  set(PC_OPENSSL_LINK_LIBRARIES ${_PC_OPENSSL_LINK_LIBRARIES} PARENT_SCOPE)
endfunction()

function(find_openssl_with_names _openssl_root)
  unset(_SSL CACHE)
  find_library(_SSL NAMES ${CMAKE_STATIC_LIBRARY_PREFIX}ssl${CMAKE_STATIC_LIBRARY_SUFFIX}
               NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

  unset(_CRYPTO CACHE)
  find_library(_CRYPTO NAMES ${CMAKE_STATIC_LIBRARY_PREFIX}crypto${CMAKE_STATIC_LIBRARY_SUFFIX}
               NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

  find_path(_INCDIR NAMES openssl/ssl.h HINTS ${_openssl_root} PATH_SUFFIXES "include"
            NO_DEFAULT_PATH)

  if(NOT _SSL OR NOT _CRYPTO OR NOT _INCDIR)
    set(NN_OPENSSL_FOUND FALSE PARENT_SCOPE)
    return()
  endif()

  set(_NN_OPENSSL_FOUND TRUE)
  check_openssl_has_claims(_NN_OPENSSL "${_INCDIR}" "${_SSL};${_CRYPTO}")
  check_openssl_version(_NN_OPENSSL "${_INCDIR}" "${_SSL};${_CRYPTO}")
  if(NOT DEFINED _NN_OPENSSL_VERSION)
    message(AUTHOR_WARNING "version not found")
    set(_NN_OPENSSL_VERSION "unknown")
  endif()

  set(NN_OPENSSL_FOUND ${_NN_OPENSSL_FOUND} PARENT_SCOPE)
  set(NN_OPENSSL_VERSION ${_NN_OPENSSL_VERSION} PARENT_SCOPE)
  set(NN_OPENSSL_HAS_CLAIMS ${_NN_OPENSSL_HAS_CLAIMS} PARENT_SCOPE)
  set(NN_OPENSSL_INCLUDE_DIRS ${_INCDIR} PARENT_SCOPE)
  set(NN_OPENSSL_LINK_LIBRARIES ${_SSL};${_CRYPTO} PARENT_SCOPE)
endfunction()

set(_check_openssl_has_claims_source_path "${CMAKE_CURRENT_LIST_DIR}/CheckOpenSSLHasClaims.c"
    CACHE INTERNAL "CheckOpenSSLHasClaims source file")

set(_check_openssl_version_source_path "${CMAKE_CURRENT_LIST_DIR}/CheckOpenSSLVersion.c"
    CACHE INTERNAL "CheckOpenSSLVersion source file")

macro(CHECK_OPENSSL_HAS_CLAIMS _prefix _incdirs _libs)
  if(NOT ${_prefix}_FOUND)
    message(FATAL_ERROR "tried check HAS_CLAIMS but no OpenSSL has been configured")
  endif()

  file(READ "${_check_openssl_has_claims_source_path}" _check_has_claims_source)

  set(CMAKE_REQUIRED_INCLUDES "${_incdirs}")
  set(CMAKE_REQUIRED_LIBRARIES "${_libs};claims")
  set(CMAKE_REQUIRED_QUIET ON)

  include(CheckCSourceRuns)
  check_c_source_runs("${_check_has_claims_source}" ${_prefix}_HAS_CLAIMS)

  unset(_OPENSSL_CFLAGS_ARGS)

  # TODO restore previous values of CMAKE_REQUIRED_*
  unset(CMAKE_REQUIRED_FLAGS)
  unset(CMAKE_REQUIRED_LIBRARIES)
  unset(CMAKE_REQUIRED_QUIET)
  unset(_check_has_claims_source)
endmacro()

macro(CHECK_OPENSSL_VERSION _prefix _incdirs _libs)
  if(NOT ${_prefix}_FOUND)
    message(FATAL_ERROR "tried check VERSION but no OpenSSL has been configured")
  endif()

  try_run(
    ${_prefix}_EXITCODE
    ${_prefix}_COMPILED
    ${CMAKE_BINARY_DIR}
    ${_check_openssl_version_source_path}
    LINK_LIBRARIES ${_libs}
    RUN_OUTPUT_VARIABLE ${_prefix}_OUTPUT
    COMPILE_OUTPUT_VARIABLE ${_prefix}_COMPILE_OUTPUT
    CMAKE_FLAGS -DINCLUDE_DIRECTORIES:STRING=${_incdirs}
  )

  if(${${_prefix}_COMPILED} AND ${${_prefix}_EXITCODE} EQUAL 0)
    set(${_prefix}_VERSION ${${_prefix}_OUTPUT})
  endif()

  unset(${_prefix}_EXITCODE)
  unset(${_prefix}_COMPILED)
  unset(${_prefix}_OUTPUT)
  unset(${_prefix}_COMPILE_OUTPUT)
endmacro()

if(DEFINED openssl_OPTIONAL_NAME_PREFIX)
  set(pkg_prefix ${openssl_OPTIONAL_NAME_PREFIX})
elseif(DEFINED OPENSSL_OPTIONAL_NAME_PREFIX)
  set(pkg_prefix ${OPENSSL_OPTIONAL_NAME_PREFIX})
else()
  set(pkg_prefix openssl)
endif()

if(DEFINED openssl_ROOT)
  set(${pkg_prefix}_ROOT ${openssl_ROOT})
elseif(DEFINED OPENSSL_ROOT)
  set(${pkg_prefix}_ROOT ${OPENSSL_ROOT})
else()
  message(FATAL_ERROR "missing mandatory variable openssl_ROOT")
endif()

find_openssl("${${pkg_prefix}_ROOT}" NAME_PREFIX ${pkg_prefix})

set(pkg_vars "")
list(APPEND pkg_vars ${pkg_prefix}_ROOT)
list(APPEND pkg_vars ${pkg_prefix}_VERSION)
list(APPEND pkg_vars ${pkg_prefix}_LIBRARIES)
list(APPEND pkg_vars ${pkg_prefix}_INCLUDE_DIRS)
list(APPEND pkg_vars ${pkg_prefix}_HAS_CLAIMS)

set(missing_vars "")
foreach(var IN LISTS pkg_vars)
  if(NOT DEFINED ${var})
    list(APPEND missing_vars ${var})
  endif()
endforeach()

if(NOT missing_vars)
  set(openssl_FOUND TRUE)
  set(OPENSSL_FOUND TRUE)
  set(${pkg_prefix}_FOUND TRUE)
else()
  if(openssl_FIND_REQUIRED)
    message(FATAL_ERROR "OpenSSL was not found in path ${${pkg_prefix}_ROOT}")
  endif()
endif()

unset(var)
unset(missing_vars)

unset(pkg_prefix)
unset(pkg_vars)
