include_guard(GLOBAL)

function(find_openssl _openssldir)
  cmake_parse_arguments(PARSE_ARGV 1 "" "" "TARGET_NAME" "")
  find_openssl_pkgconfig("${_openssldir}" "${_TARGET_NAME}")

  add_library(${_TARGET_NAME} INTERFACE IMPORTED GLOBAL)
  set_target_properties(
    ${_TARGET_NAME}
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${${_TARGET_NAME}_INCLUDE_DIRS}"
               INTERFACE_LINK_LIBRARIES "${${_TARGET_NAME}_LINK_LIBRARIES}"
               INTERFACE_LINK_OPTIONS "${${_TARGET_NAME}_LDFLAGS_OTHER}"
               INTERFACE_COMPILE_OPTIONS "${${_TARGET_NAME}_CFLAGS_OTHER}"
               HAS_CLAIMS "${${_TARGET_NAME}_HAS_CLAIMS}")

  if(${_TARGET_NAME}_HAS_CLAIMS)
    target_compile_definitions(${_TARGET_NAME} INTERFACE HAS_CLAIMS=1)
  endif()
endfunction()

macro(find_openssl_pkgconfig _openssldir _prefix)
  unset(${_prefix}_FOUND CACHE)
  unset(${_prefix}_HAS_CLAIMS CACHE)

  # NOTE this indirectly adds OPENSSL_DIR to PKG_CONFIG_PATH
  #
  # CMAKE_PREFIX_PATH is appended to PKG_CONFIG_PATH, resulting in OPENSSL_DIR
  # being the prefered search location when calling `pkg_check_modules`.
  set(CMAKE_PREFIX_PATH ${_openssldir})

  include(FindPkgConfig)
  pkg_check_modules(${_prefix} QUIET openssl)

  if(NOT ${_prefix}_FOUND)
    message(
      FATAL_ERROR
        "OPENSSLDIR does not contain a valid installation of OpenSSL.\n"
        "  got OPENSSLDIR=${_openssldir}")
  endif()

  cmake_path(IS_PREFIX _openssldir "${${_prefix}_PREFIX}" NORMALIZE
             is_own_openssl)
  if(NOT is_own_openssl)
    # NOTE avoid defaulting to system OpenSSL
    #
    # There is no easy and portable way to set pkg-config to only look at
    # packages in the OPENSSL_DIR folder, so we need to extra-check that we
    # don't default to the system OpenSSL if it exists.
    #
    # Our strategy is to set OPENSSL_DIR as the preferred search path for
    # pkg-config and check afterwards that the found version is actually in this
    # folder.
    message(
      FATAL_ERROR
        "OPENSSLDIR does not contain a valid installation of OpenSSL.\n"
        "  got OPENSSLDIR=${_openssldir}"
        "  but found PKG_CONFIG_OPENSSL=${${_prefix}_PREFIX}")
  endif()

  check_openssl_has_claims(${_prefix})
endmacro()

set(_check_openssl_has_claims_source_path
    "${CMAKE_CURRENT_LIST_DIR}/CheckOpenSSLHasClaims.c"
    CACHE INTERNAL "CheckOpenSSLHasClaims source file")

macro(CHECK_OPENSSL_HAS_CLAIMS _prefix)
  if(NOT ${_prefix}_FOUND)
    message(
      FATAL_ERROR "tried check HAS_CLAIMS but no OpenSSL has been configured")
  endif()

  file(READ "${_check_openssl_has_claims_source_path}" _check_has_claims_source)

  string(REPLACE ";" " " _OPENSSL_CFLAGS_ARGS "${${_prefix}_STATIC_CFLAGS}")
  set(CMAKE_REQUIRED_FLAGS "${_OPENSSL_CFLAGS_ARGS}")
  set(CMAKE_REQUIRED_LIBRARIES "${${_prefix}_LINK_LIBRARIES}" claims)

  include(CheckCSourceRuns)
  check_c_source_runs("${_check_has_claims_source}" ${_prefix}_HAS_CLAIMS)

  unset(_OPENSSL_CFLAGS_ARGS)
  unset(CMAKE_REQUIRED_FLAGS)
  unset(CMAKE_REQUIRED_LIBRARIES)
  unset(_check_has_claims_source)
endmacro()
