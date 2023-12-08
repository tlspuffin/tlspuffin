include_guard(GLOBAL)

set(_check_openssl_has_claims_source_path
    "${CMAKE_CURRENT_LIST_DIR}/CheckOpenSSLHasClaims.c"
    CACHE INTERNAL "CheckOpenSSLHasClaims source file")

macro(CHECK_OPENSSL_HAS_CLAIMS CLAIMS_INCDIR)
  if(NOT OPENSSL_FOUND)
    message(
      FATAL_ERROR
        "tried check OPENSSL_HAS_CLAIMS but no OpenSSL has been configured")
  endif()

  file(READ "${_check_openssl_has_claims_source_path}" _check_has_claims_source)

  string(REPLACE ";" " " _OPENSSL_CFLAGS_ARGS "${OPENSSL_STATIC_CFLAGS}")
  set(CMAKE_REQUIRED_FLAGS "${_OPENSSL_CFLAGS_ARGS} -I${CLAIMS_INCDIR}")
  set(CMAKE_REQUIRED_LIBRARIES "${OPENSSL_LINK_LIBRARIES}")

  include(CheckCSourceRuns)
  check_c_source_runs("${_check_has_claims_source}" OPENSSL_HAS_CLAIMS)

  unset(_OPENSSL_CFLAGS_ARGS)
  unset(CMAKE_REQUIRED_FLAGS)
  unset(CMAKE_REQUIRED_LIBRARIES)
  unset(_check_has_claims_source)
endmacro()
