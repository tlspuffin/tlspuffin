include_guard(GLOBAL)

cmake_policy(SET CMP0054 NEW) # if() quoted variables not dereferenced

set(_check_tls_openssl_has_claims_source_path "${CMAKE_CURRENT_LIST_DIR}/CheckHasClaims.c"
    CACHE INTERNAL "CheckTlsOpensslHasClaims source file")

function(CHECK_TLS_OPENSSL_HAS_CLAIMS _target)
  # force rerun because we might have changed the library
  unset(${_target}_HAS_CLAIMS CACHE)

  get_target_property(_COMPILE_DEFINITIONS ${_target} INTERFACE_COMPILE_DEFINITIONS)
  get_target_property(_INCLUDE_DIRECTORIES ${_target} INTERFACE_INCLUDE_DIRECTORIES)
  get_target_property(_LINK_OPTIONS ${_target} INTERFACE_LINK_OPTIONS)
  get_target_property(_LINK_LIBRARIES ${_target} INTERFACE_LINK_LIBRARIES)

  if(_LINK_OPTIONS)
    set(RUN_LINK_OPTIONS LINK_OPTIONS ${_LINK_OPTIONS})
  else()
    set(RUN_LINK_OPTIONS)
  endif()

  if(_LINK_LIBRARIES)
    set(RUN_LINK_LIBRARIES LINK_LIBRARIES ${_LINK_LIBRARIES})
  else()
    set(RUN_LINK_LIBRARIES)
  endif()

  if(_COMPILE_DEFINITIONS)
    list(TRANSFORM _COMPILE_DEFINITIONS PREPEND "-D")
    set(RUN_COMPILE_DEFINITIONS COMPILE_DEFINITIONS ${_COMPILE_DEFINITIONS})
  else()
    set(RUN_COMPILE_DEFINITIONS)
  endif()

  if(_INCLUDE_DIRECTORIES)
    set(RUN_INCLUDE_DIRECTORIES "-DINCLUDE_DIRECTORIES:STRING=${_INCLUDE_DIRECTORIES}")
  else()
    set(RUN_INCLUDE_DIRECTORIES)
  endif()

  try_run(
    _EXITCODE
    _COMPILED
    ${CMAKE_BINARY_DIR}
    ${_check_tls_openssl_has_claims_source_path}
    ${RUN_COMPILE_DEFINITIONS}
    ${RUN_LINK_OPTIONS}
    ${RUN_LINK_LIBRARIES}
    RUN_OUTPUT_VARIABLE _OUTPUT
    COMPILE_OUTPUT_VARIABLE _COMPILE_OUTPUT
    CMAKE_FLAGS
      "-DCOMPILE_DEFINITIONS:STRING=-fsanitize-coverage=trace-pc-guard"
      ${RUN_INCLUDE_DIRECTORIES}
  )

  if(NOT _COMPILED)
    message(DEBUG "failed to compile ${_target}_HAS_CLAIMS:\n${_COMPILE_OUTPUT}")
  endif()

  if(_COMPILED AND (_EXITCODE EQUAL 0))
    set(${_target}_HAS_CLAIMS "1" PARENT_SCOPE)
    target_compile_definitions(${_target} INTERFACE HAS_CLAIMS=1)
  endif()
  
  unset(_EXITCODE CACHE)
  unset(_COMPILED CACHE)
  unset(_OUTPUT CACHE)
  unset(_COMPILE_OUTPUT CACHE)
endfunction()