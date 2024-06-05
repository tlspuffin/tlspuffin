include_guard(GLOBAL)

cmake_policy(SET CMP0054 NEW) # if() quoted variables not dereferenced

set(_check_openssl_version_source_path "${CMAKE_CURRENT_LIST_DIR}/CheckVersion.c"
    CACHE INTERNAL "CheckVersion source file")

function(CHECK_OPENSSL_VERSION _target)
  # force rerun because we might have changed the library
  unset(${_target}_VERSION CACHE)

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
    ${_check_openssl_version_source_path}
    ${RUN_COMPILE_DEFINITIONS}
    ${RUN_LINK_OPTIONS}
    ${RUN_LINK_LIBRARIES}
    RUN_OUTPUT_VARIABLE _OUTPUT
    COMPILE_OUTPUT_VARIABLE _COMPILE_OUTPUT
    CMAKE_FLAGS
      "-DCOMPILE_DEFINITIONS:STRING=-fsanitize-coverage=trace-pc-guard"
      ${RUN_INCLUDE_DIRECTORIES}
  )

  if(_COMPILED AND (_EXITCODE EQUAL 0))
    set(${_target}_VERSION ${_OUTPUT} PARENT_SCOPE)
  endif()

  unset(_EXITCODE CACHE)
  unset(_COMPILED CACHE)
  unset(_OUTPUT CACHE)
  unset(_COMPILE_OUTPUT CACHE)
endfunction()
