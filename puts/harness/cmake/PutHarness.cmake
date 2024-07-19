include_guard(GLOBAL)

set(_cmake_modules_root "${CMAKE_CURRENT_LIST_DIR}")
set(_put_config_h_template "${CMAKE_CURRENT_LIST_DIR}/put_config.h.in" CACHE INTERNAL "template for harness' configuration header")

# add_put(<target-name> HARNESS <harness-name> LIBRARY <lib> [SOURCES <sources>...])
function(add_put _put)
  cmake_parse_arguments(PARSE_ARGV 1 "" "" "HARNESS;LIBRARY" "SOURCES")

  get_property(CONFIG_HASH TARGET ${_LIBRARY} PROPERTY CONFIG_HASH)
  set(HARNESS_NAME ${_HARNESS})
  set(HARNESS_VERSION ${CMAKE_PROJECT_VERSION})
  set(PUT ${_put})
  set(PUT_UID "${HARNESS_NAME}${CONFIG_HASH}")

  configure_file(
    ${_put_config_h_template}
    ${CMAKE_BINARY_DIR}/put_config_${PUT_UID}.h
    ESCAPE_QUOTES
    @ONLY
  )

  define_property(TARGET PROPERTY HARNESS_NAME BRIEF_DOCS "Harness name")
  define_property(TARGET PROPERTY PUT_LIB BRIEF_DOCS "PUT library")
  define_property(TARGET PROPERTY PUT_UID BRIEF_DOCS "PUT uid")

  add_executable(${PUT} ${_SOURCES})

  set_property(TARGET ${PUT} PROPERTY VERSION ${HARNESS_VERSION})
  set_property(TARGET ${PUT} PROPERTY HARNESS_NAME ${HARNESS_NAME})
  set_property(TARGET ${PUT} PROPERTY PUT_LIB ${_LIBRARY})
  set_property(TARGET ${PUT} PROPERTY PUT_UID ${PUT_UID})

  set_property(TARGET ${PUT} PROPERTY POSITION_INDEPENDENT_CODE OFF)
  set_property(TARGET ${PUT} PROPERTY C_VISIBILITY_PRESET default)
  target_link_options(${PUT} PRIVATE -flto LINKER:-r -nodefaultlibs -nostartfiles)

  target_compile_options(${PUT} PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:--include=${CMAKE_BINARY_DIR}/put_config_$<TARGET_PROPERTY:${PUT},PUT_UID>.h>
    $<$<COMPILE_LANGUAGE:C>:--include=${CMAKE_BINARY_DIR}/put_config_$<TARGET_PROPERTY:${PUT},PUT_UID>.h>
  )

  target_link_libraries(${PUT} PRIVATE ${_LIBRARY} puts-harness-interface claims)
endfunction()

# check_cve(<target-lib> <cve>)
function(check_cve _target _cve)
  # force rerun because we might have changed the library
  unset(${_target}_has_${_cve} CACHE)

  get_target_property(_COMPILE_DEFINITIONS ${_target} INTERFACE_COMPILE_DEFINITIONS)
  get_target_property(_INCLUDE_DIRECTORIES ${_target} INTERFACE_INCLUDE_DIRECTORIES)
  get_target_property(_LINK_OPTIONS ${_target} INTERFACE_LINK_OPTIONS)
  get_target_property(_LINK_LIBRARIES ${_target} INTERFACE_LINK_LIBRARIES)
  get_target_property(LIBRARY_NAME ${_target} LIBRARY_NAME)

  string(REPLACE "-" "_" _cve_snakecase ${_cve})
  string(TOLOWER "${_cve_snakecase}" _cve_lowercase)
  string(TOUPPER "${_cve_snakecase}" _cve_uppercase)
  set(CVE_CHECK_FILE ${_cmake_modules_root}/${LIBRARY_NAME}/cve/check_${_cve_lowercase}.c)

  if(NOT EXISTS ${CVE_CHECK_FILE})
    message(FATAL_ERROR "missing cmake CVE check-file for ${_cve} (expected: ${CVE_CHECK_FILE})")
  endif()

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
    ${CVE_CHECK_FILE}
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
    message(FATAL_ERROR "failed to compile ${_target}_check_${_cve_lowercase}:\n${_COMPILE_OUTPUT}")
  endif()

  if(_EXITCODE EQUAL 0)
    target_compile_definitions(${_target} INTERFACE HAS_${_cve_uppercase}=1)
    set_property(TARGET ${_target} APPEND PROPERTY KNOWN_VULNERABILITIES ${_cve_lowercase})
  endif()
  
  unset(_EXITCODE CACHE)
  unset(_COMPILED CACHE)
  unset(_OUTPUT CACHE)
  unset(_COMPILE_OUTPUT CACHE)
endfunction()
