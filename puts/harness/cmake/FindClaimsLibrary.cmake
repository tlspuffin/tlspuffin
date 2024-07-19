include_guard(GLOBAL)

function(find_claims)
  cmake_parse_arguments(PARSE_ARGV 0 "" "" "TARGET_NAME" "")

  set(CLAIMS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../tlspuffin-claims)

  add_library(${_TARGET_NAME} INTERFACE IMPORTED GLOBAL)

  set_property(TARGET ${_TARGET_NAME} PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${CLAIMS_DIR}")
endfunction()
