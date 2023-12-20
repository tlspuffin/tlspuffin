include_guard(GLOBAL)

function(add_bundle _name)
  cmake_parse_arguments(
    PARSE_ARGV
    1
    BUNDLE
    ""
    ""
    "LIBS")

  set(mri_file ${CMAKE_BINARY_DIR}/mk-${_name}.mri)
  set(out_file
      ${CMAKE_BINARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}${_name}${CMAKE_STATIC_LIBRARY_SUFFIX})

  file(WRITE ${mri_file}.in "CREATE ${out_file}\n")

  foreach(_target IN LISTS BUNDLE_LIBS)
    if(TARGET ${_target})
      get_target_property(_target_type ${_target} TYPE)
      if(_target_type STREQUAL "STATIC_LIBRARY")
        file(APPEND ${mri_file}.in "ADDLIB $<TARGET_FILE:${_target}>\n")
      endif()
    else()
      file(APPEND ${mri_file}.in "ADDLIB ${_target}\n")
    endif()
  endforeach()

  file(APPEND ${mri_file}.in "SAVE\nEND\n")

  file(GENERATE OUTPUT ${mri_file} INPUT ${mri_file}.in)

  add_custom_command(
    COMMAND ${CMAKE_AR} -M < ${mri_file} OUTPUT ${out_file} DEPENDS ${mri_file} ${BUNDLE_LIBS}
    COMMENT "Bundling ${_name}" VERBATIM)

  add_custom_target(mkbundle_${_name} ALL DEPENDS ${out_file})

  add_library(${_name} STATIC IMPORTED)
  set_target_properties(${_name} PROPERTIES IMPORTED_LOCATION ${out_file})
  add_dependencies(${_name} mkbundle_${name})
endfunction()
