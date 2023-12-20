macro(parse_put_args _prefix)
  get_cmake_property(_vars VARIABLES)
  parse_put_args_from_vars(${_prefix} _vars)
endmacro()

macro(parse_put_args_from_vars _prefix _vars)
  set(${_prefix}_PUTS "")

  foreach(_var IN LISTS _vars)
    if(_var MATCHES "^VENDOR_DIR$")
      # force conversion of VENDOR_DIR to absolute path
      set(VENDOR_DIR "" CACHE PATH "path to a vendor dir containing PUT libraries")

      parse_vendor_dir_arg(${_prefix} ${${_var}})
    elseif(_var MATCHES "^WITH_([A-Za-z0-9_]*)$")
      # force conversion of WITH_<put> content to absolute paths
      set(${_var} "" CACHE PATH "path to a prefix containing the ${CMAKE_MATCH_1} PUT")

      parse_with_arg(${_prefix} "${CMAKE_MATCH_1}")
    else()
      continue()
    endif()
  endforeach()

  list(REMOVE_DUPLICATES ${_prefix}_PUTS)
endmacro()

macro(parse_with_arg _prefix put_prefix)
  list(APPEND ${_prefix}_PUTS ${put_prefix})

  string(REPLACE "," ";" ${_prefix}_${put_prefix}_DIRS "${WITH_${put_prefix}}")
  list(REMOVE_DUPLICATES ${_prefix}_${put_prefix}_DIRS)

  string(TOLOWER "${put_prefix}" ${_prefix}_${put_prefix}_NAME)

  unset(put_prefix)
endmacro()

macro(parse_vendor_dir_arg _prefix vendor_dir)
  if(NOT IS_ABSOLUTE ${vendor_dir})
    message(FATAL_ERROR "cannot find VENDOR_DIR with relative path '${vendor_dir}'")
  endif()

  if(NOT IS_DIRECTORY ${vendor_dir})
    message(WARNING "skipping invalid directory '${vendor_dir}'")
    continue()
  endif()

  file(
    GLOB puts
    RELATIVE ${vendor_dir}
    ${vendor_dir}/*
  )

  foreach(put_name IN LISTS puts)
    if(NOT IS_DIRECTORY ${vendor_dir}/${put_name})
      continue()
    endif()

    string(TOUPPER "${put_name}" put_prefix)
    list(APPEND ${_prefix}_PUTS ${put_prefix})
    set(${_prefix}_${put_prefix}_NAME ${put_name})

    set(${_prefix}_${put_prefix}_DIRS "")
    file(GLOB put_dirs RELATIVE ${vendor_dir}/${put_name} ${vendor_dir}/${put_name}/*)
    foreach(put_dir IN LISTS put_dirs)
      if(NOT IS_DIRECTORY ${vendor_dir}/${put_name}/${put_dir})
        continue()
      endif()

      list(APPEND ${_prefix}_${put_prefix}_DIRS ${vendor_dir}/${put_name}/${put_dir})
    endforeach()
  endforeach()

  unset(puts)
  unset(put_name)
  unset(put_prefix)
  unset(put_dir)
endmacro()
