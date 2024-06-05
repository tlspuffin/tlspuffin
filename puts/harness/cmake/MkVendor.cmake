include_guard(GLOBAL)

# read_mk_vendor(<conf-file-path> <out-var> <match-config> [DEFAULT <default-value>])
#
# Example:
#   read_mk_vendor("<path_to>/mk_vendor.conf" WITH_SANCOV "BUILD_ARG:-DWITH_SANCOV" DEFAULT OFF)
function(read_mk_vendor _path _out_var _mkv_var)
  cmake_parse_arguments(PARSE_ARGV 3 "_ARG" "" "DEFAULT" "")

  file(STRINGS "${_path}" MK_VENDOR_META REGEX "^${_mkv_var}")
  foreach(var IN LISTS MK_VENDOR_META)
      string(REGEX REPLACE "${_mkv_var}[=:]" "" _RESULT "${var}")
  endforeach()

  if((NOT DEFINED _RESULT) AND (DEFINED _ARG_DEFAULT))
      set(_RESULT ${_ARG_DEFAULT})
  endif()

  if(DEFINED _RESULT)
    set(${_out_var} ${_RESULT} PARENT_SCOPE)
  else()
    unset(${_out_var} PARENT_SCOPE)
  endif()
endfunction()
