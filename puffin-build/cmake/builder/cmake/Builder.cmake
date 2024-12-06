include_guard(GLOBAL)

include(CheckLanguage)

# use_languages(<lang>...)
#
# For a list of support languages, see: https://cmake.org/cmake/help/latest/command/enable_language.html
#
# Examples:
#   use_languages(C)
#   use_languages(C CXX Fortran)
macro(use_languages)
  foreach(language ${ARGV})
    check_language(${language})
    if(CMAKE_${language}_COMPILER)
      enable_language(${language})
    else()
      message(FATAL_ERROR "No support for language '${language}'")
    endif()
  endforeach()

  if(${ARGC})
    include(GNUInstallDirs)
  endif()
endmacro()


# patch(PATTERN "s@foo@bar@" <source>...)
# patch(FILE xyz.patch [DIR <source_dir>])
macro(patch)
  set(_ARGS ${ARGN})
  list(POP_FRONT _ARGS _ARG_PATCH_KIND)

  if(_ARG_PATCH_KIND STREQUAL "FILE")

    cmake_parse_arguments("_ARG" "" "FILE;DIR" "" ${ARGN})

    if(NOT DEFINED _ARG_DIR)
      set(_ARG_DIR "<SOURCE_DIR>")
    endif()

    # FIXME we leverage `git-apply` to apply the patch consistently across platforms
    #
    # Unfortunately, CMake doesn't expose a cross-platform way to apply a patch and is unlikely to
    # do so in the future. Since `git` is part of our dependencies, we can use it here. But it would
    # be better to not rely on it being present.
    #
    # upstream issue: https://gitlab.kitware.com/cmake/cmake/-/issues/16854
    list(APPEND PATCH_COMMANDS COMMAND git -C "${_ARG_DIR}" --git-dir= apply -v --stat --check --apply "${_ARG_FILE}")

    unset(_ARG_FILE)
    unset(_ARG_DIR)

  elseif(_ARG_PATCH_KIND STREQUAL "PATTERN")

    list(POP_FRONT _ARGS _ARG_PATTERN)
    foreach(_ARG_SOURCE IN LISTS _ARGS)
      list(APPEND PATCH_COMMANDS COMMAND perl -pi.bak -e "${_ARG_PATTERN}" "${_ARG_SOURCE}")
    endforeach()

    unset(_ARG_PATTERN)
    unset(_ARG_SOURCE)

  endif()

  unset(_ARGS)
  unset(_ARG_PATCH_KIND)
endmacro()


# autotools_builder(
#   [ENV <var>=<val>...]
#   [FEATURES <configure-flag>...]
#   [CFLAGS <cflag>...]
#   [CXXFLAGS <cxxflag>...]
#   [LDFLAGS <ldflag>...]
#   [BUILD_TARGETS <targets>...]
#   [INSTALL_TARGET <target>]
#   [SOURCE_DIR <SOURCE_DIR>]
#  )
#
# Add builder commands for an `autotools`-based project.
#
# Examples:
#   autotools_builder(
#     ENV
#       "PATH=/my/sysroot/toolchain/bin/"
#     FEATURES
#       --enable-xyz
#       --disable-abc
#     CFLAGS
#       -Wall
#       -Wpedantic
#     CXXFLAGS
#       --std=c++14
#   )
macro(autotools_builder)
  cmake_parse_arguments("_ARG" "" "SOURCE_DIR;INSTALL_TARGET" "ENV;FEATURES;CFLAGS;CXXFLAGS;LDFLAGS;BUILD_TARGETS" ${ARGN})

  if(NOT DEFINED _ARG_SOURCE_DIR)
    set(_ARG_SOURCE_DIR "<SOURCE_DIR>")
  endif()

  if(NOT DEFINED _ARG_INSTALL_TARGET)
    set(_ARG_INSTALL_TARGET "install")
  endif()

  list(JOIN _ARG_CFLAGS " " _ARG_CFLAGS)
  list(JOIN _ARG_CXXFLAGS " " _ARG_CXXFLAGS)
  list(JOIN _ARG_LDFLAGS " " _ARG_LDFLAGS)

  list(APPEND CONFIGURE_COMMANDS COMMAND autoreconf -v --install --force "${_ARG_SOURCE_DIR}")
  list(APPEND CONFIGURE_COMMANDS COMMAND
    ${CMAKE_COMMAND} -E chdir "${_ARG_SOURCE_DIR}"
    ${CMAKE_COMMAND} -E env
        "CXX=${CMAKE_CXX_COMPILER}"
        "CPP=${CMAKE_C_COMPILER} -E"
        "CC=${CMAKE_C_COMPILER}"
        "AR=${CMAKE_AR}"
        "RANLIB=${CMAKE_RANLIB}"
        "NM=${CMAKE_NM}"
        "STRIP=${CMAKE_STRIP}"
        "CFLAGS=${_ARG_CFLAGS}"
        "CXXFLAGS=${_ARG_CXXFLAGS}"
        "LDFLAGS=${_ARG_LDFLAGS}"
        ${_ARG_ENV}
      ./configure "--prefix=${CMAKE_INSTALL_PREFIX}" ${_ARG_FEATURES}
  )

  list(APPEND BUILD_COMMANDS COMMAND make -C "${_ARG_SOURCE_DIR}" ${_ARG_BUILD_TARGETS})
  list(APPEND INSTALL_COMMANDS COMMAND make -C "${_ARG_SOURCE_DIR}" "${_ARG_INSTALL_TARGET}" "prefix=${CMAKE_INSTALL_PREFIX}")

  unset(_ARG_SOURCE_DIR)
  unset(_ARG_ENV)
  unset(_ARG_FEATURES)
  unset(_ARG_CFLAGS)
  unset(_ARG_CXXFLAGS)
  unset(_ARG_LDFLAGS)
  unset(_ARG_BUILD_TARGETS)
  unset(_ARG_INSTALL_TARGET)
endmacro()

# cmake_builder(
#   [ENV <var>=<val>...]
#   [CMAKE_FLAGS <cmake-flag>...]
#   [CFLAGS <cflag>...]
#   [CXXFLAGS <cxxflag>...]
#   [LDFLAGS <ldflag>...]
#   [TARGETS <targets>...]
#   [SOURCE_DIR <SOURCE_DIR>]
# )
#
# Add builder commands for an `CMake`-based project.
macro(cmake_builder)
  cmake_parse_arguments("_ARG" "" "SOURCE_DIR" "ENV;CMAKE_FLAGS;CFLAGS;CXXFLAGS;LDFLAGS;TARGETS" ${ARGN})

  if(NOT DEFINED _ARG_SOURCE_DIR)
    set(_ARG_SOURCE_DIR "<SOURCE_DIR>")
  endif()

  if(NOT DEFINED _ARG_TARGETS)
    set(_ARG_TARGETS "install")
  endif()

  list(JOIN _ARG_CFLAGS " " _ARG_CFLAGS)
  list(JOIN _ARG_CXXFLAGS " " _ARG_CXXFLAGS)
  list(JOIN _ARG_LDFLAGS " " _ARG_LDFLAGS)

  list(APPEND CONFIGURE_COMMANDS COMMAND
    ${CMAKE_COMMAND} -E env
      "CXX=${CMAKE_CXX_COMPILER}"
      "CPP=${CMAKE_C_COMPILER} -E"
      "CC=${CMAKE_C_COMPILER}"
      "AR=${CMAKE_AR}"
      "RANLIB=${CMAKE_RANLIB}"
      "NM=${CMAKE_NM}"
      "STRIP=${CMAKE_STRIP}"
      "CFLAGS=${_ARG_CFLAGS}"
      "CXXFLAGS=${_ARG_CXXFLAGS}"
      "LDFLAGS=${_ARG_LDFLAGS}"
      ${_ARG_ENV}
    ${CMAKE_COMMAND}
      "-B<BINARY_DIR>"
      "-S${_ARG_SOURCE_DIR}"
      "-DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}"
      ${_ARG_CMAKE_FLAGS}
  )

  list(APPEND CONFIGURE_COMMANDS COMMAND
    ${CMAKE_COMMAND}
        --build <BINARY_DIR>
        --config $<CONFIG>
        --target ${_ARG_TARGETS}
  )

  unset(_ARG_SOURCE_DIR)
  unset(_ARG_ENV)
  unset(_ARG_CMAKE_FLAGS)
  unset(_ARG_CFLAGS)
  unset(_ARG_CXXFLAGS)
  unset(_ARG_LDFLAGS)
  unset(_ARG_TARGETS)
endmacro()


function(generate_vendorinfo_script _var)
    configure_file(
      ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/vendorinfo.sh.in
      ${CMAKE_CURRENT_BINARY_DIR}/vendorinfo.sh.in @ONLY
    )

    file(GENERATE
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vendorinfo.sh
        INPUT ${CMAKE_CURRENT_BINARY_DIR}/vendorinfo.sh.in
    )

    set("${_var}" ${CMAKE_CURRENT_BINARY_DIR}/vendorinfo.sh PARENT_SCOPE)
endfunction()


function(declare_vulnerability cve_name)
  cmake_parse_arguments(PARSE_ARGV 1 "_ARG" "" "PATCH" "")

  set(HAS_${cve_name} yes PARENT_SCOPE)
  if(KNOWN_VULNERABILITIES)
    set(KNOWN_VULNERABILITIES "${KNOWN_VULNERABILITIES}" "${cve_name}" PARENT_SCOPE)
  else()
    set(KNOWN_VULNERABILITIES "${cve_name}" PARENT_SCOPE)
  endif()

  if(_ARG_PATCH)
    set(PATCH_${cve_name} "${_ARG_PATCH}" PARENT_SCOPE)
  endif()
endfunction()
