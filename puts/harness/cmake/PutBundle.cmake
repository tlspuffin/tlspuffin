include_guard(GLOBAL)

set(_put_init_rs_template "${CMAKE_CURRENT_LIST_DIR}/put_init.rs.in" CACHE INTERNAL "Rust template for PUT init file")

# add_bundle(<target-name> PUTS <put>... [RUST_BUNDLE_INIT <output-file.rs>])
function(add_bundle _bundle)
  cmake_parse_arguments(PARSE_ARGV 1 "" "" "RUST_BUNDLE_INIT" "PUTS")

  # NOTE adding a dummy C file let us build even when there is no PUT in the bundle
  file(WRITE ${CMAKE_BINARY_DIR}/bundle_dummy.c "static void _bundle_dummy(void) {}")

  add_library(${_bundle} STATIC ${CMAKE_BINARY_DIR}/bundle_dummy.c)

  foreach(PUT IN LISTS _PUTS)
    get_property(PUT_UID TARGET ${PUT} PROPERTY PUT_UID)

    # NOTE forces CMake to let us use the generated fat object as an object
    set(PUT_HARNESS_OBJECT ${CMAKE_BINARY_DIR}/put_${PUT_UID}.o)
    add_custom_command(
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PUT}> ${PUT_HARNESS_OBJECT}
        VERBATIM
        OUTPUT ${PUT_HARNESS_OBJECT}
        DEPENDS ${PUT}
        COMMENT "(${PUT_UID}) prep. relocated PUT object"
    )

    target_sources(${_bundle} PRIVATE ${PUT_HARNESS_OBJECT})
  endforeach()

  if(DEFINED _RUST_BUNDLE_INIT)
    create_registration_rs(PUTS ${_PUTS} OUTPUT ${_RUST_BUNDLE_INIT})
  endif()
endfunction()

# create_registration_rs(PUTS <put-targets>... OUTPUT <output-path>)
#
# Generate the Rust file defining the `register` function.
#
# ```
# pub fn register()
# {
#     register_openssl1ab23c();
#     register_openssl4ef567();
# }
# ```
function(create_registration_rs)
  cmake_parse_arguments(PARSE_ARGV 0 "" "" "OUTPUT" "PUTS")

  if(NOT DEFINED _OUTPUT)
    message(FATAL_ERROR "missing mandatory OUTPUT argument")
  endif()

  set(RUST_INIT_INCLUDES "")
  set(RUST_INIT_REGISTER "")
  foreach(put IN LISTS _PUTS)
    get_property(PUT_UID TARGET ${put} PROPERTY PUT_UID)

    set(RUST_PUT_INIT_FILE "${CMAKE_BINARY_DIR}/put_init_${PUT_UID}.rs")
    create_put_init_rs(${put} OUTPUT ${RUST_PUT_INIT_FILE})
    file(READ ${RUST_PUT_INIT_FILE} RUST_PUT_INIT)

    string(APPEND RUST_INIT_INCLUDES "${RUST_PUT_INIT}\n")
    string(APPEND RUST_INIT_REGISTER "    unsafe { register_${PUT_UID}(); }\n")
  endforeach()

  file(WRITE ${_OUTPUT} "${RUST_INIT_INCLUDES}")
  if(NOT RUST_INIT_REGISTER)
    file(APPEND ${_OUTPUT} "pub fn register() {}\n")
  else()
    file(APPEND ${_OUTPUT} "pub fn register() {\n${RUST_INIT_REGISTER}}\n")
  endif()
endfunction()

function(create_put_init_rs _put)
  cmake_parse_arguments(PARSE_ARGV 1 "" "" "OUTPUT" "")

  if(NOT DEFINED _OUTPUT)
    message(FATAL_ERROR "missing mandatory OUTPUT argument")
  endif()

  get_property(PUT_UID TARGET ${_put} PROPERTY PUT_UID)
  get_property(PUT_LIB TARGET ${_put} PROPERTY PUT_LIB)

  get_property(LIBRARY_VERSION TARGET ${PUT_LIB} PROPERTY VERSION)
  get_property(LIBRARY_NAME TARGET ${PUT_LIB} PROPERTY LIBRARY_NAME)
  get_property(CONFIG_NAME TARGET ${PUT_LIB} PROPERTY CONFIG_NAME)
  get_property(CONFIG_HASH TARGET ${PUT_LIB} PROPERTY CONFIG_HASH)
  get_property(_WITH_SANCOV TARGET ${PUT_LIB} PROPERTY WITH_SANCOV)
  get_property(_WITH_ASAN TARGET ${PUT_LIB} PROPERTY WITH_ASAN)
  get_property(_WITH_GCOV TARGET ${PUT_LIB} PROPERTY WITH_GCOV)
  get_property(_WITH_LLVM_COV TARGET ${PUT_LIB} PROPERTY WITH_LLVM_COV)
  get_property(KNOWN_VULNERABILITIES TARGET ${PUT_LIB} PROPERTY KNOWN_VULNERABILITIES)

  get_property(HARNESS_NAME TARGET ${_put} PROPERTY HARNESS_NAME)
  get_property(HARNESS_VERSION TARGET ${_put} PROPERTY VERSION)

  to_rust_boolean(${_WITH_SANCOV} WITH_SANCOV)
  to_rust_boolean(${_WITH_ASAN} WITH_ASAN)
  to_rust_boolean(${_WITH_GCOV} WITH_GCOV)
  to_rust_boolean(${_WITH_LLVM_COV} WITH_LLVM_COV)

  configure_file(
      ${_put_init_rs_template}
      ${_OUTPUT}
      ESCAPE_QUOTES
      @ONLY
  )
endfunction()

# to_rust_boolean(<cmake-value> <out-var>)
#
# Convert a CMake value into a Rust boolean string (true or false) suitable for interpolation in a
# Rust file.
#
# Note that the convertion is based on CMake interpretation of truthy/falthy values. For more
# details, see:
#   https://cmake.org/cmake/help/latest/command/if.html#basic-expressions
#
# Example:
#   to_rust_boolean(${WITH_SANCOV} my_rust_boolean)
function(to_rust_boolean _value _out_var)
  if(${_value})
    set(${_out_var} "true" PARENT_SCOPE)
  else()
    set(${_out_var} "false" PARENT_SCOPE)
  endif()
endfunction()