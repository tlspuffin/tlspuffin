cmake_minimum_required(VERSION 3.15)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(puts VERSION 0.1 LANGUAGES C)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  # NOTE avoid interactions with system libraries
  #
  # The default value of CMAKE_INSTALL_PREFIX lies outside of the project
  # directory (e.g. /usr/local on UNIX platforms). This prefix is usually part
  # of the system-wide configuration and might break the system libraries or
  # their downstream dependencies.
  #
  # To be on the safe side, if no prefix is explicitly provided by the caller,
  # we install the library in an isolated prefix.
  set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}" CACHE PATH "installation directory" FORCE)
endif()

enable_testing()

include(FindClaimsLibrary)

find_claims(TARGET_NAME claims)

set(PUTS "")
set(PUT_LIBS "")

string(REPLACE "," ";" LIBRARIES "${LIBRARIES}")
foreach(library_path IN LISTS LIBRARIES)

    # TODO retrieve or compute the following PUT info
    set(PROTOCOL "tls")
    set(HARNESS_NAME "openssl")
    set(HARNESS_VERSION "tlspuffin-harness-sys ${CMAKE_PROJECT_VERSION}")
    set(LIBRARY_NAME "cput")
    set(LIBRARY_VERSION "<placeholder library version>")
    set(CONFIG_HASH "<placeholder library config hash>")
    set(HAS_CLAIMS TRUE)
    get_filename_component(CONFIG_NAME ${library_path} NAME)

    # FIXME use mk_vendor config uid if available rather than library_path
    # FIXME use a harness uid rather than name (e.g. id = name + hash(version))
    string(SHA256 PUT_HASH "${PROTOCOL}/${HARNESS_NAME}/${library_path}")
    string(SUBSTRING ${PUT_HASH} 0 16 PUT_HASH)

    set(PUT_ID "${HARNESS_NAME}${PUT_HASH}")

    add_library(put-${PROTOCOL}-${PUT_ID} OBJECT ${PROTOCOL}/${HARNESS_NAME}/src/put.c)
    set_property(TARGET put-${PROTOCOL}-${PUT_ID} PROPERTY C_VISIBILITY_PRESET default)
    target_include_directories(put-${PROTOCOL}-${PUT_ID} PRIVATE "include")
    target_include_directories(put-${PROTOCOL}-${PUT_ID} PRIVATE "${library_path}/include")
    target_compile_definitions(put-${PROTOCOL}-${PUT_ID} PRIVATE PUT_ID=${PUT_ID} REGISTER=register_${PUT_ID})

    target_compile_definitions(put-${PROTOCOL}-${PUT_ID} PRIVATE USE_CUSTOM_PRNG=1)
    target_link_libraries(put-${PROTOCOL}-${PUT_ID} PRIVATE claims)

    if(HAS_CLAIMS)
      target_compile_definitions(put-${PROTOCOL}-${PUT_ID} PRIVATE HAS_CLAIMS=1)
    endif()

    add_custom_command(
        COMMAND clang -flto -nostdlib -no-pie -Wl,-r $<TARGET_OBJECTS:put-${PROTOCOL}-${PUT_ID}> "-L${library_path}/lib" -lssl -lcrypto -o ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${PUT_ID}.o
        OUTPUT ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${PUT_ID}.o
        DEPENDS put-${PROTOCOL}-${PUT_ID} $<TARGET_OBJECTS:put-${PROTOCOL}-${PUT_ID}>
        COMMENT "relocation for put-${PROTOCOL}-${PUT_ID}" VERBATIM)

    add_custom_target(relocate-put-${PROTOCOL}-${PUT_ID} ALL DEPENDS ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${PUT_ID}.o)

    add_library(relocated-put-${PROTOCOL}-${PUT_ID} OBJECT IMPORTED)
    set_property(TARGET relocated-put-${PROTOCOL}-${PUT_ID} PROPERTY IMPORTED_OBJECTS ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${PUT_ID}.o)
    add_dependencies(relocated-put-${PROTOCOL}-${PUT_ID} relocate-put-${PROTOCOL}-${PUT_ID})

    list(APPEND PUTS "${PUT_ID}")
    list(APPEND PUT_LIBS relocated-put-${PROTOCOL}-${PUT_ID})

    configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/cmake/put_init_decl.rs.in
        ${CMAKE_BINARY_DIR}/put_init_decl_${PUT_ID}.rs
        ESCAPE_QUOTES
        @ONLY)
endforeach()

set(BUNDLE_OBJECTS "")
foreach(PUT_LIB IN LISTS PUT_LIBS)
    list(APPEND BUNDLE_OBJECTS "$<TARGET_OBJECTS:${PUT_LIB}>")
    install(FILES "$<TARGET_OBJECTS:${PUT_LIB}>" DESTINATION ".")
endforeach()

# NOTE adding empty.c allows us to build even when there is no PUT in the bundle
file(WRITE ${CMAKE_BINARY_DIR}/empty.c "")
add_library(puts-bundle STATIC ${CMAKE_BINARY_DIR}/empty.c ${BUNDLE_OBJECTS})
set_target_properties(puts-bundle PROPERTIES LINKER_LANGUAGE C)

# generate Rust init file defining the `register` function
#
# ```
# pub fn register<F>(mut callback: F)
# where
#     F: FnMut(CPutHarness, CPutLibrary, *const C_PUT_TYPE),
# {
#     on_register_openssl1ab23c(&mut callback);
#     on_register_openssl4ef567(&mut callback);
# }
# ```
set(RUST_INIT_FILE ${CMAKE_BINARY_DIR}/init.rs)
set(RUST_INIT_INCLUDES "")
set(RUST_INIT_REGISTER "")
foreach(put_id IN LISTS PUTS)
    string(APPEND RUST_INIT_INCLUDES "include!(\"${CMAKE_BINARY_DIR}/put_init_decl_${put_id}.rs\");\n")
    string(APPEND RUST_INIT_REGISTER "    on_register_${put_id}(&mut callback);\n")
endforeach()

file(WRITE ${RUST_INIT_FILE} "${RUST_INIT_INCLUDES}")
if(NOT RUST_INIT_REGISTER)
    file(APPEND ${RUST_INIT_FILE} "pub fn register<F>(mut _callback: F) where F: FnMut(CPutHarness, CPutLibrary, *const C_PUT_TYPE) {}\n")
else()
    file(APPEND ${RUST_INIT_FILE} "pub fn register<F>(mut callback: F) where F: FnMut(CPutHarness, CPutLibrary, *const C_PUT_TYPE) {\n${RUST_INIT_REGISTER}}\n")
endif()

install(FILES ${RUST_INIT_FILE} DESTINATION ".")
install(FILES $<TARGET_FILE:puts-bundle> DESTINATION ".")

