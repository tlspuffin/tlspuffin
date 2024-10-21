cmake_minimum_required(VERSION 3.15)

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

set(PUTS "")
set(PUT_LIBS "")

string(REPLACE "," ";" LIBRARIES "${LIBRARIES}")
foreach(library_path IN LISTS LIBRARIES)
    set(PROTOCOL "tls")
    set(HARNESS "openssl")

    # FIXME retrieve mk_vendor config uid if available
    string(SHA256 LIBRARY_HASH "${PROTOCOL}/${HARNESS}/${library_path}")
    string(SUBSTRING ${LIBRARY_HASH} 0 16 LIBRARY_HASH)

    set(PUT_ID "${LIBRARY_HASH}")

    add_library(put-${PROTOCOL}-${HARNESS}-${PUT_ID} OBJECT ${PROTOCOL}/${HARNESS}/src/put.c)
    set_property(TARGET put-${PROTOCOL}-${HARNESS}-${PUT_ID} PROPERTY C_VISIBILITY_PRESET default)
    target_compile_definitions(put-${PROTOCOL}-${HARNESS}-${PUT_ID} PRIVATE PUT_ID=${PUT_ID} REGISTER=register_${HARNESS}_${PUT_ID})
    target_include_directories(put-${PROTOCOL}-${HARNESS}-${PUT_ID} PRIVATE "include")
    target_include_directories(put-${PROTOCOL}-${HARNESS}-${PUT_ID} PRIVATE "${library_path}/include")
    target_include_directories(put-${PROTOCOL}-${HARNESS}-${PUT_ID} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../../tlspuffin-claims")

    add_custom_command(
        COMMAND clang -flto -nostdlib -Wl,-no-pie -Wl,-r $<TARGET_OBJECTS:put-${PROTOCOL}-${HARNESS}-${PUT_ID}> "-L${library_path}/lib" -lssl -lcrypto -o ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${HARNESS}-${PUT_ID}.o OUTPUT ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${HARNESS}-${PUT_ID}.o DEPENDS put-${PROTOCOL}-${HARNESS}-${PUT_ID}
        COMMENT "relocation for put-${PROTOCOL}-${HARNESS}-${PUT_ID}" VERBATIM
    )

    add_custom_target(relocate-put-${PROTOCOL}-${HARNESS}-${PUT_ID} ALL DEPENDS ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${HARNESS}-${PUT_ID}.o)

    add_library(relocated-put-${PROTOCOL}-${HARNESS}-${PUT_ID} OBJECT IMPORTED)
    set_property(TARGET relocated-put-${PROTOCOL}-${HARNESS}-${PUT_ID} PROPERTY IMPORTED_OBJECTS ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${HARNESS}-${PUT_ID}.o)
    add_dependencies(relocated-put-${PROTOCOL}-${HARNESS}-${PUT_ID} relocate-put-${PROTOCOL}-${HARNESS}-${PUT_ID})

    list(APPEND PUTS "${HARNESS}_${PUT_ID}")
    list(APPEND PUT_LIBS relocated-put-${PROTOCOL}-${HARNESS}-${PUT_ID})
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

# create Rust init file
set(RUST_INIT_FILE ${CMAKE_BINARY_DIR}/init.rs)
set(RUST_INIT_DECL "")
set(RUST_INIT_CALL "")
foreach(put_id IN LISTS PUTS)
    string(APPEND RUST_INIT_DECL "    fn register_${put_id}(callback: FnRegister);\n")
    string(APPEND RUST_INIT_CALL "        unsafe { register_${put_id}(callback); };\n")
endforeach()

if(NOT RUST_INIT_DECL)
    file(WRITE ${RUST_INIT_FILE} "use crate::FnRegister;\n\npub fn register(_callback: FnRegister) {}\n")
else()
    file(WRITE ${RUST_INIT_FILE} "use crate::FnRegister;\n\nextern {\n${RUST_INIT_DECL}}\n\npub fn register(callback: FnRegister) {\n    ${RUST_INIT_CALL}\n}\n")
endif()

install(FILES ${RUST_INIT_FILE} DESTINATION ".")
install(FILES $<TARGET_FILE:puts-bundle> DESTINATION ".")

