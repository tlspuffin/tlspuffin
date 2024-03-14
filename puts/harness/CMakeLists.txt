cmake_minimum_required(VERSION 3.15)

project(puts VERSION 0.1 LANGUAGES C)

enable_testing()

set(PUTS "")
set(PUT_LIBS "")

string(REPLACE "," ";" VENDORS "${VENDORS}")
foreach(vendor_path IN LISTS VENDORS)
    set(PROTOCOL "tls")
    set(HARNESS "openssl")

    string(SHA256 VENDOR_HASH "${PROTOCOL}/${HARNESS}/${vendor_path}")
    string(SUBSTRING ${VENDOR_HASH} 0 16 VENDOR_HASH)

    set(PUT_ID "${HARNESS}_${VENDOR_HASH}")

    add_library(put-${PROTOCOL}-${HARNESS}-${PUT_ID} OBJECT ${PROTOCOL}/${HARNESS}/src/put.c)
    set_property(TARGET put-${PROTOCOL}-${HARNESS}-${PUT_ID} PROPERTY C_VISIBILITY_PRESET default)
    target_compile_definitions(put-${PROTOCOL}-${HARNESS}-${PUT_ID} PRIVATE PUT_ID=${PUT_ID})
    target_include_directories(put-${PROTOCOL}-${HARNESS}-${PUT_ID} PRIVATE "include")
    target_include_directories(put-${PROTOCOL}-${HARNESS}-${PUT_ID} PRIVATE "${vendor_path}/include")

    add_custom_command(
        COMMAND clang -flto -nostdlib -Wl,-r $<TARGET_OBJECTS:put-${PROTOCOL}-${HARNESS}-${PUT_ID}> "-L${vendor_path}/lib" -lssl -lcrypto -o ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${HARNESS}-${PUT_ID}.o OUTPUT ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${HARNESS}-${PUT_ID}.o DEPENDS put-${PROTOCOL}-${HARNESS}-${PUT_ID}
        COMMENT "relocation for put-${PROTOCOL}-${HARNESS}-${PUT_ID}" VERBATIM)

    add_custom_target(relocate-put-${PROTOCOL}-${HARNESS}-${PUT_ID} ALL DEPENDS ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${HARNESS}-${PUT_ID}.o)

    add_library(relocated-put-${PROTOCOL}-${HARNESS}-${PUT_ID} OBJECT IMPORTED)
    set_property(TARGET relocated-put-${PROTOCOL}-${HARNESS}-${PUT_ID} PROPERTY IMPORTED_OBJECTS ${CMAKE_BINARY_DIR}/put-${PROTOCOL}-${HARNESS}-${PUT_ID}.o)
    add_dependencies(relocated-put-${PROTOCOL}-${HARNESS}-${PUT_ID} relocate-put-${PROTOCOL}-${HARNESS}-${PUT_ID})

    list(APPEND PUTS "${PUT_ID}")
    list(APPEND PUT_LIBS relocated-put-${PROTOCOL}-${HARNESS}-${PUT_ID})
endforeach()

set(BUNDLE_OBJECTS "")
foreach(PUT_LIB IN LISTS PUT_LIBS)
    list(APPEND BUNDLE_OBJECTS "$<TARGET_OBJECTS:${PUT_LIB}>")
    install(FILES "$<TARGET_OBJECTS:${PUT_LIB}>" DESTINATION ".")
endforeach()

add_library(puts-bundle STATIC ${BUNDLE_OBJECTS})
set_target_properties(puts-bundle PROPERTIES LINKER_LANGUAGE C)

# create Rust init file
set(RUST_INIT_FILE ${CMAKE_BINARY_DIR}/init.rs)
set(RUST_INIT_DECL "")
set(RUST_INIT_CALL "")
foreach(put_id IN LISTS PUTS)
    string(APPEND RUST_INIT_DECL "    fn ${put_id}();\n")
    string(APPEND RUST_INIT_CALL "        ${put_id}();\n")
endforeach()

file(WRITE ${RUST_INIT_FILE} "extern {\n${RUST_INIT_DECL}}\n\npub fn init() {\n    unsafe {\n${RUST_INIT_CALL}    }\n}\n")

install(FILES ${RUST_INIT_FILE} DESTINATION ".")
install(FILES $<TARGET_FILE:puts-bundle> DESTINATION ".")