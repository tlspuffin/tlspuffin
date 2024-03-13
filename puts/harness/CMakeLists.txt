cmake_minimum_required(VERSION 3.15)

project(puts VERSION 0.1 LANGUAGES C)

enable_testing()

set(PUT_ID openssl111j)
add_library(put-tls-openssl-${PUT_ID} OBJECT tls/openssl/src/put.c)
set_property(TARGET put-tls-openssl-${PUT_ID} PROPERTY C_VISIBILITY_PRESET default)
target_compile_definitions(put-tls-openssl-${PUT_ID} PRIVATE PUT_ID=${PUT_ID})
target_include_directories(put-tls-openssl-${PUT_ID} PUBLIC "include")

add_library(put-tls-openssl-openssl111k OBJECT tls/openssl/src/put.c)
set_property(TARGET put-tls-openssl-openssl111k PROPERTY C_VISIBILITY_PRESET default)
target_compile_definitions(put-tls-openssl-openssl111k PRIVATE PUT_ID=openssl111k)
target_include_directories(put-tls-openssl-openssl111k PUBLIC "include")

add_library(puts-bundle STATIC $<TARGET_OBJECTS:put-tls-openssl-openssl111j> $<TARGET_OBJECTS:put-tls-openssl-openssl111k>)

# create Rust init file
set(RUST_INIT_FILE ${CMAKE_BINARY_DIR}/init.rs)
set(RUST_INIT_DECL "")
set(RUST_INIT_CALL "")
set(PUTS openssl111j openssl111k)
foreach(put_id IN LISTS PUTS)
    string(APPEND RUST_INIT_DECL "    fn ${put_id}();\n")
    string(APPEND RUST_INIT_CALL "        ${put_id}();\n")
endforeach()

file(WRITE ${RUST_INIT_FILE} "extern {\n${RUST_INIT_DECL}}\n\npub fn init() {\n    unsafe {\n${RUST_INIT_CALL}    }\n}\n")


install(FILES $<TARGET_OBJECTS:put-tls-openssl-openssl111j> DESTINATION ".")
install(FILES $<TARGET_OBJECTS:put-tls-openssl-openssl111k> DESTINATION ".")
install(FILES ${RUST_INIT_FILE} DESTINATION ".")
install(FILES $<TARGET_FILE:puts-bundle> DESTINATION ".")