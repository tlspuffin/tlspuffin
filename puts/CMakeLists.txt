cmake_minimum_required(VERSION 3.15)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

if(NOT DEFINED OPENSSL_DIR)
  message(
    FATAL_ERROR
      "Mandatory variable OPENSSL_DIR is not set.\n Try `cmake -DOPENSSL_DIR:PATH=<path> ...`"
  )
endif()

if(NOT DEFINED TLSPUFFIN_INCDIR)
  message(
    FATAL_ERROR
      "Mandatory variable TLSPUFFIN_INCDIR is not set.\n Try `cmake -DTLSPUFFIN_INCDIR:PATH=<path> ...`"
  )
endif()

project(
  puts
  VERSION 0.1
  LANGUAGES C)

string(SHA256 _dir_hash "${OPENSSL_DIR}")
set(openssl_prefix OPENSSL${_dir_hash})

include(FindClaimsLibrary)
find_claims(TARGET_NAME claims)

include(FindOpenSSLFromDir)
find_openssl("${OPENSSL_DIR}" TARGET_NAME "${openssl_prefix}")

add_library(puts-interface STATIC src/put_openssl.c)
target_include_directories(puts-interface PRIVATE ${TLSPUFFIN_INCDIR})
target_link_libraries(puts-interface PRIVATE ${openssl_prefix} claims)

get_target_property(_put_libraries ${openssl_prefix} INTERFACE_LINK_LIBRARIES)

include(BundleStaticLibs)
add_bundle(puts-libs LIBS puts-interface ${_put_libraries})

install(FILES $<TARGET_FILE:puts-libs> DESTINATION ".")
