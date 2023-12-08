cmake_minimum_required(VERSION 3.15)

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

# NOTE this indirectly adds OPENSSL_DIR to PKG_CONFIG_PATH
#
# CMAKE_PREFIX_PATH is appended to PKG_CONFIG_PATH, resulting in OPENSSL_DIR
# being the prefered search location when calling `pkg_check_modules`.
set(CMAKE_PREFIX_PATH ${OPENSSL_DIR})

unset(OPENSSL_FOUND CACHE)
unset(OPENSSL_HAS_CLAIMS CACHE)
include(FindPkgConfig)
pkg_check_modules(OPENSSL REQUIRED QUIET openssl)

if(NOT OPENSSL_FOUND)
  message(
    FATAL_ERROR
      "OPENSSL_DIR does not contain a valid installation of OpenSSL.\n"
      "  got OPENSSL_DIR=${OPENSSL_DIR}")
endif()

cmake_path(IS_PREFIX OPENSSL_DIR "${OPENSSL_PREFIX}" NORMALIZE own_openssl)
if(NOT own_openssl)
  # NOTE avoid defaulting to system OpenSSL
  #
  # There is no easy and portable way to set pkg-config to only look at packages
  # in the OPENSSL_DIR folder, so we need to extra-check that we don't default
  # to the system OpenSSL if it exists.
  #
  # Our strategy is to set OPENSSL_DIR as the preferred search path for
  # pkg-config and check afterwards that the found version is actually in this
  # folder.
  message(
    FATAL_ERROR
      "OPENSSL_DIR does not contain a valid installation of OpenSSL.\n"
      "  got OPENSSL_DIR=${OPENSSL_DIR}"
      "  but found PKG_CONFIG_OPENSSL=${OPENSSL_PREFIX}")
endif()

add_library(puts-interface STATIC src/put_openssl.c)
target_include_directories(puts-interface PRIVATE ${TLSPUFFIN_INCDIR})

# bundle the PUT interface with the vendor libraries
set(mri_file ${CMAKE_BINARY_DIR}/bundle-cput.mri)
set(out_file
    ${CMAKE_BINARY_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}puts-libs${CMAKE_STATIC_LIBRARY_SUFFIX}
)

file(WRITE ${mri_file}.in "CREATE ${out_file}\n")
file(APPEND ${mri_file}.in "ADDLIB $<TARGET_FILE:puts-interface>\n")
foreach(dep IN LISTS OPENSSL_LINK_LIBRARIES)
  file(APPEND ${mri_file}.in "ADDLIB ${dep}\n")
endforeach()
file(APPEND ${mri_file}.in "SAVE\nEND\n")

file(
  GENERATE
  OUTPUT ${mri_file}
  INPUT ${mri_file}.in)

add_custom_command(
  COMMAND ${CMAKE_AR} -M < ${mri_file}
  OUTPUT ${out_file}
  DEPENDS ${mri_file} ${OPENSSL_LINK_LIBRARIES} puts-interface
  COMMENT "Bundling OpenSSL with PUT interface"
  VERBATIM)

add_custom_target(mkbundle ALL DEPENDS ${out_file})
add_dependencies(mkbundle puts-interface)

add_library(puts-libs STATIC IMPORTED)
set_target_properties(puts-libs PROPERTIES IMPORTED_LOCATION ${out_file})
add_dependencies(puts-libs mkbundle)

install(FILES $<TARGET_FILE:puts-libs> DESTINATION ".")
