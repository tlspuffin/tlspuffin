cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

cmake_policy(SET CMP0074 NEW)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(tlspuffin-harness VERSION 0.1 LANGUAGES C CXX)

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

include(GNUInstallDirs)
include(MkVendor)
include(PutHarness)
include(PutBundle)

include(FindClaimsLibrary)
find_claims(TARGET_NAME claims)

add_library(puts-harness-interface INTERFACE)
target_include_directories(puts-harness-interface INTERFACE include)
target_link_libraries(puts-harness-interface INTERFACE claims)

set(PUTS "")

string(REPLACE "," ";" LIBRARIES "${LIBRARIES}")
foreach(library_path IN LISTS LIBRARIES)

    #
    # ------ LOAD PUT LIBRARY
    #

    # TODO retrieve dynamically
    set(LIBRARY_NAME "openssl")

    # -- load mk_vendor configuration
    read_mk_vendor("${library_path}/mk_vendor.conf" CONFIG_NAME "META:CONFNAME")
    read_mk_vendor("${library_path}/mk_vendor.conf" CONFIG_HASH "META:CONFUID")
    read_mk_vendor("${library_path}/mk_vendor.conf" WITH_SANCOV "BUILD_ARG:-DWITH_SANCOV" DEFAULT OFF)
    read_mk_vendor("${library_path}/mk_vendor.conf" WITH_ASAN "BUILD_ARG:-DWITH_ASAN" DEFAULT OFF)
    read_mk_vendor("${library_path}/mk_vendor.conf" WITH_GCOV "BUILD_ARG:-DWITH_GCOV" DEFAULT OFF)
    read_mk_vendor("${library_path}/mk_vendor.conf" WITH_LLVM_COV "BUILD_ARG:-DWITH_LLVM_COV" DEFAULT OFF)

    if(NOT DEFINED CONFIG_HASH)
      # TODO recompute the mk_vendor hash if a mk_vendor.conf file exists
      string(SHA256 CONFIG_HASH "${library_path}")
      string(SUBSTRING ${CONFIG_HASH} 0 16 CONFIG_HASH)
    endif()

    if(NOT DEFINED CONFIG_NAME)
      get_filename_component(CONFIG_NAME ${library_path} NAME)
    endif()

    # -- import CMake target for PUT library
    set(PUT_LIB put-library-${LIBRARY_NAME}-${CONFIG_HASH})

    define_property(TARGET PROPERTY LIBRARY_NAME BRIEF_DOCS "PUT library name (openssl, wolfssl, ...)")
    define_property(TARGET PROPERTY CONFIG_NAME BRIEF_DOCS "PUT library configuration name (openssl111k, libressl333-asan, ...)")
    define_property(TARGET PROPERTY CONFIG_HASH BRIEF_DOCS "PUT library configuration hash")
    define_property(TARGET PROPERTY WITH_SANCOV BRIEF_DOCS "PUT library compiled with `sancov`")
    define_property(TARGET PROPERTY WITH_ASAN BRIEF_DOCS "PUT library compiled with `asan`")
    define_property(TARGET PROPERTY WITH_GCOV BRIEF_DOCS "PUT library compiled with `gcov`")
    define_property(TARGET PROPERTY WITH_LLVM_COV BRIEF_DOCS "PUT library compiled with `llvm_cov`")
    define_property(TARGET PROPERTY KNOWN_VULNERABILITIES BRIEF_DOCS "Known CVEs for a PUT library")

    add_library(${PUT_LIB} INTERFACE)
    target_link_libraries(${PUT_LIB} INTERFACE claims "-L${library_path}/lib" -lssl -lcrypto)
    target_include_directories(${PUT_LIB} INTERFACE ${library_path}/include)

    include(${LIBRARY_NAME}/CheckHasClaims)
    CHECK_TLS_OPENSSL_HAS_CLAIMS("${PUT_LIB}")

    include(${LIBRARY_NAME}/CheckVersion)
    CHECK_OPENSSL_VERSION("${PUT_LIB}")
    if(DEFINED ${PUT_LIB}_VERSION)
      set(LIBRARY_VERSION "${${PUT_LIB}_VERSION}")
    else()
      message(FATAL_ERROR "failed to retrieve library version for ${CONFIG_NAME}: ${${PUT_LIB}_VERSION}")
    endif()

    set_property(TARGET ${PUT_LIB} PROPERTY VERSION ${LIBRARY_VERSION})
    set_property(TARGET ${PUT_LIB} PROPERTY LIBRARY_NAME ${LIBRARY_NAME})
    set_property(TARGET ${PUT_LIB} PROPERTY CONFIG_NAME ${CONFIG_NAME})
    set_property(TARGET ${PUT_LIB} PROPERTY CONFIG_HASH ${CONFIG_HASH})
    set_property(TARGET ${PUT_LIB} PROPERTY WITH_SANCOV ${WITH_SANCOV})
    set_property(TARGET ${PUT_LIB} PROPERTY WITH_ASAN ${WITH_ASAN})
    set_property(TARGET ${PUT_LIB} PROPERTY WITH_GCOV ${WITH_GCOV})
    set_property(TARGET ${PUT_LIB} PROPERTY WITH_LLVM_COV ${WITH_LLVM_COV})

    # -- register known CVEs
    include(${LIBRARY_NAME}/cve/CheckAllCVEs)
    check_all_cves(${PUT_LIB})

    #
    # ------ CREATE PUT
    #

    define_property(TARGET PROPERTY HARNESS_NAME BRIEF_DOCS "Harness name")

    # TODO try all known harnesses
    set(HARNESS_NAME "openssl")
    set(PUT relocated-put-${HARNESS_NAME}${CONFIG_HASH})

    add_put(${PUT}
      HARNESS "${HARNESS_NAME}"
      LIBRARY "${PUT_LIB}"
      SOURCES
        tls/${HARNESS_NAME}/src/put.c
    )

    target_include_directories(${PUT} PRIVATE "tls/${HARNESS_NAME}/include")
    target_compile_definitions(${PUT} PRIVATE USE_CUSTOM_PRNG=1)

    if(${PUT_LIB}_HAS_CLAIMS)
      target_compile_definitions(${PUT} PRIVATE HAS_CLAIMS=1)
    endif()

    list(APPEND PUTS "${PUT}")
endforeach()

set(RUST_INIT_FILE ${CMAKE_BINARY_DIR}/puts-bundle-init.rs)

add_bundle(puts-bundle PUTS ${PUTS} RUST_BUNDLE_INIT ${RUST_INIT_FILE})

install(FILES ${RUST_INIT_FILE} DESTINATION ".")
install(FILES $<TARGET_FILE:puts-bundle> DESTINATION ".")
install(FILES $<TARGET_OBJECTS:puts-bundle> DESTINATION ".")
