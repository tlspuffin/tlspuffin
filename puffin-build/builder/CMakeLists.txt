cmake_minimum_required(VERSION 3.18)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

cmake_policy(SET CMP0097 NEW)  # https://cmake.org/cmake/help/latest/policy/CMP0097.html
cmake_policy(SET CMP0135 OLD)  # https://cmake.org/cmake/help/latest/policy/CMP0135.html

project(vendor LANGUAGES NONE)
enable_testing()

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
  set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install" CACHE PATH "installation directory" FORCE)
endif()

if(NOT SOURCES)
  message(FATAL_ERROR "Missing mandatory argument 'SOURCES'")
endif()

if(NOT BUILDER)
  message(FATAL_ERROR "Missing mandatory argument 'BUILDER'")
endif()

if(NOT VENDOR_VERSION)
  message(FATAL_ERROR "Missing mandatory argument 'VENDOR_VERSION'")
endif()

include(Builder)

set(VENDOR_LIBNAME "${BUILDER}")
set(KNOWN_VULNERABILITIES "")
set(FIXED_VULNERABILITIES "")

option(asan "Build with address-sanitizer" OFF)
option(sancov "Build with sancov" OFF)
option(gcov "Build with instrumentation for gcov coverage" OFF)
option(llvm_cov "Build with instrumentation for llvm coverage" OFF)
set(fix "" CACHE STRING "List of CVEs to fix")
string(REPLACE "," ";" fix "${fix}")

set(KNOWN_VULNERABILITIES "")
set(FIXED_VULNERABILITIES "")

set(UPDATE_COMMANDS "")
set(PATCH_COMMANDS "")
set(CONFIGURE_COMMANDS "")
set(BUILD_COMMANDS "")
set(INSTALL_COMMANDS "")

if(EXISTS "${BUILDER}" AND NOT IS_DIRECTORY "${BUILDER}")
  include("${BUILDER}")
elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../vendors/${BUILDER}/builder.cmake")
  include("${CMAKE_CURRENT_LIST_DIR}/../vendors/${BUILDER}/builder.cmake")
  string(REPLACE ";" " " FIXED_VULNERABILITIES "${FIXED_VULNERABILITIES}")
  string(REPLACE ";" " " KNOWN_VULNERABILITIES "${KNOWN_VULNERABILITIES}")
  generate_vendorinfo_script(vendorinfo_script)
else()
  message(FATAL_ERROR "Builder '${BUILDER}' not found")
endif()

include(ExternalProject)

externalproject_add(
  vendor
  URL ${SOURCES}
  PREFIX ${CMAKE_INSTALL_PREFIX}

  UPDATE_COMMAND ":"
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] UPDATE step: starting"
  ${UPDATE_COMMANDS}
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] UPDATE step: completed"

  PATCH_COMMAND ":"
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] PATCH step: starting"
  ${PATCH_COMMANDS}
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] PATCH step: completed"

  CONFIGURE_COMMAND ":"
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] CONFIGURE step: starting"
  ${CONFIGURE_COMMANDS}
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] CONFIGURE step: completed"

  BUILD_COMMAND ":"
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] BUILD step: starting"
  ${BUILD_COMMANDS}
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] BUILD step: completed"

  INSTALL_COMMAND ":"
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] INSTALL step: starting"
  ${INSTALL_COMMANDS}
  COMMAND chmod +x ${vendorinfo_script}
  COMMAND ${CMAKE_COMMAND} -E env
      "INSTALL_DIR=<INSTALL_DIR>"
      "SOURCE_DIR=<SOURCE_DIR>"
      "CXX=${CMAKE_CXX_COMPILER}"
      "CPP=${CMAKE_C_COMPILER} -E"
      "CC=${CMAKE_C_COMPILER}"
      "AR=${CMAKE_AR}"
      "RANLIB=${CMAKE_RANLIB}"
      "NM=${CMAKE_NM}"
      "STRIP=${CMAKE_STRIP}"
    ${vendorinfo_script} > <INSTALL_DIR>/.vendor
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] INSTALL step: completed"
)
