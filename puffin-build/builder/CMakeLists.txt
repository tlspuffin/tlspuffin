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

set(UPDATE_COMMANDS "")
set(PATCH_COMMANDS "")
set(CONFIGURE_COMMANDS "")
set(BUILD_COMMANDS "")
set(INSTALL_COMMANDS "")

if(EXISTS "${BUILDER}" AND NOT IS_DIRECTORY "${BUILDER}")
  include("${BUILDER}")
elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../vendors/${BUILDER}/builder.cmake")
  include("${CMAKE_CURRENT_LIST_DIR}/../vendors/${BUILDER}/builder.cmake")
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
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] INSTALL step: completed"
)
