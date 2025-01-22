cmake_minimum_required(VERSION 3.18 FATAL_ERROR)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/common")

cmake_policy(SET CMP0097 NEW)  # https://cmake.org/cmake/help/latest/policy/CMP0097.html
cmake_policy(SET CMP0135 OLD)  # https://cmake.org/cmake/help/latest/policy/CMP0135.html
cmake_policy(SET CMP0074 NEW)  # https://cmake.org/cmake/help/latest/policy/CMP0074.html

if(NOT PUFFIN_VERSION)
  message(FATAL_ERROR "Missing mandatory argument 'PUFFIN_VERSION'")
endif()

if(NOT COMMAND)
  message(FATAL_ERROR "Missing mandatory argument 'COMMAND'")
endif()

project("${COMMAND}" VERSION "${PUFFIN_VERSION}" LANGUAGES NONE)
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

include(Utils)

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/${COMMAND}.cmake")
  include("${CMAKE_CURRENT_LIST_DIR}/${COMMAND}.cmake")
elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/${COMMAND}/run.cmake")
  list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/${COMMAND}/cmake")
  include("${CMAKE_CURRENT_LIST_DIR}/${COMMAND}/run.cmake")
else()
  message(FATAL_ERROR "Unknown command requested: COMMAND='${COMMAND}'")
endif()
