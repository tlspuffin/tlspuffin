if(NOT SOURCES)
  message(FATAL_ERROR "Missing mandatory argument 'SOURCES'")
endif()

if(NOT BUILDER)
  message(FATAL_ERROR "Missing mandatory argument 'BUILDER'")
endif()

if(NOT VENDOR_VERSION)
  message(FATAL_ERROR "Missing mandatory argument 'VENDOR_VERSION'")
endif()

# The version for CMake's version comparisons (VERSION_GREATER_EQUAL, $<VERSION_LESS:...>) in a builder: its numbers
# only (1.1.1j, 1.1.1g+git.368d0d87d0bd: 1.1.1, as CMake reads them anyway, but nothing else reaches a generator
# expression); a development head (master: not starting with a digit) is newer than every release, as puffin-build
# orders versions (src/catalogue/version.rs); CMake would compare it as 0, the oldest.
if(VENDOR_VERSION MATCHES "^([0-9]+(\\.[0-9]+)*)")
  set(VENDOR_VERSION_ORDER "${CMAKE_MATCH_1}")
else()
  set(VENDOR_VERSION_ORDER "999999")
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
elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../vendors/${BUILDER}/builder.cmake")
  include("${CMAKE_CURRENT_LIST_DIR}/../../vendors/${BUILDER}/builder.cmake")

  # The patches of the vendor's presets.toml for this version ([[patches]]: instrumentation for tlspuffin, build
  # fixes), after the builder's own patches and before the catalogue's fixes.
  string(REPLACE "," ";" LIBRARY_PATCHES "${LIBRARY_PATCHES}")
  foreach(patch_file IN LISTS LIBRARY_PATCHES)
    patch(FILE "${patch_file}")
  endforeach()

  # The vendor's vulnerability catalogue (vendors/<vendor>/vulnerabilities.toml) is the only source of its known
  # vulnerabilities: puffin-build reads it and passes the known ones, the fixed ones and the patches fixing them.
  # The patches apply after the builder's own patches.
  if(CATALOGUE)
    string(REPLACE "," ";" KNOWN_VULNERABILITIES "${CATALOGUE_KNOWN}")
    string(REPLACE "," ";" FIXED_VULNERABILITIES "${CATALOGUE_FIXED}")
    string(REPLACE "," ";" CATALOGUE_PATCHES "${CATALOGUE_PATCHES}")
    foreach(patch_file IN LISTS CATALOGUE_PATCHES)
      patch(FILE "${patch_file}")
    endforeach()
  endif()

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
    ${vendorinfo_script} > <INSTALL_DIR>/.metadata
  COMMAND ${CMAKE_COMMAND} -E echo "[${BUILDER}] INSTALL step: completed"
)

# NOTE: ensure that the `install` target in available when invoking CMake
install(CODE "message(INFO \"performing builder global install step\")")
