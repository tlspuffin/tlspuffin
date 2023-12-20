cmake_minimum_required(VERSION 3.15)

cmake_policy(SET CMP0074 NEW)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(puts
  VERSION 0.1
  LANGUAGES C
)

enable_testing()

include(BundleStaticLibs)
include(FindClaimsLibrary)

find_claims(TARGET_NAME claims)

include(ParsePutArgs)
parse_put_args("PARSED")

set(puts "")

foreach(put IN LISTS PARSED_PUTS)
  list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/vendor/${PARSED_${put}_NAME}/cmake")

  foreach(put_dir IN LISTS PARSED_${put}_DIRS)
    string(SHA256 put_hash "${put_dir}")
    string(SUBSTRING ${put_hash} 0 16 put_hash)

    set(put_name ${PARSED_${put}_NAME})
    set(put_prefix ${put_name}${put_hash})

    set(${put_name}_ROOT ${put_dir})
    set(${put_name}_OPTIONAL_NAME_PREFIX ${put_prefix})
    find_package("${put_name}" MODULE)

    if(NOT ${put_name}_FOUND)
      message(WARNING "skipping ${put_name} in prefix '${put_dir}' (not found)")
      continue()
    endif()

    message(
      STATUS "PUT:${put_name},${${put_prefix}_ROOT},${${put_prefix}_VERSION},${${put_prefix}_HAS_CLAIMS}"
    )

    add_library(puts-interface-${put_hash} STATIC src/put_${put_name}.c)

    target_include_directories(puts-interface-${put_hash}
      PUBLIC
        include
      PRIVATE
        ${${put_prefix}_INCLUDE_DIRS}
    )

    target_link_libraries(puts-interface-${put_hash}
      PRIVATE
        ${${put_prefix}_LIBRARIES}
        claims
    )

    if(${put_prefix}_HAS_CLAIMS)
      target_compile_definitions(puts-interface-${put_hash} PRIVATE HAS_CLAIMS=1)
    endif()

    get_target_property(_put_libraries puts-interface-${put_hash} LINK_LIBRARIES)
    add_bundle(bundle-${put_name}-${put_hash}
      LIBS
        puts-interface-${put_hash}
        ${_put_libraries}
    )

    list(APPEND puts bundle-${put_name}-${put_hash})
  endforeach()
endforeach()

add_bundle(bundle-puts LIBS ${puts})

install(FILES $<TARGET_FILE:bundle-puts> DESTINATION ".")
