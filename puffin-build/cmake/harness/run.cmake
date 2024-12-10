use_languages(C CXX)

if(NOT HARNESS)
  message(FATAL_ERROR "Missing mandatory argument 'HARNESS'")
endif()

if(NOT INCLUDE_DIRS)
  message(FATAL_ERROR "Missing mandatory argument 'INCLUDE_DIRS'")
endif()
string(REPLACE "," ";" INCLUDE_DIRS "${INCLUDE_DIRS}")

if(NOT LINK_LIBRARIES)
  message(FATAL_ERROR "Missing mandatory argument 'LINK_LIBRARIES'")
endif()
string(REPLACE "," ";" LINK_LIBRARIES "${LINK_LIBRARIES}")

if(NOT PUT_ID)
  message(FATAL_ERROR "Missing mandatory argument 'PUT_ID'")
endif()

set(PUT "put-${PUT_ID}")

file(GLOB HARNESS_SOURCES ${HARNESS}/src/*.c)
add_library(${PUT} STATIC ${HARNESS_SOURCES})

include(CheckPIESupported)
check_pie_supported(OUTPUT_VARIABLE output LANGUAGES C)
set_property(TARGET ${PUT} PROPERTY POSITION_INDEPENDENT_CODE TRUE)
if(NOT CMAKE_C_LINK_PIE_SUPPORTED)
  message(WARNING "No support for PIE at link time. PIE link options will be ignored.")
endif()

set_property(TARGET ${PUT} PROPERTY C_VISIBILITY_PRESET hidden)
target_include_directories(${PUT} PRIVATE "${HARNESS}/include")
target_include_directories(${PUT} PRIVATE ${INCLUDE_DIRS})
target_link_libraries(${PUT} PRIVATE ${LINK_LIBRARIES})

target_include_directories(${PUT} PRIVATE "${LIBRARY}/include")
target_include_directories(${PUT} PRIVATE "${PUFFIN_PROJECT_PATH}/tlspuffin/include")
target_include_directories(${PUT} PRIVATE "${PUFFIN_PROJECT_PATH}/puffin/include")
target_include_directories(${PUT} PRIVATE "${PUFFIN_PROJECT_PATH}/tlspuffin-claims")

set(PARTIAL_RELOCATION_COMMANDS "")
if (APPLE)
  list(APPEND PARTIAL_RELOCATION_COMMANDS COMMAND clang -o ${CMAKE_BINARY_DIR}/${PUT}.o "${CMAKE_C_FLAGS}" -flto -nostdlib -nodefaultlibs -nostartfiles -Wl,-no-pie -Wl,-whole-archive -Wl,exported_symbol=${PUT_ID} -Wl,-r $<TARGET_OBJECTS:${PUT}> ${LINK_LIBRARIES})
else()
  list(APPEND PARTIAL_RELOCATION_COMMANDS COMMAND clang -o ${CMAKE_BINARY_DIR}/${PUT}.o "${CMAKE_C_FLAGS}" -flto -nostdlib -nodefaultlibs -nostartfiles -Wl,-no-pie -Wl,-whole-archive -Wl,-r $<TARGET_OBJECTS:${PUT}> ${LINK_LIBRARIES})
  list(APPEND PARTIAL_RELOCATION_COMMANDS COMMAND objcopy -G "${PUT_ID}" "${CMAKE_BINARY_DIR}/${PUT}.o")
endif()

add_custom_command(
    ${PARTIAL_RELOCATION_COMMANDS}
    OUTPUT ${CMAKE_BINARY_DIR}/${PUT}.o
    DEPENDS ${PUT}
    COMMAND_EXPAND_LISTS
    COMMENT "relocation for PUT ${PUT_ID}" VERBATIM
)

add_custom_target(relocate-${PUT} ALL DEPENDS ${CMAKE_BINARY_DIR}/${PUT}.o)

add_library(relocated-${PUT} OBJECT IMPORTED)
set_property(TARGET relocated-${PUT} PROPERTY IMPORTED_OBJECTS ${CMAKE_BINARY_DIR}/${PUT}.o)
add_dependencies(relocated-${PUT} relocate-${PUT})

install(FILES "$<TARGET_OBJECTS:relocated-${PUT}>" DESTINATION ".")
