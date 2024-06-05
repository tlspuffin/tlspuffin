use_languages(C CXX)

if(NOT DEFINED PUTS)
  message(FATAL_ERROR "Missing mandatory argument 'PUTS'")
endif()
string(REPLACE "," ";" PUTS "${PUTS}")

# NOTE: adding a dummy C file let us build even when there is no PUT in the bundle
file(WRITE ${CMAKE_BINARY_DIR}/bundle_dummy.c "static void _bundle_dummy(void) {}")
add_library(puts-bundle STATIC ${CMAKE_BINARY_DIR}/bundle_dummy.c)

foreach(PUT IN LISTS PUTS)
  target_sources(puts-bundle PRIVATE ${PUTS})
endforeach()

install(FILES $<TARGET_FILE:puts-bundle> DESTINATION ".")
