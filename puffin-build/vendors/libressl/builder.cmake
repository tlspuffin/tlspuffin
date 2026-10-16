use_languages(C)

list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/common/arc4random_prng.c" "<SOURCE_DIR>/crypto/compat/arc4random.c")
list(APPEND PATCH_COMMANDS COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_LIST_DIR}/common/arc4random_prng.h" "<SOURCE_DIR>/crypto/compat/arc4random.h")

if(VENDOR_VERSION VERSION_GREATER_EQUAL "4.0.0")
  include("${CMAKE_CURRENT_LIST_DIR}/v4/builder.cmake")
else()
  include("${CMAKE_CURRENT_LIST_DIR}/v3/builder.cmake")
endif()

set(tls12 yes)
set(tls13 yes)
set(tls12_session_resumption yes)
# LibreSSL does not support TLS 1.3 session resumption, only 0-RTT
set(tls13_session_resumption no)
