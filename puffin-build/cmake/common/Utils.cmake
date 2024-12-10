include_guard(GLOBAL)

file(REAL_PATH "${CMAKE_CURRENT_LIST_DIR}/../../../" PUFFIN_PROJECT_PATH)

include(CheckLanguage)

# use_languages(<lang>...)
#
# For a list of support languages, see: https://cmake.org/cmake/help/latest/command/enable_language.html
#
# Examples:
#   use_languages(C)
#   use_languages(C CXX Fortran)
macro(use_languages)
  foreach(language ${ARGV})
    check_language(${language})
    if(CMAKE_${language}_COMPILER)
      enable_language(${language})
    else()
      message(FATAL_ERROR "No support for language '${language}'")
    endif()
  endforeach()

  if(${ARGC})
    include(GNUInstallDirs)
  endif()
endmacro()
