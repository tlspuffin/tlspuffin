include_guard(GLOBAL)

set(_check_c_compiler_can_print_deps_source_path "${CMAKE_CURRENT_LIST_DIR}/CheckCCompilerCanPrintDeps.c"
    CACHE INTERNAL "CheckCCompilerCanPrintDeps source file")

macro(check_c_compiler_can_print_deps _cc)
    execute_process(
        COMMAND ${_cc} -M "${_check_c_compiler_can_print_deps_source_path}"
        RESULT_VARIABLE _CC_CAN_PRINT_DEPS_RETCODE
        OUTPUT_QUIET
        ERROR_QUIET
    )

    if(_CC_CAN_PRINT_DEPS_RETCODE EQUAL 0)
        set(CC_CAN_PRINT_DEPS YES)
    else()
        set(CC_CAN_PRINT_DEPS NO)
    endif()

    unset(_CC_CAN_PRINT_DEPS_RETCODE)
endmacro()
