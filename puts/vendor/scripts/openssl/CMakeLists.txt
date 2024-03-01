cmake_minimum_required(VERSION 3.15)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../../../cmake")

if(NOT DEFINED ENV{CC})
    set(ENV{CC} "clang")
endif()
set(CC $ENV{CC})

project(openssl LANGUAGES C)

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

option(PARALLEL "Activate parallel build" OFF)
option(WITH_ASAN "Build with address-sanitizer" OFF)
option(WITH_SANCOV "Build with sancov" OFF)
option(WITH_GCOV "Build with instrumentation for gcov coverage" OFF)
option(WITH_LLVM_COV "Build with instrumentation for llvm coverage" OFF)

set(CFLAGS_EXTRA "" CACHE STRING "extra flags for C compiler")
string(REPLACE "," ";" CFLAGS_EXTRA "${CFLAGS_EXTRA}")
list(APPEND CFLAGS_EXTRA -I${CMAKE_SOURCE_DIR}/../../../../tlspuffin-claims)

set(LDFLAGS_EXTRA "" CACHE STRING "extra flags for the linker")
string(REPLACE "," ";" LDFLAGS_EXTRA "${LDFLAGS_EXTRA}")

set(CONFIGURE_FEATURES no-dso no-shared no-tests)
set(CONFIGURE_FLAGS --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR> --libdir=lib)
set(CONFIGURE_EXTRA "")
set(CONFIGURE_ENV "CC=${CC}")

if(PARALLEL)
    set(BUILD_FLAGS "-j32")
else()
    set(BUILD_FLAGS "-j1")
endif()

if(WITH_ASAN)
    list(APPEND CONFIGURE_FEATURES enable-asan)
    list(APPEND CFLAGS_EXTRA -DOPENSSL_NO_BUF_FREELISTS -fsanitize=address -shared-libsan)
endif()

if(WITH_SANCOV)
    list(APPEND CFLAGS_EXTRA -fsanitize-coverage=trace-pc-guard)
endif()

if(WITH_GCOV)
    list(APPEND CFLAGS_EXTRA -ftest-coverage -fprofile-arcs -O0)
endif()

if(WITH_LLVM_COV)
    list(APPEND CFLAGS_EXTRA -fprofile-instr-generate -fcoverage-mapping -O0)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
    if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL x86_64)
        set(OPENSSL_TARGET "darwin64-x86_64-cc")
    else()
        set(OPENSSL_TARGET "darwin64-arm64-cc")
    endif()
elseif(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
    if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL x86_64)
        set(OPENSSL_TARGET "linux-x86_64")
    endif()
endif()

if(DEFINED OPENSSL_TARGET)
  set(CONFIGURE_COMMAND ${CONFIGURE_ENV} <SOURCE_DIR>/Configure ${CFLAGS_EXTRA} ${LDFLAGS_EXTRA} ${CONFIGURE_FEATURES} ${CONFIGURE_FLAGS}
                        ${OPENSSL_TARGET} ${CONFIGURE_EXTRA})
else()
  # Fallback to letting OpenSSL guess the target platform
  set(CONFIGURE_COMMAND ${CONFIGURE_ENV} <SOURCE_DIR>/config ${CFLAGS_EXTRA} ${LDFLAGS_EXTRA} ${CONFIGURE_FEATURES} ${CONFIGURE_FLAGS}
                        ${CONFIGURE_EXTRA})
endif()

set(FETCH_METHOD "git" CACHE STRING "the method used to retrieve the sources")
set(SUPPORTED_METHODS "git")

if(FETCH_METHOD STREQUAL "git")
    if(NOT DEFINED FETCH_URL)
        message(FATAL_ERROR "Missing FETCH_URL for fetch method '${FETCH_METHOD}'")
    endif()

    if(NOT DEFINED FETCH_REF)
        message(FATAL_ERROR "Missing FETCH_REF for fetch method '${FETCH_METHOD}' (can be a branch name, a tag or a commit hash)")
    endif()

    execute_process(
        COMMAND git ls-remote --quiet --exit-code "${FETCH_URL}" "${FETCH_REF}"
        RESULT_VARIABLE REF_IS_HASH
        OUTPUT_QUIET
        ERROR_QUIET
    )

    if(REF_IS_HASH)
        set(GIT_SHALLOW OFF)
    else()
        set(GIT_SHALLOW ON)
    endif()

    if(PATCHES)
        string(REPLACE "," ";" PATCH_ARGS "${PATCHES}")
        set(PATCH_COMMAND git checkout -- . && git clean -d --force && git apply -v --stat --check --apply ${PATCH_ARGS})
    else()
        set(PATCH_COMMAND :)
    endif()

    set(BUILD_COMMAND make depend && make ${BUILD_FLAGS})
    set(INSTALL_COMMAND make ${BUILD_FLAGS} install_sw)

    include(ExternalProject)
    externalproject_add(
        vendor
        GIT_REPOSITORY ${FETCH_URL}
        GIT_TAG ${FETCH_REF}
        GIT_SHALLOW ${GIT_SHALLOW}
        UPDATE_DISCONNECTED TRUE
        PREFIX ${CMAKE_INSTALL_PREFIX}
        CONFIGURE_COMMAND ${CONFIGURE_COMMAND}
        PATCH_COMMAND ${PATCH_COMMAND}
        BUILD_COMMAND ${BUILD_COMMAND}
        BUILD_IN_SOURCE TRUE
        INSTALL_COMMAND ${INSTALL_COMMAND})

    # NOTE we patch the vendor build system to use CC instead of `makedepend`
    #
    # The OpenSSL build system prior to version 1.0.2 uses `makedepend` when the
    # C compiler (CC) is not gcc.
    #
    # The `makedepend` utility extracts source code dependencies and includes
    # them automatically in a Makefile. But this utility is often missing on
    # modern platforms, since the compiler usually has the capability to do the
    # same dependency extraction. Worse yet, if `makedepend` is found but comes
    # from a different toolchain it might select headers that are incompatible
    # with the current C compiler.
    #
    # To avoid these problems, if the C compiler supports the `-M` option, we
    # patch the vendor build system to use it instead.
    include(CheckCCompilerCanPrintDeps)
    check_c_compiler_can_print_deps(${CC})

    if(CC_CAN_PRINT_DEPS)
        externalproject_add_step(
            vendor
            makedepend
            DEPENDEES configure
            DEPENDERS build
            WORKING_DIRECTORY <SOURCE_DIR>
            COMMAND find <SOURCE_DIR> -type f -name Makefile -exec perl -pi.bak -e "s@^MAKEDEPPROG=.*@MAKEDEPPROG= ${CC}@" {} +
            COMMAND find <SOURCE_DIR> -type f -name domd -exec perl -pi.bak -e "s@\\\\.\\\\*gcc(\\\\$)@\\\\.\\\\*${CC}@" {} +
            LOG TRUE)
    endif()
else()
  list(JOIN SUPPORTED_METHODS ", " SUPPORTED_STR)
  message(FATAL_ERROR "Unsupported FETCH_METHOD '${FETCH_METHOD}' (set to one of: ${SUPPORTED_STR})")
endif()
