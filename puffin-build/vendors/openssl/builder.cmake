use_languages(C)

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
check_c_compiler_can_print_deps(${CMAKE_C_COMPILER})

if(CC_CAN_PRINT_DEPS)
  list(APPEND BUILD_COMMANDS COMMAND find <SOURCE_DIR> -type f -name Makefile -exec perl -pi.bak -e "s@^MAKEDEPPROG=.*@MAKEDEPPROG= ${CMAKE_C_COMPILER}@" {} +)
  list(APPEND BUILD_COMMANDS COMMAND find <SOURCE_DIR> -type f -name domd -exec perl -pi.bak -e "s@\\.\\*gcc@.*${CMAKE_C_COMPILER}@" {} +)
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
  set(CONFIGURE_EXE <SOURCE_DIR>/Configure)
else()
  # Fallback to letting OpenSSL guess the target platform
  set(CONFIGURE_EXE <SOURCE_DIR>/config)
endif()

set(CONFIGURE_FLAGS
  no-dso
  no-shared
  no-tests
  $<$<BOOL:${asan}>:enable-asan>

  --prefix=<INSTALL_DIR>
  --openssldir=<INSTALL_DIR>
  --libdir=lib  # force consistent libdir across platforms
)

string(REGEX MATCH "^([0-9]+\.[0-9]+\.[0-9]+)(.)" _match "${VENDOR_VERSION}")
set(VERSION_LETTER "${CMAKE_MATCH_2}")

# check for Heartbleed: CVE-2014-0160
# see: https://www.openssl.org/news/vulnerabilities.html#y2014
if(VENDOR_VERSION VERSION_GREATER_EQUAL "1.0.1" AND VENDOR_VERSION VERSION_LESS "1.0.2")
  set(VULN_LETTER "a;b;c;d;e;f")
  if(NOT VERSION_LETTER OR VERSION_LETTER IN_LIST VULN_LETTER)
    declare_vulnerability("CVE-2014-0160")
  endif()
endif()

# check for FREAK: CVE-2015-0204
# see: https://www.openssl.org/news/vulnerabilities.html#y2015
if(VENDOR_VERSION VERSION_GREATER_EQUAL "1.0.0" AND VENDOR_VERSION VERSION_LESS "1.0.1")
  set(VULN_LETTER "a;b;c;d;e;f;g;h;i;j;k;l;m;n;o")
  if(NOT VERSION_LETTER OR VERSION_LETTER IN_LIST VULN_LETTER)
    declare_vulnerability("CVE-2015-0204")
  endif()
endif()

if(VENDOR_VERSION VERSION_GREATER_EQUAL "1.0.1" AND VENDOR_VERSION VERSION_LESS "1.0.2")
  set(VULN_LETTER "a;b;c;d;e;f;g;h;i;j")
  if(NOT VERSION_LETTER OR VERSION_LETTER IN_LIST VULN_LETTER)
    declare_vulnerability("CVE-2015-0204")
  endif()
endif()

# check for CVE-2021-3449
# see: https://www.openssl.org/news/vulnerabilities.html#y2021
if(VENDOR_VERSION VERSION_GREATER_EQUAL "1.1.1" AND VENDOR_VERSION VERSION_LESS "1.1.2")
  set(VULN_LETTER "a;b;c;d;e;f;g;h;i;j")
  if(NOT VERSION_LETTER OR VERSION_LETTER IN_LIST VULN_LETTER)
    declare_vulnerability("CVE-2021-3449")
  endif()
endif()

set(CFLAGS
  -g
  -fPIC
  -fvisibility=hidden
  -I${CMAKE_SOURCE_DIR}/../../tlspuffin-claims

  # SANCOV
  $<$<BOOL:${sancov}>:-fsanitize-coverage=trace-pc-guard>

  # ASAN
  $<$<BOOL:${asan}>:-DOPENSSL_NO_BUF_FREELISTS>
  $<$<BOOL:${asan}>:-fsanitize=address>
  $<$<BOOL:${asan}>:-static-libsan>

  # LLVM_COV
  $<$<BOOL:${llvm_cov}>:-fprofile-instr-generate>
  $<$<BOOL:${llvm_cov}>:-fcoverage-mapping>
  $<$<BOOL:${llvm_cov}>:-O0>

  # GCOV
  $<$<BOOL:${gcov}>:-ftest-coverage>
  $<$<BOOL:${gcov}>:-fprofile-arcs>
  $<$<BOOL:${gcov}>:-O0>
)
list(JOIN CFLAGS " " CFLAGS)

list(APPEND CONFIGURE_COMMANDS COMMAND
    ${CMAKE_COMMAND} -E chdir "<SOURCE_DIR>"
    ${CMAKE_COMMAND} -E env
        "CPP=${CMAKE_C_COMPILER} -E"
        "CC=${CMAKE_C_COMPILER}"
        "AR=${CMAKE_AR}"
        "RANLIB=${CMAKE_RANLIB}"
        "NM=${CMAKE_NM}"
        "STRIP=${CMAKE_STRIP}"
      ${CONFIGURE_EXE} ${CFLAGS} ${CONFIGURE_FLAGS} ${OPENSSL_TARGET}
)

list(APPEND BUILD_COMMANDS
  COMMAND make -C "<SOURCE_DIR>" depend
  COMMAND make -C "<SOURCE_DIR>" $<IF:$<VERSION_LESS_EQUAL:${VENDOR_VERSION},1.1.0>,-j1,-j>
)

set(tls12 yes)
set(tls12_session_resumption yes)
if(VENDOR_VERSION VERSION_GREATER_EQUAL "1.1.1")
  set(tls13 yes)
  set(tls13_session_resumption yes)
endif()
if(VENDOR_VERSION VERSION_GREATER_EQUAL "3.4.0")
  set(allow_setting_tls12_ciphers yes)
endif()
if(VENDOR_VERSION VERSION_GREATER_EQUAL "3.0.0")
  set(allow_setting_tls13_ciphers yes)
endif()
set(transcript_extraction yes)
set(client_authentication_transcript_extraction yes)

list(APPEND INSTALL_COMMANDS COMMAND make -C "<SOURCE_DIR>" install_sw "prefix=${CMAKE_INSTALL_PREFIX}")
