# Insert the tlspuffin claim hooks into an OpenSSL source tree.
#
# usage: cmake -DSOURCE_DIR=<dir> -DVENDOR_VERSION=<version> -P apply_hooks.cmake
#
# The hooks are one-liners calling into puffin_claims.h / puffin_claims.c, which are shared
# by all versions. Each insertion is anchored on a literal string that must match exactly once, so
# a change in the vendor sources makes the build fail loudly instead of silently dropping a claim.

if(NOT SOURCE_DIR OR NOT VENDOR_VERSION)
  message(FATAL_ERROR "usage: cmake -DSOURCE_DIR=<dir> -DVENDOR_VERSION=<version> -P apply_hooks.cmake")
endif()

# puffin_insert(<file> ANCHOR <literal> (BEFORE|AFTER) <text>)
function(puffin_insert FILE)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "" "ANCHOR;BEFORE;AFTER" "")

  set(path "${SOURCE_DIR}/${FILE}")
  file(READ "${path}" content)

  string(FIND "${content}" "${ARG_ANCHOR}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "puffin hooks: anchor not found in '${FILE}':\n${ARG_ANCHOR}")
  endif()

  string(LENGTH "${ARG_ANCHOR}" anchor_len)
  math(EXPR after_first "${pos} + ${anchor_len}")
  string(SUBSTRING "${content}" ${after_first} -1 rest)
  string(FIND "${rest}" "${ARG_ANCHOR}" other)
  if(NOT other EQUAL -1)
    message(FATAL_ERROR "puffin hooks: anchor is not unique in '${FILE}':\n${ARG_ANCHOR}")
  endif()

  if(DEFINED ARG_BEFORE)
    set(at ${pos})
    set(text "${ARG_BEFORE}")
  else()
    set(at ${after_first})
    set(text "${ARG_AFTER}")
  endif()

  string(SUBSTRING "${content}" 0 ${at} head)
  string(SUBSTRING "${content}" ${at} -1 tail)
  file(WRITE "${path}" "${head}${text}${tail}")
endfunction()

# -- ssl_local.h: claim fields in the connection structure
puffin_insert(ssl/ssl_local.h
  ANCHOR "struct ssl_st {\n"
  BEFORE "#include \"puffin_claims.h\"\n\n")

if(VENDOR_VERSION VERSION_GREATER_EQUAL "3.2.0")
  puffin_insert(ssl/ssl_local.h
    ANCHOR "struct ssl_connection_st {\n    /* type identifier and common data */\n    struct ssl_st ssl;\n"
    AFTER "    PUFFIN_CLAIM_FIELDS\n")
else()
  puffin_insert(ssl/ssl_local.h
    ANCHOR "struct ssl_st {\n"
    AFTER "    PUFFIN_CLAIM_FIELDS\n\n")
endif()

# -- statem.c: claim every message read from / written to the peer
puffin_insert(ssl/statem/statem.c
  ANCHOR "ret = process_message(s, &pkt);\n"
  AFTER "\n            PUFFIN_CLAIM_READ(s, st, ret);\n")
puffin_insert(ssl/statem/statem.c
  ANCHOR "if (!ssl_close_construct_packet(s, &pkt, mt)"
  BEFORE "PUFFIN_CLAIM_WRITE(s, st);\n\n            ")

# -- statem_srvr.c: transcript hash up to the client Certificate message
puffin_insert(ssl/statem/statem_srvr.c
  ANCHOR "/* Resend session tickets */"
  BEFORE "PUFFIN_CLAIM_CERT_TRANSCRIPT(s);\n\n        ")

# -- tls13_enc.c: transcript used by each HKDF derivation
puffin_insert(ssl/tls13_enc.c
  ANCHOR "unsigned char *out, size_t outlen, int fatal)\n{\n"
  AFTER "    PUFFIN_TLS13_HKDF_CLAIM(s, label, labellen, data, datalen);\n\n")
